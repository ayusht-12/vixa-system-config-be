import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import verify_hex_digest
from app.models.audit import AuditLogEntry
from app.models.config import (
    ConfigChange,
    ConfigChangeStatus,
    ConfigParameter,
    ConfigTier,
    ConfigValueType,
)
from app.services import config_service
from app.services.audit_service import verify_chain
from app.services.config_service import apply_pending_changes


async def _create_pending_parameter(
    db: AsyncSession,
    *,
    key: str,
    active_value: str = "old",
    pending_value: str = "new",
) -> ConfigParameter:
    parameter = ConfigParameter(
        key=key,
        section="runtime",
        tier=ConfigTier.NECESSARY,
        value_type=ConfigValueType.STRING,
        active_value=active_value,
        pending_value=pending_value,
        requires_restart=False,
        is_sensitive=False,
    )
    db.add(parameter)
    await db.flush()
    db.add(
        ConfigChange(
            parameter_id=parameter.id,
            previous_value=active_value,
            new_value=pending_value,
            changed_by="tester@nexus.local",
            status=ConfigChangeStatus.PENDING,
        )
    )
    await db.commit()
    return parameter


async def _audit_count(db: AsyncSession) -> int:
    return await db.scalar(select(func.count()).select_from(AuditLogEntry)) or 0


async def _pending_change_for(db: AsyncSession, parameter: ConfigParameter) -> ConfigChange:
    change = await db.scalar(
        select(ConfigChange).where(ConfigChange.parameter_id == parameter.id)
    )
    assert change is not None
    return change


@pytest.mark.asyncio
async def test_apply_pending_changes_commits_config_and_audit_atomically(
    db_session: AsyncSession,
) -> None:
    parameter = await _create_pending_parameter(db_session, key="atomic-success")

    count = await apply_pending_changes(db_session, changed_by="admin@nexus.local")

    await db_session.refresh(parameter)
    change = await _pending_change_for(db_session, parameter)
    audits = (
        await db_session.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence.asc()))
    ).scalars().all()

    assert count == 1
    assert parameter.active_value == "new"
    assert parameter.pending_value is None
    assert change.status == ConfigChangeStatus.APPLIED
    assert change.applied_at is not None
    assert len(audits) == 1
    assert audits[0].metadata_json["parameter_key"] == "atomic-success"
    assert verify_hex_digest(audits[0].entry_hash, audits[0].signature) is True

    verification = await verify_chain(db_session)
    assert verification.is_valid is True
    assert verification.verified_count == 1
    assert verification.failed_count == 0


@pytest.mark.asyncio
async def test_audit_append_failure_rolls_back_config_mutation(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parameter = await _create_pending_parameter(db_session, key="audit-fails")

    async def fail_audit_append(*_args: object, **_kwargs: object) -> AuditLogEntry:
        raise RuntimeError("audit append failed")

    monkeypatch.setattr(config_service, "append_entry_in_transaction", fail_audit_append)

    with pytest.raises(RuntimeError, match="audit append failed"):
        await apply_pending_changes(db_session, changed_by="admin@nexus.local")

    await db_session.refresh(parameter)
    change = await _pending_change_for(db_session, parameter)

    assert parameter.active_value == "old"
    assert parameter.pending_value == "new"
    assert change.status == ConfigChangeStatus.PENDING
    assert change.applied_at is None
    assert await _audit_count(db_session) == 0


@pytest.mark.asyncio
async def test_config_flush_failure_leaves_no_audit_entry(
    db_session: AsyncSession,
) -> None:
    parameter = await _create_pending_parameter(db_session, key="config-fails")

    def fail_config_flush(session: object, _flush_context: object, _instances: object) -> None:
        dirty = getattr(session, "dirty")
        if any(isinstance(item, ConfigParameter) for item in dirty):
            raise RuntimeError("config flush failed")

    event.listen(db_session.sync_session, "before_flush", fail_config_flush)
    try:
        with pytest.raises(RuntimeError, match="config flush failed"):
            await apply_pending_changes(db_session, changed_by="admin@nexus.local")
    finally:
        event.remove(db_session.sync_session, "before_flush", fail_config_flush)

    await db_session.refresh(parameter)
    change = await _pending_change_for(db_session, parameter)

    assert parameter.active_value == "old"
    assert parameter.pending_value == "new"
    assert change.status == ConfigChangeStatus.PENDING
    assert change.applied_at is None
    assert await _audit_count(db_session) == 0


@pytest.mark.asyncio
async def test_multi_item_apply_failure_does_not_partially_commit(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = await _create_pending_parameter(db_session, key="multi-first")
    second = await _create_pending_parameter(db_session, key="multi-second")
    real_append = config_service.append_entry_in_transaction
    calls = 0

    async def fail_second_audit_append(*args: object, **kwargs: object) -> AuditLogEntry:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("second audit append failed")
        return await real_append(*args, **kwargs)

    monkeypatch.setattr(config_service, "append_entry_in_transaction", fail_second_audit_append)

    with pytest.raises(RuntimeError, match="second audit append failed"):
        await apply_pending_changes(db_session, changed_by="admin@nexus.local")

    await db_session.refresh(first)
    await db_session.refresh(second)
    first_change = await _pending_change_for(db_session, first)
    second_change = await _pending_change_for(db_session, second)

    assert calls == 2
    assert first.active_value == "old"
    assert first.pending_value == "new"
    assert second.active_value == "old"
    assert second.pending_value == "new"
    assert first_change.status == ConfigChangeStatus.PENDING
    assert second_change.status == ConfigChangeStatus.PENDING
    assert await _audit_count(db_session) == 0


@pytest.mark.asyncio
async def test_successful_multi_item_apply_preserves_chain_and_signatures(
    db_session: AsyncSession,
) -> None:
    await _create_pending_parameter(db_session, key="chain-first")
    await _create_pending_parameter(db_session, key="chain-second")

    count = await apply_pending_changes(db_session, changed_by="admin@nexus.local")

    audits = (
        await db_session.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence.asc()))
    ).scalars().all()
    verification = await verify_chain(db_session)

    assert count == 2
    assert len(audits) == 2
    assert audits[0].prev_hash is None
    assert audits[1].prev_hash == audits[0].entry_hash
    assert all(verify_hex_digest(audit.entry_hash, audit.signature) for audit in audits)
    assert verification.is_valid is True
    assert verification.verified_count == 2
    assert verification.failed_count == 0
    assert verification.root_hash == audits[-1].entry_hash
