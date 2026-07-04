import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import verify_hex_digest
from app.models.anomaly import AnomalyEvent, AnomalySeverity, AnomalyStatus
from app.models.audit import AuditLogEntry
from app.models.config import (
    ConfigChange,
    ConfigChangeStatus,
    ConfigParameter,
    ConfigTier,
    ConfigValueType,
)
from app.models.tenancy import IsolationMode, Tenant, TenantStatus, TenantTier
from app.models.user import User
from app.schemas.anomaly import AnomalyEventCreate
from app.services import anomaly_service, config_service
from app.services.anomaly_service import create_anomaly_event, update_anomaly_status
from app.services.audit_service import verify_chain
from app.services.config_service import apply_pending_changes


async def _auth_headers(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@nexus.local", "password": "TestPassword!123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _create_config_parameter(
    db_session: AsyncSession,
    *,
    key: str,
    active_value: str = "old",
    pending_value: str | None = None,
    is_sensitive: bool = False,
) -> ConfigParameter:
    parameter = ConfigParameter(
        id=uuid.uuid4(),
        key=key,
        section="security",
        tier=ConfigTier.CRITICAL,
        value_type=ConfigValueType.STRING,
        active_value=active_value,
        pending_value=pending_value,
        is_sensitive=is_sensitive,
        requires_restart=False,
    )
    db_session.add(parameter)
    await db_session.commit()
    await db_session.refresh(parameter)
    return parameter


async def _create_pending_parameter(
    db_session: AsyncSession,
    *,
    key: str,
    active_value: str = "old",
    pending_value: str = "new",
) -> ConfigParameter:
    parameter = await _create_config_parameter(
        db_session, key=key, active_value=active_value, pending_value=pending_value
    )
    db_session.add(
        ConfigChange(
            parameter_id=parameter.id,
            previous_value=active_value,
            new_value=pending_value,
            changed_by="test@nexus.local",
            status=ConfigChangeStatus.PENDING,
        )
    )
    await db_session.commit()
    await db_session.refresh(parameter)
    return parameter


async def _create_raw_anomaly(db_session: AsyncSession) -> AnomalyEvent:
    anomaly = AnomalyEvent(
        category="auth",
        score=0.8,
        severity=AnomalySeverity.from_score(0.8),
        status=AnomalyStatus.OPEN,
        title="Raw anomaly",
        description="Created directly for rollback verification",
        actor="detector",
        source_ip="198.51.100.11",
        metadata_json={"secret": "raw-secret", "safe": "visible"},
        occurred_at=datetime.now(timezone.utc),
    )
    db_session.add(anomaly)
    await db_session.commit()
    await db_session.refresh(anomaly)
    return anomaly


async def _create_tenant(db_session: AsyncSession, *, slug: str) -> Tenant:
    tenant = Tenant(
        slug=slug,
        org_id=slug.upper()[:20],
        display_name=f"{slug} tenant",
        tier=TenantTier.ENTERPRISE,
        isolation_mode=IsolationMode.STRICT,
        status=TenantStatus.ACTIVE,
        region="us-east-1",
        db_schema_name=f"{slug}_schema",
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    return tenant


async def _audit_rows(db_session: AsyncSession) -> list[AuditLogEntry]:
    return (
        await db_session.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence.asc()))
    ).scalars().all()


async def _audit_count(db_session: AsyncSession) -> int:
    return await db_session.scalar(select(func.count()).select_from(AuditLogEntry)) or 0


@pytest.mark.asyncio
async def test_auth_config_apply_and_audit_chain_integrate(
    client: AsyncClient,
    db_session: AsyncSession,
    test_user: User,
) -> None:
    parameter = await _create_config_parameter(
        db_session,
        key="jwt_secret",
        active_value="old-secret-value",
        is_sensitive=True,
    )
    headers = await _auth_headers(client)

    stage_response = await client.patch(
        f"/api/v1/config/parameters/{parameter.id}",
        headers=headers,
        json={
            "value": "new-secret-value",
            "reason": "rotate integration secret",
            "changed_by": "request-body@example.test",
        },
    )
    assert stage_response.status_code == 200
    assert stage_response.json()["active_value"] == "••••••••"
    assert stage_response.json()["pending_value"] == "••••••••"

    apply_response = await client.post("/api/v1/config/apply", headers=headers)
    assert apply_response.status_code == 200
    assert apply_response.json() == {"detail": "Applied 1 pending change(s)"}

    await db_session.refresh(parameter)
    assert parameter.active_value == "new-secret-value"
    assert parameter.pending_value is None

    audit = (await _audit_rows(db_session))[0]
    assert audit.event_type.value == "config_change"
    assert audit.event_subtype == "PARAMETER_UPDATED"
    assert audit.actor == "test@nexus.local"
    assert audit.metadata_json["parameter_key"] == "jwt_secret"
    assert audit.metadata_json["previous_value"] == "[REDACTED]"
    assert audit.metadata_json["new_value"] == "[REDACTED]"
    assert "old-secret-value" not in audit.description
    assert "new-secret-value" not in audit.description
    assert verify_hex_digest(audit.entry_hash, audit.signature) is True

    verification = await verify_chain(db_session)
    assert verification.is_valid is True
    assert verification.verified_count == 1
    assert verification.failed_count == 0


@pytest.mark.asyncio
async def test_auth_anomaly_lifecycle_and_audit_chain_integrate(
    client: AsyncClient,
    db_session: AsyncSession,
    test_user: User,
) -> None:
    headers = await _auth_headers(client)
    tenant = await _create_tenant(db_session, slug="tenant-a")
    metadata = {
        "api_key": "raw-api-key",
        "safe": "visible",
        "nested": [{"Refresh_Token": "raw-refresh-token", "label": "kept"}],
    }

    create_response = await client.post(
        "/api/v1/anomalies/events",
        headers=headers,
        json={
            "category": "auth",
            "score": 0.93,
            "title": "Suspicious login burst",
            "description": "Multiple failed logins",
            "actor": "detector-service",
            "source_ip": "198.51.100.8",
            "tenant_id": str(tenant.id),
            "metadata_json": metadata,
        },
    )
    assert create_response.status_code == 201
    created = create_response.json()
    assert created["severity"] == "critical"
    assert created["metadata_json"]["api_key"] == "[REDACTED]"
    assert created["metadata_json"]["nested"][0]["Refresh_Token"] == "[REDACTED]"
    assert created["metadata_json"]["safe"] == "visible"

    event_id = created["id"]
    status_response = await client.post(
        f"/api/v1/anomalies/events/{event_id}/acknowledge", headers=headers
    )
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "investigating"

    stored = await db_session.get(AnomalyEvent, uuid.UUID(event_id))
    assert stored is not None
    assert stored.tenant_id == tenant.id
    assert stored.severity == AnomalySeverity.CRITICAL
    assert stored.status == AnomalyStatus.INVESTIGATING
    assert stored.metadata_json == metadata

    unscoped_anomaly = await _create_raw_anomaly(db_session)
    assert unscoped_anomaly.tenant_id is None
    unfiltered_response = await client.get("/api/v1/anomalies/events", headers=headers)
    tenant_filtered_response = await client.get(
        f"/api/v1/anomalies/events?tenant_id={tenant.id}", headers=headers
    )
    assert unfiltered_response.status_code == 200
    assert tenant_filtered_response.status_code == 200
    assert unfiltered_response.json()["total"] == 2
    assert tenant_filtered_response.json()["total"] == 1
    assert tenant_filtered_response.json()["items"][0]["id"] == event_id

    audits = await _audit_rows(db_session)
    assert [audit.event_subtype for audit in audits] == [
        "ANOMALY_CREATED",
        "ANOMALY_STATUS_UPDATED",
    ]
    assert [audit.actor for audit in audits] == ["test@nexus.local", "test@nexus.local"]
    assert audits[0].metadata_json["metadata_json"]["api_key"] == "[REDACTED]"
    assert audits[0].metadata_json["metadata_json"]["nested"][0]["Refresh_Token"] == "[REDACTED]"
    assert audits[0].metadata_json["metadata_json"]["safe"] == "visible"
    assert audits[1].metadata_json["previous_status"] == "open"
    assert audits[1].metadata_json["status"] == "investigating"
    assert audits[1].prev_hash == audits[0].entry_hash
    assert all(verify_hex_digest(audit.entry_hash, audit.signature) for audit in audits)

    verification = await verify_chain(db_session)
    assert verification.is_valid is True
    assert verification.verified_count == 2
    assert verification.failed_count == 0


@pytest.mark.asyncio
async def test_cross_module_rollback_failure_integrity(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = await _create_pending_parameter(db_session, key="multi-first")
    second = await _create_pending_parameter(db_session, key="multi-second")
    real_config_append = config_service.append_entry_in_transaction
    calls = 0

    async def fail_second_config_audit(*args: object, **kwargs: object) -> AuditLogEntry:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("second config audit failed")
        return await real_config_append(*args, **kwargs)

    monkeypatch.setattr(config_service, "append_entry_in_transaction", fail_second_config_audit)

    with pytest.raises(RuntimeError, match="second config audit failed"):
        await apply_pending_changes(db_session, changed_by="test@nexus.local")

    await db_session.refresh(first)
    await db_session.refresh(second)
    assert calls == 2
    assert first.active_value == "old"
    assert first.pending_value == "new"
    assert second.active_value == "old"
    assert second.pending_value == "new"
    assert await _audit_count(db_session) == 0

    monkeypatch.undo()
    anomaly = await _create_raw_anomaly(db_session)

    async def fail_anomaly_audit(*_args: object, **_kwargs: object) -> AuditLogEntry:
        raise RuntimeError("anomaly audit failed")

    monkeypatch.setattr(anomaly_service, "append_entry_in_transaction", fail_anomaly_audit)

    with pytest.raises(RuntimeError, match="anomaly audit failed"):
        await update_anomaly_status(
            db_session,
            anomaly.id,
            AnomalyStatus.RESOLVED,
            audit_actor="test@nexus.local",
        )

    await db_session.refresh(anomaly)
    assert anomaly.status == AnomalyStatus.OPEN
    assert anomaly.resolved_at is None
    assert await _audit_count(db_session) == 0

    monkeypatch.undo()

    def fail_anomaly_flush(session: object, _flush_context: object, _instances: object) -> None:
        if any(isinstance(item, AnomalyEvent) for item in getattr(session, "new")):
            raise RuntimeError("anomaly flush failed")

    event.listen(db_session.sync_session, "before_flush", fail_anomaly_flush)
    try:
        with pytest.raises(RuntimeError, match="anomaly flush failed"):
            await create_anomaly_event(
                db_session,
                AnomalyEventCreate(
                    category="auth",
                    score=0.75,
                    title="Flush failure",
                    description="Domain mutation fails before audit append",
                    actor="detector",
                    source_ip="198.51.100.10",
                    metadata_json={"token": "raw-token"},
                ),
                audit_actor="test@nexus.local",
            )
    finally:
        event.remove(db_session.sync_session, "before_flush", fail_anomaly_flush)

    assert await db_session.scalar(select(func.count()).select_from(AnomalyEvent)) == 1
    assert await _audit_count(db_session) == 0
