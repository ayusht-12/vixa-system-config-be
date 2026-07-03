import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLogEntry
from app.schemas.audit import AuditLogEntryCreate
from app.services.audit_service import append_entry, verify_chain


def _entry(actor: str, description: str) -> AuditLogEntryCreate:
    return AuditLogEntryCreate(
        severity="info",
        event_type="state_change",
        event_subtype="test.event",
        actor=actor,
        description=description,
    )


@pytest.mark.asyncio
async def test_chain_links_entries_via_prev_hash(db_session: AsyncSession) -> None:
    first = await append_entry(db_session, _entry("tester", "first event"))
    second = await append_entry(db_session, _entry("tester", "second event"))

    assert first.prev_hash is None
    assert second.prev_hash == first.entry_hash
    assert first.entry_hash != second.entry_hash


@pytest.mark.asyncio
async def test_verify_chain_passes_on_untouched_entries(db_session: AsyncSession) -> None:
    for i in range(5):
        await append_entry(db_session, _entry("tester", f"event {i}"))

    result = await verify_chain(db_session)

    assert result.is_valid is True
    assert result.verified_count == 5
    assert result.failed_count == 0
    assert result.first_break_sequence is None


@pytest.mark.asyncio
async def test_verify_chain_detects_tamper_without_cascading(db_session: AsyncSession) -> None:
    entries = [await append_entry(db_session, _entry("tester", f"event {i}")) for i in range(5)]

    tampered = entries[2]
    await db_session.execute(
        update(AuditLogEntry)
        .where(AuditLogEntry.id == tampered.id)
        .values(description="this was not the original description")
    )
    await db_session.commit()

    result = await verify_chain(db_session)

    assert result.is_valid is False
    assert result.failed_count == 1
    assert result.first_break_sequence == tampered.sequence
    assert result.verified_count == 4


@pytest.mark.asyncio
async def test_verify_chain_empty_is_valid(db_session: AsyncSession) -> None:
    result = await verify_chain(db_session)

    assert result.is_valid is True
    assert result.verified_count == 0
    assert result.failed_count == 0
    assert result.root_hash is None
