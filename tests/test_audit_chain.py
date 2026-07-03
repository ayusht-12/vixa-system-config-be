import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import verify_hex_digest
from app.models.audit import AuditLogEntry
from app.schemas.audit import AuditLogEntryCreate
from app.services.audit_service import append_entry, compute_entry_hash, verify_chain


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


@pytest.mark.asyncio
async def test_append_sanitizes_sensitive_metadata_before_hash_and_signature(
    db_session: AsyncSession,
) -> None:
    original_metadata = {
        "password": "top-level-password",
        "safe_value": "visible",
        "nested": {
            "Secret_Key": "deep-secret",
            "safe_nested": {"count": 3},
            "deeper": {"credentials": "deep-credentials"},
        },
        "events": [
            {"api_key": "list-api-key", "label": "first"},
            {"Authorization": "Bearer secret-token", "token": "list-token"},
            "plain-list-value",
        ],
        "note": "secret words in values are preserved",
    }

    entry = await append_entry(
        db_session,
        AuditLogEntryCreate(
            severity="info",
            event_type="state_change",
            event_subtype="metadata.sanitized",
            actor="tester",
            description="sensitive metadata is sanitized",
            metadata_json=original_metadata,
        ),
    )

    assert entry.metadata_json["password"] == "[REDACTED]"
    assert entry.metadata_json["nested"]["Secret_Key"] == "[REDACTED]"
    assert entry.metadata_json["nested"]["deeper"]["credentials"] == "[REDACTED]"
    assert entry.metadata_json["events"][0]["api_key"] == "[REDACTED]"
    assert entry.metadata_json["events"][1]["Authorization"] == "[REDACTED]"
    assert entry.metadata_json["events"][1]["token"] == "[REDACTED]"
    assert entry.metadata_json["safe_value"] == "visible"
    assert entry.metadata_json["nested"]["safe_nested"]["count"] == 3
    assert entry.metadata_json["events"][0]["label"] == "first"
    assert entry.metadata_json["events"][2] == "plain-list-value"
    assert entry.metadata_json["note"] == "secret words in values are preserved"

    stored = await db_session.get(AuditLogEntry, entry.id)
    assert stored is not None
    assert stored.metadata_json == entry.metadata_json
    assert stored.metadata_json != original_metadata

    expected_hash = compute_entry_hash(
        prev_hash=stored.prev_hash,
        occurred_at=stored.occurred_at,
        severity=stored.severity.value,
        event_type=stored.event_type.value,
        event_subtype=stored.event_subtype,
        actor=stored.actor,
        description=stored.description,
        tenant_slug=stored.tenant_slug,
        source_ip=stored.source_ip,
        metadata_json=stored.metadata_json,
    )
    assert stored.entry_hash == expected_hash
    assert verify_hex_digest(stored.entry_hash, stored.signature) is True

    result = await verify_chain(db_session)
    assert result.is_valid is True
    assert result.verified_count == 1
    assert result.failed_count == 0


@pytest.mark.asyncio
async def test_sanitized_metadata_preserves_consecutive_chain_integrity(
    db_session: AsyncSession,
) -> None:
    first = await append_entry(
        db_session,
        AuditLogEntryCreate(
            severity="info",
            event_type="auth_event",
            event_subtype="first",
            actor="tester",
            description="first sanitized event",
            metadata_json={"refresh_token": "raw-refresh", "operation": "first"},
        ),
    )
    second = await append_entry(
        db_session,
        AuditLogEntryCreate(
            severity="warning",
            event_type="auth_event",
            event_subtype="second",
            actor="tester",
            description="second sanitized event",
            metadata_json={"private_key": "raw-private-key", "operation": "second"},
        ),
    )

    assert first.metadata_json == {"refresh_token": "[REDACTED]", "operation": "first"}
    assert second.metadata_json == {"private_key": "[REDACTED]", "operation": "second"}
    assert second.prev_hash == first.entry_hash
    assert first.entry_hash != second.entry_hash
    assert verify_hex_digest(first.entry_hash, first.signature) is True
    assert verify_hex_digest(second.entry_hash, second.signature) is True

    result = await verify_chain(db_session)
    assert result.is_valid is True
    assert result.verified_count == 2
    assert result.failed_count == 0
    assert result.root_hash == second.entry_hash
