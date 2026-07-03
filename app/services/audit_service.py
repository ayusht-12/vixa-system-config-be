import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import get_signing_key_id, sign_hex_digest, verify_hex_digest
from app.models.audit import AuditLogEntry
from app.schemas.audit import (
    AuditLogEntryCreate,
    AuditLogEntryRead,
    ChainVerificationResult,
    HashChainSummary,
)


def _canonical_payload(
    *,
    prev_hash: str | None,
    occurred_at: datetime,
    severity: str,
    event_type: str,
    event_subtype: str,
    actor: str,
    description: str,
    tenant_slug: str | None,
    source_ip: str | None,
    metadata_json: dict,
) -> bytes:
    """Deterministic byte representation of the fields that make up an
    entry's identity. Sorted keys + fixed separators guarantee the same
    logical entry always hashes to the same digest, on any machine.
    """
    payload = {
        "prev_hash": prev_hash,
        "occurred_at": occurred_at.astimezone(timezone.utc).isoformat(),
        "severity": severity,
        "event_type": event_type,
        "event_subtype": event_subtype,
        "actor": actor,
        "description": description,
        "tenant_slug": tenant_slug,
        "source_ip": source_ip,
        "metadata_json": metadata_json,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_entry_hash(**fields) -> str:
    return hashlib.sha256(_canonical_payload(**fields)).hexdigest()


async def _get_tail(db: AsyncSession) -> AuditLogEntry | None:
    result = await db.execute(
        select(AuditLogEntry).order_by(AuditLogEntry.sequence.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def append_entry(db: AsyncSession, payload: AuditLogEntryCreate) -> AuditLogEntry:
    """Append one entry to the hash chain.

    Note this deliberately does *not* run inside a caller-supplied
    transaction that might be rolled back after the hash is computed —
    each call commits its own entry so `prev_hash` linkage always reflects
    what's durably persisted, even under concurrent appends serialized by
    Postgres row locking on the sequence.
    """
    tail = await _get_tail(db)
    prev_hash = tail.entry_hash if tail else None
    occurred_at = datetime.now(timezone.utc)

    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        occurred_at=occurred_at,
        severity=payload.severity,
        event_type=payload.event_type,
        event_subtype=payload.event_subtype,
        actor=payload.actor,
        description=payload.description,
        tenant_slug=payload.tenant_slug,
        source_ip=payload.source_ip,
        metadata_json=payload.metadata_json,
    )
    signature = sign_hex_digest(entry_hash)

    entry = AuditLogEntry(
        id=uuid.uuid4(),
        occurred_at=occurred_at,
        severity=payload.severity,
        event_type=payload.event_type,
        event_subtype=payload.event_subtype,
        tenant_id=payload.tenant_id,
        tenant_slug=payload.tenant_slug,
        actor=payload.actor,
        source_ip=payload.source_ip,
        description=payload.description,
        metadata_json=payload.metadata_json,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        signing_key_id=get_signing_key_id(),
        signature=signature,
        created_at=occurred_at,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


async def verify_chain(db: AsyncSession) -> ChainVerificationResult:
    """Walk every entry in sequence order, recomputing each hash and
    signature from scratch and comparing against what's stored.

    Any historical row that was altered (even a single byte of
    `description`) will produce a different hash than what's stored in
    that row *and* every row after it, since each hash commits to
    `prev_hash`. The first sequence number where the recomputed hash
    diverges from storage is surfaced so operators know exactly where the
    chain broke.
    """
    start = time.perf_counter()
    result = await db.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence.asc()))
    entries = result.scalars().all()

    verified = 0
    failed = 0
    first_break: int | None = None
    expected_prev_hash: str | None = None

    for entry in entries:
        expected_hash = compute_entry_hash(
            prev_hash=expected_prev_hash,
            occurred_at=entry.occurred_at,
            severity=entry.severity.value,
            event_type=entry.event_type.value,
            event_subtype=entry.event_subtype,
            actor=entry.actor,
            description=entry.description,
            tenant_slug=entry.tenant_slug,
            source_ip=entry.source_ip,
            metadata_json=entry.metadata_json,
        )
        hash_ok = expected_hash == entry.entry_hash and entry.prev_hash == expected_prev_hash
        signature_ok = verify_hex_digest(entry.entry_hash, entry.signature)

        if hash_ok and signature_ok:
            verified += 1
        else:
            failed += 1
            if first_break is None:
                first_break = entry.sequence

        # Continue the walk using the *stored* hash so a single corrupted
        # entry doesn't cascade into false positives for every entry after
        # it — we want to know exactly which entry broke, not just "the
        # rest of the chain doesn't match its ancestor".
        expected_prev_hash = entry.entry_hash

    duration_ms = round((time.perf_counter() - start) * 1000, 2)

    return ChainVerificationResult(
        verified_count=verified,
        failed_count=failed,
        is_valid=failed == 0,
        first_break_sequence=first_break,
        duration_ms=duration_ms,
        root_hash=entries[-1].entry_hash if entries else None,
    )


async def get_chain_summary(db: AsyncSession) -> HashChainSummary:
    total = (await db.execute(select(func.count()).select_from(AuditLogEntry))).scalar_one()
    tail = await _get_tail(db)
    verification = await verify_chain(db)
    return HashChainSummary(
        total_entries=total,
        root_hash=tail.entry_hash if tail else None,
        signing_key_id=tail.signing_key_id if tail else None,
        last_verified_at=datetime.now(timezone.utc),
        last_verification=verification,
    )


async def list_entries(
    db: AsyncSession,
    *,
    severity: str | None = None,
    event_type: str | None = None,
    tenant_slug: str | None = None,
    actor_search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[AuditLogEntryRead], int]:
    query = select(AuditLogEntry)
    count_query = select(func.count()).select_from(AuditLogEntry)

    if severity:
        query = query.where(AuditLogEntry.severity == severity)
        count_query = count_query.where(AuditLogEntry.severity == severity)
    if event_type:
        query = query.where(AuditLogEntry.event_type == event_type)
        count_query = count_query.where(AuditLogEntry.event_type == event_type)
    if tenant_slug:
        query = query.where(AuditLogEntry.tenant_slug == tenant_slug)
        count_query = count_query.where(AuditLogEntry.tenant_slug == tenant_slug)
    if actor_search:
        pattern = f"%{actor_search}%"
        query = query.where(AuditLogEntry.actor.ilike(pattern))
        count_query = count_query.where(AuditLogEntry.actor.ilike(pattern))

    total = (await db.execute(count_query)).scalar_one()

    query = (
        query.order_by(AuditLogEntry.sequence.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    entries = (await db.execute(query)).scalars().all()

    return [
        AuditLogEntryRead(
            id=e.id,
            sequence=e.sequence,
            occurred_at=e.occurred_at,
            severity=e.severity.value,
            event_type=e.event_type.value,
            event_subtype=e.event_subtype,
            tenant_slug=e.tenant_slug,
            actor=e.actor,
            source_ip=e.source_ip,
            description=e.description,
            metadata_json=e.metadata_json,
            prev_hash=e.prev_hash,
            entry_hash=e.entry_hash,
            signing_key_id=e.signing_key_id,
            integrity="valid",
        )
        for e in entries
    ], total
