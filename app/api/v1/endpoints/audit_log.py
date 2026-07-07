import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.core.config import settings
from app.models.audit import AuditEventType, AuditSeverity
from app.models.user import User
from app.schemas.audit import (
    AuditExportResponse,
    AuditLogEntryCreate,
    AuditLogEntryRead,
    ChainVerificationResult,
    HashChainSummary,
    IntegrityStatus,
)
from app.schemas.common import Page
from app.services.audit_service import (
    append_entry,
    export_entries,
    get_chain_summary,
    get_entry,
    get_integrity_status,
    list_entries,
    verify_chain,
)

router = APIRouter()


def _ensure_timezone_aware(value: datetime | None, field_name: str) -> datetime | None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{field_name} must include timezone information",
        )
    return value


@router.get("/entries", response_model=Page[AuditLogEntryRead])
async def read_audit_entries(
    severity: AuditSeverity | None = None,
    event_type: AuditEventType | None = None,
    tenant_slug: str | None = None,
    actor: str | None = Query(default=None, description="Substring search on actor"),
    search: str | None = Query(
        default=None,
        description="Case-insensitive search across actor, description, subtype, tenant, and source IP",
    ),
    from_time: datetime | None = Query(
        default=None,
        description="Inclusive lower bound for occurred_at; timezone required",
    ),
    to_time: datetime | None = Query(
        default=None,
        description="Inclusive upper bound for occurred_at; timezone required",
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Page[AuditLogEntryRead]:
    from_time = _ensure_timezone_aware(from_time, "from_time")
    to_time = _ensure_timezone_aware(to_time, "to_time")
    if from_time is not None and to_time is not None and from_time > to_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="from_time must be before or equal to to_time",
        )

    items, total = await list_entries(
        db,
        severity=severity.value if severity else None,
        event_type=event_type.value if event_type else None,
        tenant_slug=tenant_slug,
        actor_search=actor,
        search=search,
        from_time=from_time,
        to_time=to_time,
        page=page,
        page_size=page_size,
    )
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.post("/entries", response_model=AuditLogEntryRead, status_code=201)
async def create_audit_entry(
    payload: AuditLogEntryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditLogEntryRead:
    """Append an entry to the immutable log. There is intentionally no
    corresponding PATCH/DELETE — see `AuditLogEntry`'s docstring.
    """
    if payload.actor == "":
        payload.actor = current_user.email
    entry = await append_entry(db, payload)
    return AuditLogEntryRead(
        id=entry.id,
        sequence=entry.sequence,
        occurred_at=entry.occurred_at,
        severity=entry.severity.value,
        event_type=entry.event_type.value,
        event_subtype=entry.event_subtype,
        tenant_slug=entry.tenant_slug,
        actor=entry.actor,
        source_ip=entry.source_ip,
        description=entry.description,
        metadata_json=entry.metadata_json,
        prev_hash=entry.prev_hash,
        entry_hash=entry.entry_hash,
        signing_key_id=entry.signing_key_id,
        signature=entry.signature,
        integrity="unverified",
    )


@router.get("/summary", response_model=HashChainSummary)
async def read_chain_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> HashChainSummary:
    return await get_chain_summary(db)


@router.get("/export", response_model=AuditExportResponse)
async def export_audit_entries(
    severity: AuditSeverity | None = None,
    event_type: AuditEventType | None = None,
    tenant_slug: str | None = None,
    from_time: datetime | None = Query(default=None),
    to_time: datetime | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> AuditExportResponse:
    """Admin-only chronological export of audit metadata. Metadata is
    sanitized at write time, so no sensitive values are ever exported."""
    from_time = _ensure_timezone_aware(from_time, "from_time")
    to_time = _ensure_timezone_aware(to_time, "to_time")
    if from_time is not None and to_time is not None and from_time > to_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="from_time must be before or equal to to_time",
        )
    return await export_entries(
        db,
        severity=severity.value if severity else None,
        event_type=event_type.value if event_type else None,
        tenant_slug=tenant_slug,
        from_time=from_time,
        to_time=to_time,
    )


@router.get("/integrity-status", response_model=IntegrityStatus)
async def read_integrity_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> IntegrityStatus:
    """Current tamper-evidence status of the chain (verifies on read)."""
    return await get_integrity_status(db)


@router.get("/entries/{audit_log_id}", response_model=AuditLogEntryRead)
async def read_audit_entry(
    audit_log_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AuditLogEntryRead:
    return await get_entry(db, audit_log_id)


@router.post("/verify", response_model=ChainVerificationResult)
async def trigger_chain_verification(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> ChainVerificationResult:
    """Re-walk and cryptographically verify the entire chain. Admin-only —
    this is a full table scan plus one signature verification per entry.
    """
    return await verify_chain(db)
