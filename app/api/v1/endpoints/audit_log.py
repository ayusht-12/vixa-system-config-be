from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.core.config import settings
from app.models.user import User
from app.schemas.audit import (
    AuditLogEntryCreate,
    AuditLogEntryRead,
    ChainVerificationResult,
    HashChainSummary,
)
from app.schemas.common import Page
from app.services.audit_service import append_entry, get_chain_summary, list_entries, verify_chain

router = APIRouter()


@router.get("/entries", response_model=Page[AuditLogEntryRead])
async def read_audit_entries(
    severity: str | None = None,
    event_type: str | None = None,
    tenant_slug: str | None = None,
    actor: str | None = Query(default=None, description="Substring search on actor"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Page[AuditLogEntryRead]:
    items, total = await list_entries(
        db,
        severity=severity,
        event_type=event_type,
        tenant_slug=tenant_slug,
        actor_search=actor,
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
        integrity="valid",
    )


@router.get("/summary", response_model=HashChainSummary)
async def read_chain_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> HashChainSummary:
    return await get_chain_summary(db)


@router.post("/verify", response_model=ChainVerificationResult)
async def trigger_chain_verification(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> ChainVerificationResult:
    """Re-walk and cryptographically verify the entire chain. Admin-only —
    this is a full table scan plus one signature verification per entry.
    """
    return await verify_chain(db)
