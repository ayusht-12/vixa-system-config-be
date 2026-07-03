import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.models.user import User
from app.schemas.common import Page
from app.schemas.dashboard import (
    AuditLogEntryRead,
    DashboardSummary,
    EventTrends,
    TenantHealthList,
    TrendInterval,
)
from app.services.dashboard_service import (
    get_activity,
    get_event_trends,
    get_summary,
    get_tenant_health,
)

router = APIRouter()


@router.get("/summary", response_model=DashboardSummary)
async def read_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> DashboardSummary:
    return await get_summary(db)


@router.get("/activity", response_model=Page[AuditLogEntryRead])
async def read_dashboard_activity(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    tenant_id: uuid.UUID | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> Page[AuditLogEntryRead]:
    items, total = await get_activity(
        db,
        page=page,
        page_size=page_size,
        tenant_id=tenant_id,
        event_type=event_type,
        severity=severity,
        created_from=created_from,
        created_to=created_to,
    )
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/tenant-health", response_model=TenantHealthList)
async def read_tenant_health(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    since: datetime | None = None,
) -> TenantHealthList:
    if since is None:
        since = datetime.now(timezone.utc) - timedelta(hours=24)
    return await get_tenant_health(db, since=since)


@router.get("/event-trends", response_model=EventTrends)
async def read_event_trends(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    from_timestamp: datetime | None = None,
    to_timestamp: datetime | None = None,
    interval: TrendInterval = "day",
) -> EventTrends:
    if to_timestamp is None:
        to_timestamp = datetime.now(timezone.utc)
    if from_timestamp is None:
        from_timestamp = to_timestamp - timedelta(days=7)
    return await get_event_trends(
        db, from_timestamp=from_timestamp, to_timestamp=to_timestamp, interval=interval
    )
