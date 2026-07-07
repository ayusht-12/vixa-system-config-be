from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_admin
from app.models.operations import ErrorLevel, JobStatus
from app.schemas.operations import (
    ApplicationErrorRead,
    BackgroundJobRead,
    CacheStatus,
    DbStatus,
    EventPublisherStatus,
    MetricsSummary,
    MigrationStatus,
    OperationalReadiness,
)
from app.services.operations_service import (
    get_cache_status,
    get_db_status,
    get_event_publisher_status,
    get_metrics_summary,
    get_migration_status,
    get_operational_readiness,
    list_errors,
    list_jobs,
)

# Observability internals expose infrastructure state, so the surface is admin-only.
router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/metrics-summary", response_model=MetricsSummary)
async def read_metrics_summary(db: AsyncSession = Depends(get_db)) -> MetricsSummary:
    return await get_metrics_summary(db)


@router.get("/errors", response_model=list[ApplicationErrorRead])
async def read_errors(
    db: AsyncSession = Depends(get_db),
    level: ErrorLevel | None = None,
    resolved: bool | None = None,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[ApplicationErrorRead]:
    return await list_errors(db, level=level, resolved=resolved, limit=limit)


@router.get("/jobs", response_model=list[BackgroundJobRead])
async def read_jobs(
    db: AsyncSession = Depends(get_db),
    status: JobStatus | None = None,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[BackgroundJobRead]:
    return await list_jobs(db, status_filter=status, limit=limit)


@router.get("/cache-status", response_model=CacheStatus)
async def read_cache_status() -> CacheStatus:
    return get_cache_status()


@router.get("/db-status", response_model=DbStatus)
async def read_db_status(db: AsyncSession = Depends(get_db)) -> DbStatus:
    return await get_db_status(db)


@router.get("/migrations", response_model=MigrationStatus)
async def read_migration_status(db: AsyncSession = Depends(get_db)) -> MigrationStatus:
    return await get_migration_status(db)


@router.get("/events", response_model=EventPublisherStatus)
async def read_event_publisher_status(
    db: AsyncSession = Depends(get_db),
) -> EventPublisherStatus:
    return await get_event_publisher_status(db)


@router.get("/readiness", response_model=OperationalReadiness)
async def read_operational_readiness(
    db: AsyncSession = Depends(get_db),
) -> OperationalReadiness:
    return await get_operational_readiness(db)
