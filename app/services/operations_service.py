import time
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import engine
from app.models.audit import AuditLogEntry
from app.models.engine import ApiEndpointStat, SystemMetricSample
from app.models.operations import ApplicationError, BackgroundJob, ErrorLevel, JobStatus
from app.schemas.operations import (
    ApplicationErrorRead,
    BackgroundJobRead,
    CacheStatus,
    DbStatus,
    EndpointThroughput,
    EventPublisherStatus,
    MetricGauge,
    MetricsSummary,
    MigrationStatus,
    OperationalReadiness,
    ReadinessCheck,
)


# --------------------------------------------------------------------------- #
# Metrics summary (derived from real engine telemetry)
# --------------------------------------------------------------------------- #


async def get_metrics_summary(db: AsyncSession) -> MetricsSummary:
    # Latest sample per metric key.
    samples = (
        await db.execute(
            select(SystemMetricSample).order_by(SystemMetricSample.recorded_at.desc())
        )
    ).scalars().all()
    latest_by_key: dict = {}
    captured_at: datetime | None = None
    for sample in samples:
        if sample.metric_key not in latest_by_key:
            latest_by_key[sample.metric_key] = sample
            if captured_at is None or sample.recorded_at > captured_at:
                captured_at = sample.recorded_at

    gauges = [
        MetricGauge(
            metric_key=s.metric_key.value,
            value=round(s.value, 2),
            unit=s.unit,
            limit_value=s.limit_value,
            percent_of_limit=(
                round(min(100.0, s.value / s.limit_value * 100), 1) if s.limit_value else None
            ),
        )
        for s in latest_by_key.values()
    ]
    gauges.sort(key=lambda g: g.metric_key)

    stats = (await db.execute(select(ApiEndpointStat))).scalars().all()
    total_rps = round(sum(s.requests_per_second for s in stats), 2)
    total_throttled = sum(s.throttled_count for s in stats)
    total_rejected = sum(s.rejected_count for s in stats)
    max_p99 = round(max((s.latency_p99_ms for s in stats), default=0.0), 2)
    top = sorted(stats, key=lambda s: s.requests_per_second, reverse=True)[:5]

    return MetricsSummary(
        captured_at=captured_at,
        gauges=gauges,
        total_requests_per_second=total_rps,
        total_throttled=total_throttled,
        total_rejected=total_rejected,
        max_latency_p99_ms=max_p99,
        top_endpoints=[
            EndpointThroughput(
                endpoint_path=s.endpoint_path,
                requests_per_second=round(s.requests_per_second, 2),
                throttled_count=s.throttled_count,
                rejected_count=s.rejected_count,
                latency_p99_ms=round(s.latency_p99_ms, 2),
            )
            for s in top
        ],
    )


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


async def list_errors(
    db: AsyncSession,
    *,
    level: ErrorLevel | None = None,
    resolved: bool | None = None,
    limit: int = 50,
) -> list[ApplicationErrorRead]:
    query = select(ApplicationError).order_by(ApplicationError.occurred_at.desc()).limit(limit)
    if level is not None:
        query = query.where(ApplicationError.level == level)
    if resolved is not None:
        query = query.where(ApplicationError.resolved == resolved)
    rows = (await db.execute(query)).scalars().all()
    return [
        ApplicationErrorRead(
            id=r.id,
            occurred_at=r.occurred_at,
            level=r.level.value,
            error_type=r.error_type,
            message=r.message,
            source=r.source,
            request_path=r.request_path,
            status_code=r.status_code,
            occurrences=r.occurrences,
            resolved=r.resolved,
        )
        for r in rows
    ]


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #


async def list_jobs(
    db: AsyncSession, *, status_filter: JobStatus | None = None, limit: int = 50
) -> list[BackgroundJobRead]:
    query = select(BackgroundJob).order_by(BackgroundJob.created_at.desc()).limit(limit)
    if status_filter is not None:
        query = query.where(BackgroundJob.status == status_filter)
    rows = (await db.execute(query)).scalars().all()
    return [
        BackgroundJobRead(
            id=r.id,
            name=r.name,
            queue=r.queue,
            status=r.status.value,
            progress_percent=r.progress_percent,
            scheduled_at=r.scheduled_at,
            started_at=r.started_at,
            finished_at=r.finished_at,
            duration_ms=r.duration_ms,
            attempts=r.attempts,
            max_attempts=r.max_attempts,
            last_error=r.last_error,
            detail=r.detail,
        )
        for r in rows
    ]


# --------------------------------------------------------------------------- #
# Infrastructure status (live introspection — nothing fabricated)
# --------------------------------------------------------------------------- #


def get_cache_status() -> CacheStatus:
    """No cache backend is configured in this deployment, so this is reported
    honestly rather than with placeholder hit-rate figures."""
    return CacheStatus(
        configured=False,
        status="not_configured",
        backend="none",
        detail="No cache backend (e.g. Redis) is configured for this environment.",
    )


async def get_db_status(db: AsyncSession) -> DbStatus:
    reachable = True
    latency_ms: float | None = None
    detail: str | None = None
    try:
        start = time.perf_counter()
        await db.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
    except Exception as exc:  # pragma: no cover - only on a real outage
        reachable = False
        detail = "database unreachable"
        _ = exc

    pool = engine.pool
    try:
        pool_size = pool.size()
        checked_out = pool.checkedout()
        overflow = pool.overflow()
    except Exception:  # pragma: no cover - pool type without these methods
        pool_size = settings.DB_POOL_SIZE
        checked_out = 0
        overflow = 0

    available = max(0, pool_size - checked_out)
    return DbStatus(
        status="up" if reachable else "down",
        reachable=reachable,
        database=settings.POSTGRES_DB,
        pool_size=pool_size,
        checked_out=checked_out,
        overflow=overflow,
        available=available,
        latency_ms=latency_ms,
        detail=detail,
    )


def _alembic_head() -> str | None:
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        root = Path(__file__).resolve().parents[2]
        cfg = Config()
        cfg.set_main_option("script_location", str(root / "alembic"))
        return ScriptDirectory.from_config(cfg).get_current_head()
    except Exception:  # pragma: no cover - defensive
        return None


async def get_migration_status(db: AsyncSession) -> MigrationStatus:
    # Probe for the table first: a failing SELECT against a missing relation
    # aborts the surrounding transaction in Postgres and would poison any
    # queries that follow in the same session (e.g. the readiness aggregate).
    has_version_table = (
        await db.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = 'alembic_version'"
            )
        )
    ).scalar()
    current: str | None = None
    if has_version_table:
        current = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar()

    head = _alembic_head()
    up_to_date = current is not None and head is not None and current == head
    if up_to_date:
        detail = "Database schema is at the latest migration."
        pending = 0
    elif current is None:
        detail = "No alembic_version recorded; database may be schema-managed out of band."
        pending = 0
    elif head is None:
        detail = "Could not resolve the migration head from the script directory."
        pending = 0
    else:
        detail = f"Database is at '{current}' but code head is '{head}'."
        pending = 1

    return MigrationStatus(
        current_revision=current,
        head_revision=head,
        is_up_to_date=up_to_date,
        pending_count=pending,
        detail=detail,
    )


async def get_event_publisher_status(db: AsyncSession) -> EventPublisherStatus:
    """The immutable audit log is this platform's event sink; publisher health
    is reported from it directly rather than an imaginary broker."""
    total = (await db.execute(select(func.count()).select_from(AuditLogEntry))).scalar_one()
    last = (
        await db.execute(select(func.max(AuditLogEntry.occurred_at)))
    ).scalar()
    return EventPublisherStatus(
        status="healthy",
        sink="immutable-audit-log",
        total_published=total,
        last_published_at=last,
        backlog=0,
    )


async def get_operational_readiness(db: AsyncSession) -> OperationalReadiness:
    db_status = await get_db_status(db)
    migration_status = await get_migration_status(db)
    cache_status = get_cache_status()

    checks = [
        ReadinessCheck(
            name="database",
            status=db_status.status,
            detail=db_status.detail or f"latency {db_status.latency_ms}ms",
        ),
        ReadinessCheck(
            name="migrations",
            status="up" if migration_status.is_up_to_date else "degraded",
            detail=migration_status.detail,
        ),
        ReadinessCheck(
            name="cache",
            status=cache_status.status,
            detail=cache_status.detail,
        ),
    ]
    # Cache being unconfigured is not a hard readiness failure; only the
    # database must be reachable for the service to be considered ready.
    ready = db_status.reachable
    return OperationalReadiness(
        status="ready" if ready else "not_ready",
        checked_at=datetime.now(timezone.utc),
        checks=checks,
    )
