import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import AnomalyEvent, AnomalyStatus
from app.models.audit import AuditLogEntry, AuditSeverity
from app.models.config import ConfigParameter
from app.models.tenancy import Tenant, TenantStatus
from app.schemas.audit import AuditLogEntryRead
from app.schemas.dashboard import (
    DashboardSummary,
    EventTrendBucket,
    EventTrends,
    TenantHealth,
    TenantHealthList,
    TrendInterval,
)

_OPEN_ANOMALY_STATUSES = (AnomalyStatus.OPEN, AnomalyStatus.INVESTIGATING)


async def get_summary(db: AsyncSession) -> DashboardSummary:
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    total_tenants = (await db.execute(select(func.count()).select_from(Tenant))).scalar_one()
    active_tenants = (
        await db.execute(
            select(func.count()).select_from(Tenant).where(Tenant.status == TenantStatus.ACTIVE)
        )
    ).scalar_one()
    total_configurations = (
        await db.execute(select(func.count()).select_from(ConfigParameter))
    ).scalar_one()
    configurations_with_pending_changes = (
        await db.execute(
            select(func.count())
            .select_from(ConfigParameter)
            .where(ConfigParameter.pending_value.is_not(None))
        )
    ).scalar_one()
    audit_events_last_24h = (
        await db.execute(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.occurred_at >= since_24h)
        )
    ).scalar_one()
    critical_audit_events_last_24h = (
        await db.execute(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(
                AuditLogEntry.occurred_at >= since_24h,
                AuditLogEntry.severity == AuditSeverity.CRITICAL,
            )
        )
    ).scalar_one()
    open_anomalies = (
        await db.execute(
            select(func.count())
            .select_from(AnomalyEvent)
            .where(AnomalyEvent.status.in_(_OPEN_ANOMALY_STATUSES))
        )
    ).scalar_one()

    return DashboardSummary(
        total_tenants=total_tenants,
        active_tenants=active_tenants,
        total_configurations=total_configurations,
        configurations_with_pending_changes=configurations_with_pending_changes,
        audit_events_last_24h=audit_events_last_24h,
        critical_audit_events_last_24h=critical_audit_events_last_24h,
        open_anomalies=open_anomalies,
    )


async def get_tenant_health(db: AsyncSession, *, since: datetime) -> TenantHealthList:
    tenants = (await db.execute(select(Tenant).order_by(Tenant.display_name))).scalars().all()

    audit_counts = dict(
        (
            await db.execute(
                select(AuditLogEntry.tenant_id, func.count())
                .where(AuditLogEntry.occurred_at >= since, AuditLogEntry.tenant_id.is_not(None))
                .group_by(AuditLogEntry.tenant_id)
            )
        ).all()
    )
    critical_audit_counts = dict(
        (
            await db.execute(
                select(AuditLogEntry.tenant_id, func.count())
                .where(
                    AuditLogEntry.occurred_at >= since,
                    AuditLogEntry.tenant_id.is_not(None),
                    AuditLogEntry.severity == AuditSeverity.CRITICAL,
                )
                .group_by(AuditLogEntry.tenant_id)
            )
        ).all()
    )
    open_anomaly_counts = dict(
        (
            await db.execute(
                select(AnomalyEvent.tenant_id, func.count())
                .where(
                    AnomalyEvent.tenant_id.is_not(None),
                    AnomalyEvent.status.in_(_OPEN_ANOMALY_STATUSES),
                )
                .group_by(AnomalyEvent.tenant_id)
            )
        ).all()
    )

    items = [
        TenantHealth(
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            tenant_display_name=tenant.display_name,
            tenant_status=tenant.status.value,
            isolation_score=tenant.isolation_score,
            isolation_level=tenant.isolation_level,
            recent_audit_event_count=audit_counts.get(tenant.id, 0),
            critical_audit_event_count=critical_audit_counts.get(tenant.id, 0),
            open_anomaly_count=open_anomaly_counts.get(tenant.id, 0),
        )
        for tenant in tenants
    ]
    return TenantHealthList(items=items, total=len(items))


async def get_event_trends(
    db: AsyncSession, *, from_timestamp: datetime, to_timestamp: datetime, interval: TrendInterval
) -> EventTrends:
    rows = (
        await db.execute(
            select(
                func.date_trunc(interval, AuditLogEntry.occurred_at).label("bucket"),
                AuditLogEntry.severity,
                func.count().label("count"),
            )
            .where(
                AuditLogEntry.occurred_at >= from_timestamp,
                AuditLogEntry.occurred_at <= to_timestamp,
            )
            .group_by("bucket", AuditLogEntry.severity)
            .order_by("bucket")
        )
    ).all()

    return EventTrends(
        interval=interval,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        buckets=[
            EventTrendBucket(bucket=row.bucket, severity=row.severity.value, count=row.count)
            for row in rows
        ],
    )


async def get_activity(
    db: AsyncSession,
    *,
    page: int,
    page_size: int,
    tenant_id: uuid.UUID | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> tuple[list[AuditLogEntryRead], int]:
    query = select(AuditLogEntry)
    count_query = select(func.count()).select_from(AuditLogEntry)

    filters = []
    if tenant_id is not None:
        filters.append(AuditLogEntry.tenant_id == tenant_id)
    if event_type:
        filters.append(AuditLogEntry.event_type == event_type)
    if severity:
        filters.append(AuditLogEntry.severity == severity)
    if created_from:
        filters.append(AuditLogEntry.occurred_at >= created_from)
    if created_to:
        filters.append(AuditLogEntry.occurred_at <= created_to)

    for condition in filters:
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = (await db.execute(count_query)).scalar_one()

    query = (
        query.order_by(AuditLogEntry.sequence.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    entries = (await db.execute(query)).scalars().all()

    items = [
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
            signature=e.signature,
            integrity="valid",
        )
        for e in entries
    ]
    return items, total
