import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import AnomalyEvent, AnomalySeverity, AnomalyStatus
from app.models.audit import AuditLogEntry, AuditSeverity
from app.models.config import ConfigParameter
from app.models.tenancy import Tenant, TenantStatus
from app.schemas.audit import AuditLogEntryRead
from app.schemas.compliance import ComplianceSummary
from app.schemas.dashboard import (
    AnomalyOverviewKpis,
    CategoryCount,
    DashboardSummary,
    EventTrendBucket,
    EventTrends,
    SeverityCount,
    TenantHealth,
    TenantHealthList,
    TrendInterval,
)
from app.schemas.hsm import SecuritySummary
from app.services.compliance_service import get_compliance_summary
from app.services.hsm_service import get_security_summary

_OPEN_ANOMALY_STATUSES = (AnomalyStatus.OPEN, AnomalyStatus.INVESTIGATING)

# Kept in sync with the HSM router's module serial; only echoed in the summary.
_HSM_MODULE_SERIAL = "TL7-US-E1-0042"
# Kept in sync with the anomaly service's scoring model label.
_ML_MODEL_NAME = "IsolationForest v3.2"


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


async def get_anomaly_overview(db: AsyncSession) -> AnomalyOverviewKpis:
    """Light anomaly KPI aggregation for the dashboard's anomaly card."""
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)
    since_1h = now - timedelta(hours=1)

    status_counts = dict(
        (
            await db.execute(
                select(AnomalyEvent.status, func.count()).group_by(AnomalyEvent.status)
            )
        ).all()
    )
    open_by_severity = dict(
        (
            await db.execute(
                select(AnomalyEvent.severity, func.count())
                .where(AnomalyEvent.status.in_(_OPEN_ANOMALY_STATUSES))
                .group_by(AnomalyEvent.severity)
            )
        ).all()
    )

    resolved_last_24h = (
        await db.execute(
            select(func.count())
            .select_from(AnomalyEvent)
            .where(
                AnomalyEvent.status == AnomalyStatus.RESOLVED,
                AnomalyEvent.resolved_at.is_not(None),
                AnomalyEvent.resolved_at >= since_24h,
            )
        )
    ).scalar_one()
    dismissed_last_24h = (
        await db.execute(
            select(func.count())
            .select_from(AnomalyEvent)
            .where(
                AnomalyEvent.status == AnomalyStatus.DISMISSED,
                AnomalyEvent.updated_at >= since_24h,
            )
        )
    ).scalar_one()
    events_last_24h = (
        await db.execute(
            select(func.count())
            .select_from(AnomalyEvent)
            .where(AnomalyEvent.occurred_at >= since_24h)
        )
    ).scalar_one()
    events_last_hour = (
        await db.execute(
            select(func.count())
            .select_from(AnomalyEvent)
            .where(AnomalyEvent.occurred_at >= since_1h)
        )
    ).scalar_one()

    category_rows = (
        await db.execute(
            select(AnomalyEvent.category, func.count().label("count"))
            .where(AnomalyEvent.occurred_at >= since_24h)
            .group_by(AnomalyEvent.category)
            .order_by(func.count().desc())
            .limit(5)
        )
    ).all()

    return AnomalyOverviewKpis(
        open_count=status_counts.get(AnomalyStatus.OPEN, 0),
        investigating_count=status_counts.get(AnomalyStatus.INVESTIGATING, 0),
        resolved_last_24h=resolved_last_24h,
        dismissed_last_24h=dismissed_last_24h,
        critical_open=open_by_severity.get(AnomalySeverity.CRITICAL, 0),
        high_open=open_by_severity.get(AnomalySeverity.HIGH, 0),
        events_last_24h=events_last_24h,
        events_last_hour=events_last_hour,
        ml_model_name=_ML_MODEL_NAME,
        open_by_severity=[
            SeverityCount(severity=sev.value, count=open_by_severity.get(sev, 0))
            for sev in AnomalySeverity
        ],
        top_categories=[
            CategoryCount(category=row.category, count=row.count) for row in category_rows
        ],
    )


async def get_compliance_overview(db: AsyncSession) -> ComplianceSummary:
    """Compliance KPI aggregation — reuses the compliance module's posture summary."""
    return await get_compliance_summary(db)


async def get_security_overview(db: AsyncSession) -> SecuritySummary:
    """Security/HSM KPI aggregation — reuses the security module's posture summary."""
    return await get_security_summary(db, module_serial=_HSM_MODULE_SERIAL)


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
