import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import (
    AnomalyEvent,
    AnomalySeverity,
    AnomalyStatus,
    BehavioralBaseline,
    Incident,
    IncidentStatus,
)
from app.schemas.anomaly import (
    AnomalyDetectionOverview,
    AnomalyEventCreate,
    AnomalyEventRead,
    BehavioralBaselineRead,
    HeatmapCell,
    IncidentRead,
    SeveritySummaryBucket,
    ThreatCategoryStat,
)
from app.schemas.audit import AuditLogEntryCreate
from app.services.audit_service import append_entry_in_transaction

_HEATMAP_WINDOW_HOURS = 24
_ML_MODEL_NAME = "IsolationForest v3.2"


def _audit_actor(primary: str | None, fallback: str | None = None) -> str:
    return primary or fallback or "system"


def _audit_metadata(event: AnomalyEvent, *, previous_status: AnomalyStatus | None = None) -> dict:
    metadata = {
        "anomaly_id": str(event.id),
        "category": event.category,
        "severity": event.severity.value,
        "status": event.status.value,
        "score": event.score,
        "metadata_json": event.metadata_json,
    }
    if previous_status is not None:
        metadata["previous_status"] = previous_status.value
    return metadata


async def _append_anomaly_audit(
    db: AsyncSession,
    event: AnomalyEvent,
    *,
    actor: str,
    subtype: str,
    description: str,
    previous_status: AnomalyStatus | None = None,
) -> None:
    await append_entry_in_transaction(
        db,
        AuditLogEntryCreate(
            severity="info",
            event_type="anomaly_detected",
            event_subtype=subtype,
            actor=actor,
            description=description,
            tenant_id=event.tenant_id,
            source_ip=event.source_ip,
            metadata_json=_audit_metadata(event, previous_status=previous_status),
        ),
    )


async def create_anomaly_event(
    db: AsyncSession, payload: AnomalyEventCreate, *, audit_actor: str | None = None
) -> AnomalyEvent:
    """Ingest a new anomaly. Severity is derived from the ML score server-side —
    clients report a confidence score, never a severity label directly, so the
    classification boundary lives in one place (`AnomalySeverity.from_score`).
    """
    try:
        event = AnomalyEvent(
            tenant_id=payload.tenant_id,
            category=payload.category,
            score=payload.score,
            severity=AnomalySeverity.from_score(payload.score),
            status=AnomalyStatus.OPEN,
            title=payload.title,
            description=payload.description,
            actor=payload.actor,
            source_ip=payload.source_ip,
            baseline_sigma=payload.baseline_sigma,
            metadata_json=payload.metadata_json,
            occurred_at=datetime.now(timezone.utc),
        )
        db.add(event)
        await db.flush()
        await _append_anomaly_audit(
            db,
            event,
            actor=_audit_actor(audit_actor, payload.actor),
            subtype="ANOMALY_CREATED",
            description=f"Anomaly created: {event.title}",
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    await db.refresh(event)
    return event


async def _severity_summary(db: AsyncSession) -> list[SeveritySummaryBucket]:
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    two_hours_ago = now - timedelta(hours=2)

    current_counts = dict(
        (
            await db.execute(
                select(AnomalyEvent.severity, func.count())
                .where(AnomalyEvent.occurred_at >= hour_ago)
                .group_by(AnomalyEvent.severity)
            )
        ).all()
    )
    previous_counts = dict(
        (
            await db.execute(
                select(AnomalyEvent.severity, func.count())
                .where(
                    AnomalyEvent.occurred_at >= two_hours_ago,
                    AnomalyEvent.occurred_at < hour_ago,
                )
                .group_by(AnomalyEvent.severity)
            )
        ).all()
    )

    buckets = []
    for severity in AnomalySeverity:
        current = current_counts.get(severity, 0)
        previous = previous_counts.get(severity, 0)
        buckets.append(
            SeveritySummaryBucket(
                severity=severity.value,
                count=current,
                trend_delta=current - previous,
            )
        )
    return buckets


async def _heatmap(db: AsyncSession) -> list[HeatmapCell]:
    since = datetime.now(timezone.utc) - timedelta(hours=_HEATMAP_WINDOW_HOURS)
    rows = (
        await db.execute(
            select(
                func.date_trunc("hour", AnomalyEvent.occurred_at).label("bucket"),
                AnomalyEvent.severity,
                func.count().label("count"),
            )
            .where(AnomalyEvent.occurred_at >= since)
            .group_by("bucket", AnomalyEvent.severity)
        )
    ).all()

    if not rows:
        return []

    max_count = max(r.count for r in rows) or 1
    cells: list[HeatmapCell] = []
    for row in rows:
        cells.append(
            HeatmapCell(
                hour=row.bucket.hour,
                severity=row.severity.value,
                count=row.count,
                intensity_percent=round(row.count / max_count * 100, 1),
            )
        )
    return cells


async def _threat_categories(db: AsyncSession) -> list[ThreatCategoryStat]:
    since = datetime.now(timezone.utc) - timedelta(hours=_HEATMAP_WINDOW_HOURS)
    rows = (
        await db.execute(
            select(AnomalyEvent.category, func.count().label("count"))
            .where(AnomalyEvent.occurred_at >= since)
            .group_by(AnomalyEvent.category)
            .order_by(func.count().desc())
        )
    ).all()
    total = sum(r.count for r in rows)
    if not total:
        return []
    return [
        ThreatCategoryStat(
            category=row.category,
            count=row.count,
            percent=round(row.count / total * 100, 1),
        )
        for row in rows
    ]


async def _baselines(db: AsyncSession) -> list[BehavioralBaselineRead]:
    result = await db.execute(select(BehavioralBaseline).order_by(BehavioralBaseline.label))
    baselines = result.scalars().all()
    out = []
    for b in baselines:
        percent = round(min(100.0, b.current_value / b.upper_bound * 100), 1) if b.upper_bound else 0.0
        deviation = round(b.current_value / b.baseline_value, 2) if b.baseline_value else 0.0
        out.append(
            BehavioralBaselineRead(
                metric_key=b.metric_key,
                label=b.label,
                baseline_value=b.baseline_value,
                current_value=b.current_value,
                unit=b.unit,
                upper_bound=b.upper_bound,
                percent_of_upper_bound=percent,
                deviation_multiple=deviation,
            )
        )
    return out


def _incident_to_read(incident: Incident) -> IncidentRead:
    now = datetime.now(timezone.utc)
    remaining = None
    overdue = False
    if incident.status != IncidentStatus.RESOLVED:
        elapsed_minutes = (now - incident.created_at).total_seconds() / 60
        remaining = round(incident.sla_minutes - elapsed_minutes)
        overdue = remaining < 0
    return IncidentRead(
        id=incident.id,
        code=incident.code,
        severity=incident.severity.value,
        status=incident.status.value,
        summary=incident.summary,
        sla_minutes=incident.sla_minutes,
        sla_remaining_minutes=remaining,
        is_overdue=overdue,
        created_at=incident.created_at,
        resolved_at=incident.resolved_at,
    )


async def get_anomaly_detection_overview(db: AsyncSession) -> AnomalyDetectionOverview:
    recent_result = await db.execute(
        select(AnomalyEvent).order_by(AnomalyEvent.occurred_at.desc()).limit(25)
    )
    recent_events = recent_result.scalars().all()

    incidents_result = await db.execute(select(Incident).order_by(Incident.created_at.desc()))
    incidents = incidents_result.scalars().all()

    total_events_result = await db.execute(
        select(func.count()).select_from(AnomalyEvent).where(
            AnomalyEvent.occurred_at >= datetime.now(timezone.utc) - timedelta(seconds=1)
        )
    )
    stream_rate = float(total_events_result.scalar_one() or 0)

    return AnomalyDetectionOverview(
        stream_events_per_second=stream_rate,
        ml_model_name=_ML_MODEL_NAME,
        severity_summary=await _severity_summary(db),
        recent_events=[AnomalyEventRead.model_validate(e) for e in recent_events],
        baselines=await _baselines(db),
        heatmap=await _heatmap(db),
        threat_categories=await _threat_categories(db),
        incidents=[_incident_to_read(i) for i in incidents],
    )


async def update_anomaly_status(
    db: AsyncSession,
    event_id: uuid.UUID,
    status_value: AnomalyStatus,
    *,
    audit_actor: str | None = None,
) -> AnomalyEvent | None:
    try:
        event = await db.get(AnomalyEvent, event_id)
        if event is None:
            await db.rollback()
            return None

        previous_status = event.status
        event.status = status_value
        if status_value == AnomalyStatus.RESOLVED:
            event.resolved_at = datetime.now(timezone.utc)
        elif status_value == AnomalyStatus.OPEN:
            event.resolved_at = None

        await db.flush()
        await _append_anomaly_audit(
            db,
            event,
            actor=_audit_actor(audit_actor, event.actor),
            subtype="ANOMALY_STATUS_UPDATED",
            description=(
                f"Anomaly status updated: {previous_status.value} -> {event.status.value}"
            ),
            previous_status=previous_status,
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    await db.refresh(event)
    return event


async def get_anomaly_event(db: AsyncSession, event_id: uuid.UUID) -> AnomalyEvent:
    event = await db.get(AnomalyEvent, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return event


async def list_anomaly_events(
    db: AsyncSession,
    *,
    page: int,
    page_size: int,
    status_filter: AnomalyStatus | None = None,
    severity_filter: AnomalySeverity | None = None,
    category: str | None = None,
    tenant_id: uuid.UUID | None = None,
) -> tuple[list[AnomalyEventRead], int]:
    query = select(AnomalyEvent)
    count_query = select(func.count()).select_from(AnomalyEvent)

    filters = []
    if status_filter is not None:
        filters.append(AnomalyEvent.status == status_filter)
    if severity_filter is not None:
        filters.append(AnomalyEvent.severity == severity_filter)
    if category:
        filters.append(AnomalyEvent.category == category)
    if tenant_id is not None:
        filters.append(AnomalyEvent.tenant_id == tenant_id)

    for condition in filters:
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = (await db.execute(count_query)).scalar_one()

    query = (
        query.order_by(AnomalyEvent.occurred_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    events = (await db.execute(query)).scalars().all()
    return [AnomalyEventRead.model_validate(e) for e in events], total
