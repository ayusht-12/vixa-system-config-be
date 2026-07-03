import uuid
from datetime import datetime, timedelta, timezone

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

_HEATMAP_WINDOW_HOURS = 24
_ML_MODEL_NAME = "IsolationForest v3.2"


async def create_anomaly_event(db: AsyncSession, payload: AnomalyEventCreate) -> AnomalyEvent:
    """Ingest a new anomaly. Severity is derived from the ML score server-side —
    clients report a confidence score, never a severity label directly, so the
    classification boundary lives in one place (`AnomalySeverity.from_score`).
    """
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
    await db.commit()
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
    db: AsyncSession, event_id: uuid.UUID, status_value: AnomalyStatus
) -> AnomalyEvent | None:
    event = await db.get(AnomalyEvent, event_id)
    if event is None:
        return None
    event.status = status_value
    if status_value == AnomalyStatus.RESOLVED:
        event.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(event)
    return event
