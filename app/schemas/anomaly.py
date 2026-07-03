import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORMModel


class AnomalyEventRead(ORMModel):
    id: uuid.UUID
    category: str
    score: float
    severity: str
    status: str
    title: str
    description: str
    actor: str | None
    source_ip: str | None
    baseline_sigma: float | None
    metadata_json: dict
    occurred_at: datetime


class AnomalyEventCreate(BaseModel):
    category: str
    score: float
    title: str
    description: str
    actor: str | None = None
    source_ip: str | None = None
    tenant_id: uuid.UUID | None = None
    baseline_sigma: float | None = None
    metadata_json: dict = {}


class SeveritySummaryBucket(BaseModel):
    severity: str
    count: int
    trend_delta: int
    trend_window_label: str = "last hour"


class BehavioralBaselineRead(BaseModel):
    metric_key: str
    label: str
    baseline_value: float
    current_value: float
    unit: str
    upper_bound: float
    percent_of_upper_bound: float
    deviation_multiple: float


class HeatmapCell(BaseModel):
    hour: int
    severity: str
    count: int
    intensity_percent: float


class ThreatCategoryStat(BaseModel):
    category: str
    count: int
    percent: float


class IncidentRead(BaseModel):
    id: uuid.UUID
    code: str
    severity: str
    status: str
    summary: str
    sla_minutes: int
    sla_remaining_minutes: int | None
    is_overdue: bool
    created_at: datetime
    resolved_at: datetime | None


class AnomalyDetectionOverview(BaseModel):
    stream_events_per_second: float
    ml_model_name: str
    severity_summary: list[SeveritySummaryBucket]
    recent_events: list[AnomalyEventRead]
    baselines: list[BehavioralBaselineRead]
    heatmap: list[HeatmapCell]
    threat_categories: list[ThreatCategoryStat]
    incidents: list[IncidentRead]
