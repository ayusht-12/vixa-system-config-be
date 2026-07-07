import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ORMModel

REDACTED_METADATA_VALUE = "[REDACTED]"
SENSITIVE_METADATA_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "credentials",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_key",
    "token",
}


def redact_sensitive_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: REDACTED_METADATA_VALUE
            if str(key).lower() in SENSITIVE_METADATA_KEYS
            else redact_sensitive_metadata(nested_value)
            for key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_metadata(item) for item in value]
    return value


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

    @field_validator("metadata_json", mode="before")
    @classmethod
    def redact_metadata_json(cls, value: Any) -> Any:
        return redact_sensitive_metadata(value)


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


# --------------------------------------------------------------------------- #
# History, bulk operations, trends & types
# --------------------------------------------------------------------------- #


class AnomalyHistoryEntry(BaseModel):
    """One lifecycle event for an anomaly, reconstructed from the immutable
    audit log (creation and each status transition)."""

    sequence: int
    occurred_at: datetime
    actor: str
    subtype: str
    description: str
    previous_status: str | None
    new_status: str | None


class BulkStatusRequest(BaseModel):
    event_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


class BulkStatusResponse(BaseModel):
    new_status: str
    requested: int
    updated: int
    updated_ids: list[uuid.UUID]
    not_found_ids: list[uuid.UUID]


class AnomalyTrendBucket(BaseModel):
    bucket: datetime
    severity: str
    count: int


class AnomalyTrends(BaseModel):
    interval: str
    from_timestamp: datetime
    to_timestamp: datetime
    buckets: list[AnomalyTrendBucket]


class AnomalyTypeStat(BaseModel):
    category: str
    total: int
    open_count: int


class AnomalyTypesResponse(BaseModel):
    categories: list[AnomalyTypeStat]
    severities: list[str]
    statuses: list[str]
