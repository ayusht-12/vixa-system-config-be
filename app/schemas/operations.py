import uuid
from datetime import datetime

from pydantic import BaseModel


# --------------------------------------------------------------------------- #
# Metrics summary
# --------------------------------------------------------------------------- #


class MetricGauge(BaseModel):
    metric_key: str
    value: float
    unit: str
    limit_value: float | None
    percent_of_limit: float | None


class EndpointThroughput(BaseModel):
    endpoint_path: str
    requests_per_second: float
    throttled_count: int
    rejected_count: int
    latency_p99_ms: float


class MetricsSummary(BaseModel):
    captured_at: datetime | None
    gauges: list[MetricGauge]
    total_requests_per_second: float
    total_throttled: int
    total_rejected: int
    max_latency_p99_ms: float
    top_endpoints: list[EndpointThroughput]


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class ApplicationErrorRead(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    level: str
    error_type: str
    message: str
    source: str
    request_path: str | None
    status_code: int | None
    occurrences: int
    resolved: bool


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #


class BackgroundJobRead(BaseModel):
    id: uuid.UUID
    name: str
    queue: str
    status: str
    progress_percent: float
    scheduled_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: float | None
    attempts: int
    max_attempts: int
    last_error: str | None
    detail: str | None


# --------------------------------------------------------------------------- #
# Infrastructure status
# --------------------------------------------------------------------------- #


class CacheStatus(BaseModel):
    configured: bool
    status: str  # up | down | not_configured
    backend: str
    detail: str


class DbStatus(BaseModel):
    status: str  # up | down
    reachable: bool
    database: str
    pool_size: int
    checked_out: int
    overflow: int
    available: int
    latency_ms: float | None
    detail: str | None


class MigrationStatus(BaseModel):
    current_revision: str | None
    head_revision: str | None
    is_up_to_date: bool
    pending_count: int
    detail: str


class EventPublisherStatus(BaseModel):
    status: str  # healthy | degraded
    sink: str
    total_published: int
    last_published_at: datetime | None
    backlog: int


class ReadinessCheck(BaseModel):
    name: str
    status: str  # up | down | not_configured | skipped
    detail: str | None


class OperationalReadiness(BaseModel):
    status: str  # ready | not_ready
    checked_at: datetime
    checks: list[ReadinessCheck]
