import uuid
from datetime import datetime

from pydantic import BaseModel


class ControlMappingRead(BaseModel):
    control_domain: str
    control_description: str
    control_code: str
    status: str


class FrameworkRead(BaseModel):
    id: uuid.UUID
    code: str
    display_name: str
    subtitle: str
    description: str
    auditor: str | None
    certified: bool
    cert_expires_at: datetime | None
    score: float
    open_violation_count: int
    control_breakdown: list[ControlMappingRead]


class ControlCoverageRow(BaseModel):
    """One row of the cross-framework control-coverage table."""

    control_domain: str
    control_description: str
    per_framework: dict[str, ControlMappingRead | None]
    coverage_percent: float


class ViolationRead(BaseModel):
    id: uuid.UUID
    framework_code: str
    severity: str
    status: str
    control_reference: str
    title: str
    description: str
    detected_at: datetime
    resolved_at: datetime | None
    resolution_note: str | None


class SchemaValidationSummary(BaseModel):
    total_today: int
    pass_rate_percent: float
    failure_count: int
    failures: list["SchemaValidationRow"]


class SchemaValidationRow(BaseModel):
    endpoint_path: str
    schema_ref: str
    passed: bool
    error_message: str | None
    tenant_slug: str | None
    reference_id: str | None
    validated_at: datetime


class ComplianceOverview(BaseModel):
    overall_score: float
    frameworks: list[FrameworkRead]
    control_coverage: list[ControlCoverageRow]
    violations: list[ViolationRead]
    schema_validation: SchemaValidationSummary


class ControlRead(BaseModel):
    id: uuid.UUID
    framework_id: uuid.UUID
    framework_code: str
    control_domain: str
    control_description: str
    control_code: str
    status: str


class AssessmentCreate(BaseModel):
    framework_id: uuid.UUID


class AssessmentRead(BaseModel):
    id: uuid.UUID
    framework_id: uuid.UUID
    framework_code: str
    status: str
    started_by: str
    started_at: datetime
    completed_at: datetime | None
    score: float | None
    total_controls: int | None
    mapped_controls: int | None
    gap_controls: int | None
    notes: str | None


class FrameworkScore(BaseModel):
    code: str
    display_name: str
    score: float
    certified: bool
    open_violation_count: int


class ComplianceSummary(BaseModel):
    overall_score: float
    framework_count: int
    certified_count: int
    total_controls: int
    mapped_controls: int
    partial_controls: int
    gap_controls: int
    open_violation_count: int
    frameworks: list[FrameworkScore]


class GapRead(BaseModel):
    framework_id: uuid.UUID
    framework_code: str
    control_domain: str
    control_description: str
    control_code: str
    status: str  # gap | partial


class ScoreTrendPoint(BaseModel):
    captured_at: datetime
    score: float


class ScoreTrendSeries(BaseModel):
    framework_id: uuid.UUID
    code: str
    display_name: str
    current_score: float
    delta: float
    points: list[ScoreTrendPoint]


class ScoreTrendsResponse(BaseModel):
    window_days: int
    series: list[ScoreTrendSeries]
