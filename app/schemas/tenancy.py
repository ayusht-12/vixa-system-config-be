import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.tenancy import IsolationMode, TenantMemberRole, TenantTier


class TenantCreate(BaseModel):
    slug: str
    org_id: str
    display_name: str
    tier: TenantTier
    isolation_mode: IsolationMode = IsolationMode.STRICT
    region: str
    db_schema_name: str
    network_cidr: str | None = None
    network_vpc: str | None = None
    network_shared: bool = False
    dek_label: str | None = None


class TenantUpdate(BaseModel):
    display_name: str | None = None
    tier: TenantTier | None = None
    isolation_mode: IsolationMode | None = None
    region: str | None = None
    network_cidr: str | None = None
    network_vpc: str | None = None
    network_shared: bool | None = None
    dek_label: str | None = None
    db_schema_valid: bool | None = None
    encryption_valid: bool | None = None
    events_per_second: float | None = None


class TenantRead(BaseModel):
    id: uuid.UUID
    slug: str
    org_id: str
    display_name: str
    tier: str
    isolation_mode: str
    status: str
    region: str
    db_schema_name: str
    db_schema_valid: bool
    network_cidr: str | None
    network_vpc: str | None
    network_shared: bool
    dek_label: str | None
    encryption_valid: bool
    events_per_second: float
    isolation_score: float
    isolation_level: str


class BreachAlertRead(BaseModel):
    id: uuid.UUID
    severity: str
    title: str
    description: str
    source_tenant_slug: str | None
    target_tenant_slug: str | None
    resource: str | None
    principal: str | None
    action_taken: str | None
    detected_at: datetime
    dismissed: bool


class ProvisioningStepRead(BaseModel):
    key: str
    label: str
    status: str  # done | in_progress | pending


class ProvisioningJobRead(BaseModel):
    id: uuid.UUID
    tenant_slug: str
    status: str
    percent_complete: int
    steps: list[ProvisioningStepRead]
    eta_seconds: int | None


class TenantSchemaValidationRead(BaseModel):
    tenant_slug: str
    schema_name: str
    schema_version: str
    table_count: int | None
    status: str
    detail: str | None
    validated_at: datetime


class BackupSnapshotRead(BaseModel):
    tenant_slug: str
    status: str
    size_bytes: int | None
    taken_at: datetime | None
    age_hours: float | None
    retention_days: int
    retained_count: int
    stale_reason: str | None


class IsolationSummary(BaseModel):
    enforced: int
    partial: int
    breach: int
    pending: int
    total: int


class TenancyOverview(BaseModel):
    tenants: list[TenantRead]
    isolation_summary: IsolationSummary
    breach_alerts: list[BreachAlertRead]
    active_provisioning: list[ProvisioningJobRead]
    schema_validations: list[TenantSchemaValidationRead]
    backup_snapshots: list[BackupSnapshotRead]
    total_events_per_second: float


class TenantMemberCreate(BaseModel):
    user_id: uuid.UUID
    role: TenantMemberRole = TenantMemberRole.VIEWER


class TenantMemberRead(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    email: str
    display_name: str
    role: str
    created_at: datetime


class TenantUsageSummary(BaseModel):
    tenant_id: uuid.UUID
    slug: str
    display_name: str
    status: str
    member_count: int
    events_per_second: float
    provisioning_jobs_total: int
    active_provisioning_jobs: int
    schema_validations_total: int
    backup_snapshots_total: int
    current_backup_snapshots: int
    isolation_score: float
    isolation_level: str
