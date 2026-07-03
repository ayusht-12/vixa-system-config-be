import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.audit import AuditLogEntryRead
from app.schemas.common import Page

TrendInterval = Literal["hour", "day"]


class DashboardSummary(BaseModel):
    total_tenants: int
    active_tenants: int
    total_configurations: int
    configurations_with_pending_changes: int
    audit_events_last_24h: int
    critical_audit_events_last_24h: int
    open_anomalies: int


class TenantHealth(BaseModel):
    tenant_id: uuid.UUID
    tenant_slug: str
    tenant_display_name: str
    tenant_status: str
    isolation_score: float
    isolation_level: str
    recent_audit_event_count: int
    critical_audit_event_count: int
    open_anomaly_count: int


class TenantHealthList(BaseModel):
    items: list[TenantHealth]
    total: int


class EventTrendBucket(BaseModel):
    bucket: datetime
    severity: str
    count: int


class EventTrends(BaseModel):
    interval: TrendInterval
    from_timestamp: datetime
    to_timestamp: datetime
    buckets: list[EventTrendBucket]


DashboardActivityPage = Page[AuditLogEntryRead]
