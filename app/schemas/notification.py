import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.notification import AlertChannel, NotificationSeverity


# --------------------------------------------------------------------------- #
# Notifications
# --------------------------------------------------------------------------- #


class NotificationRead(BaseModel):
    id: uuid.UUID
    severity: str
    category: str
    title: str
    body: str
    source: str
    link: str | None
    is_read: bool
    read_at: datetime | None
    created_at: datetime


class UnreadCountResponse(BaseModel):
    unread: int
    total: int


class MarkAllReadResponse(BaseModel):
    detail: str
    marked_read: int


# --------------------------------------------------------------------------- #
# Alert rules
# --------------------------------------------------------------------------- #


class AlertRuleRead(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    source: str
    condition: str
    threshold_severity: str
    channel: str
    target: str
    is_enabled: bool
    created_by: str
    last_triggered_at: datetime | None
    trigger_count: int
    created_at: datetime


class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    source: str = Field(min_length=1, max_length=40)
    condition: str = Field(min_length=1, max_length=255)
    threshold_severity: NotificationSeverity
    channel: AlertChannel
    target: str = Field(min_length=1, max_length=200)
    is_enabled: bool = True


class AlertRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    source: str | None = Field(default=None, min_length=1, max_length=40)
    condition: str | None = Field(default=None, min_length=1, max_length=255)
    threshold_severity: NotificationSeverity | None = None
    channel: AlertChannel | None = None
    target: str | None = Field(default=None, min_length=1, max_length=200)
    is_enabled: bool | None = None
