import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ConfigParameterRead(BaseModel):
    id: uuid.UUID
    key: str
    section: str
    tier: str
    value_type: str
    active_value: str
    pending_value: str | None
    has_pending_change: bool
    allowed_values: list[str] | None
    is_sensitive: bool
    requires_restart: bool
    description: str | None

    @classmethod
    def from_model(cls, param) -> "ConfigParameterRead":
        allowed = param.allowed_values.split(",") if param.allowed_values else None
        value = "••••••••" if param.is_sensitive else param.active_value
        pending = param.pending_value
        if param.is_sensitive and pending:
            pending = "••••••••"
        return cls(
            id=param.id,
            key=param.key,
            section=param.section,
            tier=param.tier.value,
            value_type=param.value_type.value,
            active_value=value,
            pending_value=pending,
            has_pending_change=param.has_pending_change,
            allowed_values=allowed,
            is_sensitive=param.is_sensitive,
            requires_restart=param.requires_restart,
            description=param.description,
        )


class ConfigParameterStage(BaseModel):
    value: str
    reason: str | None = None
    changed_by: str = "admin@nexus"


class ConfigChangeRead(BaseModel):
    id: uuid.UUID
    parameter_key: str
    previous_value: str
    new_value: str
    reason: str | None
    changed_by: str
    status: str
    created_at: datetime
    applied_at: datetime | None


class ConfigTierSummary(BaseModel):
    tier: str
    total: int
    pending: int


class ConfigManagerOverview(BaseModel):
    sections: dict[str, list[ConfigParameterRead]]
    tier_summary: list[ConfigTierSummary]
    pending_changes: list[ConfigChangeRead]


# --------------------------------------------------------------------------- #
# Versioned configuration documents
# --------------------------------------------------------------------------- #


class ConfigurationRead(BaseModel):
    id: uuid.UUID
    name: str
    version: int
    status: str
    payload: dict[str, Any]  # sensitive keys already masked by the service
    sensitive_keys: list[str]
    checksum: str
    description: str | None
    created_by: str
    activated_at: datetime | None
    archived_at: datetime | None
    deleted_at: datetime | None
    is_deleted: bool
    created_at: datetime
    updated_at: datetime


class ConfigurationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    payload: dict[str, Any]
    description: str | None = Field(default=None, max_length=255)
    sensitive_keys: list[str] = Field(default_factory=list)


class ConfigurationUpdate(BaseModel):
    """A PATCH creates a *successor version* rather than mutating in place."""

    payload: dict[str, Any]
    description: str | None = Field(default=None, max_length=255)
    sensitive_keys: list[str] | None = None


class ConfigurationValidateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    payload: dict[str, Any]
    sensitive_keys: list[str] = Field(default_factory=list)


class ConfigurationValidateResponse(BaseModel):
    valid: bool
    errors: list[str]
    checksum: str | None


class ConfigurationCompareResponse(BaseModel):
    name: str
    base_version: int
    other_version: int
    added: dict[str, Any]
    removed: dict[str, Any]
    changed: dict[str, dict[str, Any]]  # key -> {"from": ..., "to": ...}
    unchanged_count: int


class ConfigurationExportItem(BaseModel):
    name: str
    version: int
    status: str
    checksum: str
    description: str | None
    created_by: str
    created_at: datetime


class ConfigurationExportResponse(BaseModel):
    exported_at: datetime
    count: int
    items: list[ConfigurationExportItem]


class ConfigurationImportItem(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    payload: dict[str, Any]
    description: str | None = Field(default=None, max_length=255)
    sensitive_keys: list[str] = Field(default_factory=list)


class ConfigurationImportRequest(BaseModel):
    items: list[ConfigurationImportItem] = Field(min_length=1, max_length=100)


class ConfigurationImportResultRow(BaseModel):
    name: str
    version: int | None
    outcome: str  # "created" | "skipped"
    detail: str


class ConfigurationImportResponse(BaseModel):
    imported: int
    skipped: int
    rows: list[ConfigurationImportResultRow]
