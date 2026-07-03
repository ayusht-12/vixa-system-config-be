import uuid
from datetime import datetime

from pydantic import BaseModel


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
