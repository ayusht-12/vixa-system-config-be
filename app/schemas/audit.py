import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class AuditLogEntryCreate(BaseModel):
    severity: str
    event_type: str
    event_subtype: str
    actor: str
    description: str
    tenant_id: uuid.UUID | None = None
    tenant_slug: str | None = None
    source_ip: str | None = None
    metadata_json: dict = Field(default_factory=dict)


class AuditLogEntryRead(BaseModel):
    id: uuid.UUID
    sequence: int
    occurred_at: datetime
    severity: str
    event_type: str
    event_subtype: str
    tenant_slug: str | None
    actor: str
    source_ip: str | None
    description: str
    metadata_json: dict
    prev_hash: str | None
    entry_hash: str
    signing_key_id: str
    signature: str
    integrity: str  # "unverified" until an explicit chain verification is run


class ChainVerificationResult(BaseModel):
    verified_count: int
    failed_count: int
    is_valid: bool
    first_break_sequence: int | None
    duration_ms: float
    root_hash: str | None


class HashChainSummary(BaseModel):
    total_entries: int
    root_hash: str | None
    signing_key_id: str | None
    last_verified_at: datetime | None
    last_verification: ChainVerificationResult | None


class AuditExportResponse(BaseModel):
    """Controlled export of audit metadata. Entry metadata is already
    sanitized at write time, so no sensitive values are ever exported."""

    generated_at: datetime
    total: int
    returned: int
    truncated: bool
    entries: list[AuditLogEntryRead]


class IntegrityStatus(BaseModel):
    total_entries: int
    is_valid: bool
    verified_count: int
    failed_count: int
    first_break_sequence: int | None
    root_hash: str | None
    signing_key_id: str | None
    checked_at: datetime
    duration_ms: float
