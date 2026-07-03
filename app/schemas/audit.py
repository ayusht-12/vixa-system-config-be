import uuid
from datetime import datetime

from pydantic import BaseModel


class AuditLogEntryCreate(BaseModel):
    severity: str
    event_type: str
    event_subtype: str
    actor: str
    description: str
    tenant_id: uuid.UUID | None = None
    tenant_slug: str | None = None
    source_ip: str | None = None
    metadata_json: dict = {}


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
    integrity: str  # "valid" — chain position, checked lazily on verify, not per-read


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
