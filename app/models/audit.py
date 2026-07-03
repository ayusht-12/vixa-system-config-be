import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, BigInteger, DateTime, Enum, ForeignKey, Identity, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base


class AuditSeverity(str, enum.Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class AuditEventType(str, enum.Enum):
    STATE_CHANGE = "state_change"
    AUTH_EVENT = "auth_event"
    CONFIG_CHANGE = "config_change"
    POLICY_EVAL = "policy_eval"
    TENANT_LIFECYCLE = "tenant_lifecycle"
    KEY_OPERATION = "key_operation"
    ANOMALY_DETECTED = "anomaly_detected"


class AuditLogEntry(Base):
    """Append-only, hash-chained audit log entry.

    Every entry commits to the hash of the entry immediately before it
    (``prev_hash``), forming a tamper-evident chain analogous to a
    single-lane blockchain: mutating or deleting any historical row breaks
    the hash of every entry after it, which ``verify_chain`` detects.

    This table has no ``updated_at`` and the service layer never issues
    UPDATE/DELETE against it — a DB-level trigger (see migration
    ``0002_audit_log_immutability``) additionally rejects those statements
    at the database level, so immutability doesn't depend on application
    discipline alone.
    """

    __tablename__ = "audit_log_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sequence: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), unique=True, nullable=False, index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    severity: Mapped[AuditSeverity] = mapped_column(
        Enum(AuditSeverity, native_enum=False, validate_strings=True), nullable=False, index=True
    )
    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, native_enum=False, validate_strings=True),
        nullable=False,
        index=True,
    )
    event_subtype: Mapped[str] = mapped_column(String(60), nullable=False)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True
    )
    tenant_slug: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    signing_key_id: Mapped[str] = mapped_column(String(60), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
