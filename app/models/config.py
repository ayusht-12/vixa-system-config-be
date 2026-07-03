import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin


class ConfigTier(str, enum.Enum):
    CRITICAL = "critical"
    NECESSARY = "necessary"
    OPTIONAL = "optional"


class ConfigValueType(str, enum.Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    DURATION = "duration"
    ENUM = "enum"
    JSON = "json"


class ConfigParameter(Base, TimestampMixin):
    """A single named engine configuration key, grouped into a UI section."""

    __tablename__ = "config_parameters"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    key: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    section: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    tier: Mapped[ConfigTier] = mapped_column(
        Enum(ConfigTier, native_enum=False, validate_strings=True), nullable=False, index=True
    )
    value_type: Mapped[ConfigValueType] = mapped_column(
        Enum(ConfigValueType, native_enum=False, validate_strings=True), nullable=False
    )
    active_value: Mapped[str] = mapped_column(Text, nullable=False)
    pending_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    allowed_values: Mapped[str | None] = mapped_column(
        String(500), nullable=True, doc="Comma-separated allowed values for enum types"
    )
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    requires_restart: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    changes: Mapped[list["ConfigChange"]] = relationship(
        back_populates="parameter", cascade="all, delete-orphan", order_by="desc(ConfigChange.created_at)"
    )

    @property
    def has_pending_change(self) -> bool:
        return self.pending_value is not None and self.pending_value != self.active_value


class ConfigChangeStatus(str, enum.Enum):
    PENDING = "pending"
    APPLIED = "applied"
    REVERTED = "reverted"


class ConfigChange(Base, TimestampMixin):
    """Audit trail of every staged/applied config mutation (config diff view)."""

    __tablename__ = "config_changes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    parameter_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("config_parameters.id", ondelete="CASCADE"), nullable=False
    )
    previous_value: Mapped[str] = mapped_column(Text, nullable=False)
    new_value: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    changed_by: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[ConfigChangeStatus] = mapped_column(
        Enum(ConfigChangeStatus, native_enum=False, validate_strings=True),
        default=ConfigChangeStatus.PENDING,
        nullable=False,
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    parameter: Mapped[ConfigParameter] = relationship(back_populates="changes")
