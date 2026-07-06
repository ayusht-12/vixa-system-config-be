import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin


class TenantTier(str, enum.Enum):
    ENTERPRISE = "enterprise"
    PREMIUM = "premium"
    STANDARD = "standard"


class IsolationMode(str, enum.Enum):
    STRICT = "strict"
    STANDARD = "standard"
    SHARED = "shared"


class TenantStatus(str, enum.Enum):
    ACTIVE = "active"
    PROVISIONING = "provisioning"
    SUSPENDED = "suspended"
    DECOMMISSIONED = "decommissioned"


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    tier: Mapped[TenantTier] = mapped_column(
        Enum(TenantTier, native_enum=False, validate_strings=True), nullable=False
    )
    isolation_mode: Mapped[IsolationMode] = mapped_column(
        Enum(IsolationMode, native_enum=False, validate_strings=True),
        default=IsolationMode.STRICT,
        nullable=False,
    )
    status: Mapped[TenantStatus] = mapped_column(
        Enum(TenantStatus, native_enum=False, validate_strings=True),
        default=TenantStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    region: Mapped[str] = mapped_column(String(40), nullable=False)
    db_schema_name: Mapped[str] = mapped_column(String(80), nullable=False)
    db_schema_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    network_cidr: Mapped[str | None] = mapped_column(String(40), nullable=True)
    network_vpc: Mapped[str | None] = mapped_column(String(30), nullable=True)
    network_shared: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dek_label: Mapped[str | None] = mapped_column(String(60), nullable=True)
    encryption_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    events_per_second: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    provisioning_jobs: Mapped[list["TenantProvisioningJob"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    memberships: Mapped[list["TenantMember"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    schema_validations: Mapped[list["TenantSchemaValidation"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    backup_snapshots: Mapped[list["TenantBackupSnapshot"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )

    @property
    def isolation_score(self) -> float:
        """Weighted isolation posture score (0-100).

        Schema validity and encryption are hard requirements (40 points
        each); network isolation is weighted lower (20 points) because a
        shared subnet is a containable, monitored condition rather than an
        outright boundary failure.
        """
        score = 0.0
        score += 40.0 if self.db_schema_valid else 0.0
        score += 20.0 if not self.network_shared else 0.0
        score += 40.0 if self.encryption_valid else 0.0
        return round(score, 1)

    @property
    def isolation_level(self) -> str:
        if self.status == TenantStatus.PROVISIONING:
            return "pending"
        if not self.db_schema_valid or not self.encryption_valid:
            return "breach"
        if self.network_shared:
            return "partial"
        return "strict"


class TenantMemberRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class TenantMember(Base, TimestampMixin):
    __tablename__ = "tenant_members"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_tenant_members_tenant_user"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[TenantMemberRole] = mapped_column(
        Enum(TenantMemberRole, native_enum=False, validate_strings=True),
        default=TenantMemberRole.VIEWER,
        nullable=False,
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="memberships")
    user: Mapped["User"] = relationship(back_populates="tenant_memberships")


class BreachSeverity(str, enum.Enum):
    CRITICAL = "critical"
    WARNING = "warning"


class BreachAlert(Base, TimestampMixin):
    """Cross-tenant boundary violation or policy breach detected by the isolation enforcer."""

    __tablename__ = "breach_alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    severity: Mapped[BreachSeverity] = mapped_column(
        Enum(BreachSeverity, native_enum=False, validate_strings=True), nullable=False
    )
    title: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    target_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    resource: Mapped[str | None] = mapped_column(String(160), nullable=True)
    principal: Mapped[str | None] = mapped_column(String(160), nullable=True)
    action_taken: Mapped[str | None] = mapped_column(String(160), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    dismissed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


PROVISIONING_STEPS: list[str] = [
    "org_namespace_created",
    "network_policy_applied",
    "schema_migration",
    "dek_generation",
    "isolation_validation",
    "initial_snapshot",
]


class ProvisioningJobStatus(str, enum.Enum):
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETE = "complete"
    ABORTED = "aborted"


class TenantProvisioningJob(Base, TimestampMixin):
    __tablename__ = "tenant_provisioning_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[ProvisioningJobStatus] = mapped_column(
        Enum(ProvisioningJobStatus, native_enum=False, validate_strings=True),
        default=ProvisioningJobStatus.RUNNING,
        nullable=False,
    )
    completed_steps: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    current_step: Mapped[str | None] = mapped_column(String(60), nullable=True)
    eta_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="provisioning_jobs")

    @property
    def percent_complete(self) -> int:
        if not PROVISIONING_STEPS:
            return 0
        return round(len(self.completed_steps) / len(PROVISIONING_STEPS) * 100)


class TenantSchemaValidation(Base, TimestampMixin):
    __tablename__ = "tenant_schema_validations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    schema_name: Mapped[str] = mapped_column(String(80), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(20), nullable=False)
    table_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    detail: Mapped[str | None] = mapped_column(String(160), nullable=True)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    tenant: Mapped[Tenant] = relationship(back_populates="schema_validations")


class SnapshotStatus(str, enum.Enum):
    CURRENT = "current"
    STALE = "stale"
    PENDING = "pending"


class TenantBackupSnapshot(Base, TimestampMixin):
    __tablename__ = "tenant_backup_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[SnapshotStatus] = mapped_column(
        Enum(SnapshotStatus, native_enum=False, validate_strings=True), nullable=False
    )
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    taken_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retention_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    retained_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stale_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="backup_snapshots")
