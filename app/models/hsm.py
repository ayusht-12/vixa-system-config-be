import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin


class SlotPurpose(str, enum.Enum):
    PRIMARY = "primary"
    SIGNING = "signing"
    TENANT_DEK = "tenant_dek"
    STANDBY = "standby"


class HsmSlot(Base, TimestampMixin):
    __tablename__ = "hsm_slots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    slot_number: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(60), nullable=False)
    purpose: Mapped[SlotPurpose] = mapped_column(
        Enum(SlotPurpose, native_enum=False, validate_strings=True), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    object_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    capacity_max_objects: Mapped[int] = mapped_column(Integer, default=2500, nullable=False)
    ops_per_second: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    token_flags: Mapped[str] = mapped_column(String(80), default="RNG,WRITE,LOGIN", nullable=False)

    master_keys: Mapped[list["MasterKey"]] = relationship(back_populates="slot")

    @property
    def capacity_percent(self) -> float:
        if self.capacity_max_objects <= 0:
            return 0.0
        return round(min(100.0, self.object_count / self.capacity_max_objects * 100), 1)


class MasterKeyStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRING = "expiring"
    RETIRED = "retired"
    PENDING = "pending"


class MasterKey(Base, TimestampMixin):
    __tablename__ = "master_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    key_label: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    slot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("hsm_slots.id", ondelete="SET NULL"), nullable=True
    )
    hsm_object_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    algorithm: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[MasterKeyStatus] = mapped_column(
        Enum(MasterKeyStatus, native_enum=False, validate_strings=True), nullable=False, index=True
    )
    rotation_policy_days: Mapped[int] = mapped_column(Integer, default=180, nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("master_keys.id", ondelete="SET NULL"), nullable=True
    )
    wraps_dek_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    throughput_ops: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    slot: Mapped[HsmSlot | None] = relationship(back_populates="master_keys")
    ceremonies: Mapped[list["KeyCeremony"]] = relationship(back_populates="master_key")


class CeremonyStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETE = "complete"
    ABORTED = "aborted"


class KeyCeremony(Base, TimestampMixin):
    """An m-of-n custodian-quorum key rotation/generation ceremony."""

    __tablename__ = "key_ceremonies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ceremony_ref: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    master_key_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("master_keys.id", ondelete="CASCADE"), nullable=False
    )
    predecessor_label: Mapped[str | None] = mapped_column(String(80), nullable=True)
    required_approvals: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    status: Mapped[CeremonyStatus] = mapped_column(
        Enum(CeremonyStatus, native_enum=False, validate_strings=True),
        default=CeremonyStatus.PENDING,
        nullable=False,
    )
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    master_key: Mapped[MasterKey] = relationship(back_populates="ceremonies")
    approvals: Mapped[list["KeyCustodianApproval"]] = relationship(
        back_populates="ceremony", cascade="all, delete-orphan"
    )

    @property
    def approval_count(self) -> int:
        return sum(1 for a in self.approvals if a.approved_at is not None)

    @property
    def quorum_met(self) -> bool:
        return self.approval_count >= self.required_approvals


class KeyCustodianApproval(Base, TimestampMixin):
    __tablename__ = "key_custodian_approvals"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ceremony_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("key_ceremonies.id", ondelete="CASCADE"), nullable=False
    )
    custodian_email: Mapped[str] = mapped_column(String(120), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    ceremony: Mapped[KeyCeremony] = relationship(back_populates="approvals")


class CertificateType(str, enum.Enum):
    TLS_SERVER = "tls_server"
    CODE_SIGN = "code_sign"
    OIDC_JWT = "oidc_jwt"
    MUTUAL_TLS = "mutual_tls"
    ROOT_CA = "root_ca"
    ATTESTATION = "attestation"


class Certificate(Base, TimestampMixin):
    __tablename__ = "certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    common_name: Mapped[str] = mapped_column(String(120), nullable=False)
    cert_type: Mapped[CertificateType] = mapped_column(
        Enum(CertificateType, native_enum=False, validate_strings=True), nullable=False
    )
    key_algorithm: Mapped[str] = mapped_column(String(30), nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(30), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    @property
    def days_left(self) -> int:
        from datetime import timezone as _tz

        now = datetime.now(_tz.utc)
        delta = self.expires_at - now
        return max(0, delta.days)


class CryptoAlgorithm(Base, TimestampMixin):
    __tablename__ = "crypto_algorithms"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    purpose_label: Mapped[str] = mapped_column(String(40), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ops_per_second: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    detail_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AttestationRun(Base, TimestampMixin):
    """One hardware-attestation sweep: a set of named pass/fail checks."""

    __tablename__ = "attestation_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    checks: Mapped[list[dict]] = mapped_column(JSON, nullable=False)
    all_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.get("passed"))
