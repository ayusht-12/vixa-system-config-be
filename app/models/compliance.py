import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin


class FrameworkCode(str, enum.Enum):
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"


class ComplianceFramework(Base, TimestampMixin):
    __tablename__ = "compliance_frameworks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    code: Mapped[FrameworkCode] = mapped_column(
        Enum(FrameworkCode, native_enum=False, validate_strings=True),
        unique=True,
        nullable=False,
    )
    display_name: Mapped[str] = mapped_column(String(80), nullable=False)
    subtitle: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    auditor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    certified: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    score: Mapped[float] = mapped_column(Float, nullable=False, default=100.0)

    control_mappings: Mapped[list["ControlMapping"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan"
    )
    violations: Mapped[list["ComplianceViolation"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan"
    )


class ControlStatus(str, enum.Enum):
    MAPPED = "mapped"
    PARTIAL = "partial"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"


class ControlMapping(Base, TimestampMixin):
    """Coverage of one control domain (e.g. Access Control) under one framework."""

    __tablename__ = "control_mappings"
    __table_args__ = (
        UniqueConstraint("framework_id", "control_domain", name="uq_control_domain_per_framework"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False
    )
    control_domain: Mapped[str] = mapped_column(String(80), nullable=False)
    control_description: Mapped[str] = mapped_column(String(160), nullable=False)
    control_code: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[ControlStatus] = mapped_column(
        Enum(ControlStatus, native_enum=False, validate_strings=True), nullable=False
    )

    framework: Mapped[ComplianceFramework] = relationship(back_populates="control_mappings")


class ViolationSeverity(str, enum.Enum):
    VIOLATION = "violation"
    REVIEW = "review"


class ViolationStatus(str, enum.Enum):
    OPEN = "open"
    RESOLVED = "resolved"


class ComplianceViolation(Base, TimestampMixin):
    __tablename__ = "compliance_violations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    severity: Mapped[ViolationSeverity] = mapped_column(
        Enum(ViolationSeverity, native_enum=False, validate_strings=True), nullable=False
    )
    status: Mapped[ViolationStatus] = mapped_column(
        Enum(ViolationStatus, native_enum=False, validate_strings=True),
        default=ViolationStatus.OPEN,
        nullable=False,
    )
    control_reference: Mapped[str] = mapped_column(String(60), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(String(255), nullable=True)

    framework: Mapped[ComplianceFramework] = relationship(back_populates="violations")


class SchemaValidationResult(Base, TimestampMixin):
    """JSON-Schema validation outcome for an ingest/API endpoint payload."""

    __tablename__ = "schema_validation_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    endpoint_path: Mapped[str] = mapped_column(String(120), nullable=False)
    schema_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_message: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_slug: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reference_id: Mapped[str | None] = mapped_column(String(60), nullable=True)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AssessmentStatus(str, enum.Enum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class ComplianceAssessment(Base, TimestampMixin):
    """A point-in-time control assessment run against one framework. Started in
    IN_PROGRESS and finalized via complete(), which snapshots the control
    coverage counts and score at completion time."""

    __tablename__ = "compliance_assessments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[AssessmentStatus] = mapped_column(
        Enum(AssessmentStatus, native_enum=False, validate_strings=True),
        default=AssessmentStatus.IN_PROGRESS,
        nullable=False,
    )
    started_by: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    total_controls: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mapped_controls: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gap_controls: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str | None] = mapped_column(String(255), nullable=True)

    framework: Mapped[ComplianceFramework] = relationship()


class ComplianceScoreSnapshot(Base, TimestampMixin):
    """A recorded compliance score for one framework at a point in time. The
    series of these forms the score-trend history shown on the dashboard."""

    __tablename__ = "compliance_score_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    framework: Mapped[ComplianceFramework] = relationship()
