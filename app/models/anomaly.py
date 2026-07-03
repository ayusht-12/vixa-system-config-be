import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, Enum, Float, ForeignKey, String, Table, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin


class AnomalySeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_score(cls, score: float) -> "AnomalySeverity":
        """Classify an ML anomaly score (0..1) into a severity band.

        Thresholds mirror the model's calibrated decision boundaries used by
        the anomaly-scoring pipeline (IsolationForest confidence output).
        """
        if score >= 0.90:
            return cls.CRITICAL
        if score >= 0.70:
            return cls.HIGH
        if score >= 0.40:
            return cls.MEDIUM
        return cls.LOW


class AnomalyStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class AnomalyEvent(Base, TimestampMixin):
    __tablename__ = "anomaly_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True
    )
    category: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[AnomalySeverity] = mapped_column(
        Enum(AnomalySeverity, native_enum=False, validate_strings=True),
        nullable=False,
        index=True,
    )
    status: Mapped[AnomalyStatus] = mapped_column(
        Enum(AnomalyStatus, native_enum=False, validate_strings=True),
        default=AnomalyStatus.OPEN,
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    baseline_sigma: Mapped[float | None] = mapped_column(Float, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    incidents: Mapped[list["Incident"]] = relationship(
        secondary="incident_anomaly_links", back_populates="anomalies"
    )


class BehavioralBaseline(Base, TimestampMixin):
    """Rolling baseline vs. current-value comparison, used to render deviation bars."""

    __tablename__ = "behavioral_baselines"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    metric_key: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    baseline_value: Mapped[float] = mapped_column(Float, nullable=False)
    current_value: Mapped[float] = mapped_column(Float, nullable=False)
    unit: Mapped[str] = mapped_column(String(20), nullable=False)
    upper_bound: Mapped[float] = mapped_column(Float, nullable=False)


class IncidentSeverity(str, enum.Enum):
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"


class IncidentStatus(str, enum.Enum):
    UNASSIGNED = "unassigned"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"


class Incident(Base, TimestampMixin):
    """A correlated group of anomalies escalated into a tracked incident with an SLA clock."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    code: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity, native_enum=False, validate_strings=True), nullable=False
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, native_enum=False, validate_strings=True),
        default=IncidentStatus.UNASSIGNED,
        nullable=False,
    )
    summary: Mapped[str] = mapped_column(String(255), nullable=False)
    sla_minutes: Mapped[int] = mapped_column(default=60, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    anomalies: Mapped[list[AnomalyEvent]] = relationship(
        secondary="incident_anomaly_links", back_populates="incidents"
    )


incident_anomaly_links = Table(
    "incident_anomaly_links",
    Base.metadata,
    Column(
        "incident_id",
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "anomaly_event_id",
        UUID(as_uuid=True),
        ForeignKey("anomaly_events.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)
