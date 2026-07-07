import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base, TimestampMixin


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ErrorLevel(str, enum.Enum):
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"


class BackgroundJob(Base, TimestampMixin):
    """A tracked background/scheduled job execution (backups, attestation,
    score snapshots, etc.)."""

    __tablename__ = "background_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    queue: Mapped[str] = mapped_column(String(60), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, native_enum=False, validate_strings=True), nullable=False, index=True
    )
    progress_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ApplicationError(Base):
    """A recorded application error/exception occurrence, aggregated by type.

    Messages are stored as short, non-sensitive summaries — never raw request
    bodies, credentials or tokens."""

    __tablename__ = "application_errors"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    level: Mapped[ErrorLevel] = mapped_column(
        Enum(ErrorLevel, native_enum=False, validate_strings=True), nullable=False, index=True
    )
    error_type: Mapped[str] = mapped_column(String(120), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    request_path: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
