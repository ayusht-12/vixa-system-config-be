import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin


class ClusterRole(str, enum.Enum):
    PRIMARY = "primary"
    REPLICA = "replica"
    STANDBY = "standby"


class EngineInstance(Base, TimestampMixin):
    """A running Nexus Engine node. Normally one row per deployment region."""

    __tablename__ = "engine_instances"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    instance_uuid: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    region: Mapped[str] = mapped_column(String(60), nullable=False)
    availability_zone: Mapped[str] = mapped_column(String(30), nullable=False)
    cluster_role: Mapped[ClusterRole] = mapped_column(
        Enum(ClusterRole, native_enum=False, validate_strings=True),
        default=ClusterRole.PRIMARY,
        nullable=False,
    )
    build_hash: Mapped[str] = mapped_column(String(40), nullable=False)
    build_branch: Mapped[str] = mapped_column(String(60), default="main", nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_operational: Mapped[bool] = mapped_column(default=True, nullable=False)

    # OIDC auth snapshot — engine-wide, so modeled as columns rather than a
    # separate 1:1 table.
    oidc_provider: Mapped[str | None] = mapped_column(String(80), nullable=True)
    oidc_active_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    oidc_auth_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    oidc_failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    oidc_jwks_refreshed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    oidc_cert_valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    etcd_nodes: Mapped[list["EtcdNode"]] = relationship(
        back_populates="engine_instance", cascade="all, delete-orphan"
    )
    metric_samples: Mapped[list["SystemMetricSample"]] = relationship(
        back_populates="engine_instance", cascade="all, delete-orphan"
    )


class EtcdNode(Base, TimestampMixin):
    __tablename__ = "etcd_nodes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    engine_instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engine_instances.id", ondelete="CASCADE"), nullable=False
    )
    node_name: Mapped[str] = mapped_column(String(40), nullable=False)
    address: Mapped[str] = mapped_column(String(64), nullable=False)
    is_leader: Mapped[bool] = mapped_column(default=False, nullable=False)
    raft_term: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lag_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    db_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    engine_instance: Mapped[EngineInstance] = relationship(back_populates="etcd_nodes")


class MetricKey(str, enum.Enum):
    CPU_PERCENT = "cpu_percent"
    MEMORY_PERCENT = "memory_percent"
    DISK_IO_MBPS = "disk_io_mbps"
    NETWORK_MBPS = "network_mbps"
    GOROUTINES = "goroutines"
    GC_PAUSE_MS = "gc_pause_ms"
    OPEN_FDS = "open_fds"


class SystemMetricSample(Base):
    """Time-series telemetry sample. One row per (metric, collection tick)."""

    __tablename__ = "system_metric_samples"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    engine_instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engine_instances.id", ondelete="CASCADE"), nullable=False, index=True
    )
    metric_key: Mapped[MetricKey] = mapped_column(
        Enum(MetricKey, native_enum=False, validate_strings=True), nullable=False, index=True
    )
    value: Mapped[float] = mapped_column(Float, nullable=False)
    unit: Mapped[str] = mapped_column(String(20), nullable=False)
    limit_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    engine_instance: Mapped[EngineInstance] = relationship(back_populates="metric_samples")


class ApiEndpointStat(Base):
    """Rolling per-endpoint rate-limit throughput sample."""

    __tablename__ = "api_endpoint_stats"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    engine_instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("engine_instances.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint_path: Mapped[str] = mapped_column(String(120), nullable=False)
    requests_per_second: Mapped[float] = mapped_column(Float, nullable=False)
    throttled_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    latency_p99_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
