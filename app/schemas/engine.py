from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORMModel


class EngineIdentity(BaseModel):
    instance_uuid: str
    name: str
    region: str
    availability_zone: str
    cluster_role: str
    uptime_seconds: int
    build_hash: str
    build_branch: str
    version: str
    is_operational: bool


class SystemHealthMetric(BaseModel):
    metric_key: str
    label: str
    value: float
    unit: str
    limit_value: float | None
    percent_of_limit: float | None
    footnote: str
    recorded_at: datetime


class EtcdNodeStatus(ORMModel):
    node_name: str
    address: str
    is_leader: bool
    raft_term: int
    lag_ms: float


class EtcdClusterStatus(BaseModel):
    nodes: list[EtcdNodeStatus]
    has_quorum: bool
    raft_term: int
    db_size_bytes: int
    write_ops_per_second: float
    read_ops_per_second: float


class ApiEndpointBreakdown(BaseModel):
    endpoint_path: str
    requests_per_second: float
    percent_of_total: float


class ApiRateSummary(BaseModel):
    current_rate: float
    peak_rate: float
    rate_limit: float
    throttled: int
    rejected: int
    latency_p99_ms: float
    endpoints: list[ApiEndpointBreakdown]


class OidcAuthStatus(BaseModel):
    provider: str | None
    active_tokens: int
    auth_rate: float
    failure_count: int
    failure_rate_percent: float
    jwks_refreshed_minutes_ago: int | None
    cert_valid_days: int | None


class CommandCenterOverview(BaseModel):
    engine: EngineIdentity
    system_health: list[SystemHealthMetric]
    etcd_cluster: EtcdClusterStatus
    api_rate: ApiRateSummary
    oidc: OidcAuthStatus
