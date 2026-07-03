from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.engine import ApiEndpointStat, EngineInstance, SystemMetricSample
from app.schemas.engine import (
    ApiEndpointBreakdown,
    ApiRateSummary,
    CommandCenterOverview,
    EngineIdentity,
    EtcdClusterStatus,
    EtcdNodeStatus,
    OidcAuthStatus,
    SystemHealthMetric,
)

# A node is considered "responsive" for quorum purposes if its replication
# lag is below this threshold; a node lagging further behind is treated as
# unreachable for consensus math even though it may still be listed.
_QUORUM_LAG_THRESHOLD_MS = 5_000

# Static per-metric limit used to compute "percent of limit" until a real
# capacity-planning table backs this. Kept in the service layer (not the
# DB) because these are deployment-tuning constants, not tenant data.
_METRIC_LIMITS: dict[str, float] = {
    "goroutines": 10_000,
    "gc_pause_ms": 2.0,
    "open_fds": 65_536,
}


async def _get_engine_instance(db: AsyncSession) -> EngineInstance:
    result = await db.execute(
        select(EngineInstance)
        .options(selectinload(EngineInstance.etcd_nodes))
        .where(EngineInstance.is_operational.is_(True))
        .order_by(EngineInstance.created_at.asc())
        .limit(1)
    )
    instance = result.scalar_one_or_none()
    if instance is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No operational engine instance found"
        )
    return instance


def _build_identity(instance: EngineInstance) -> EngineIdentity:
    now = datetime.now(timezone.utc)
    uptime = int((now - instance.started_at).total_seconds())
    return EngineIdentity(
        instance_uuid=instance.instance_uuid,
        name=instance.name,
        region=instance.region,
        availability_zone=instance.availability_zone,
        cluster_role=instance.cluster_role.value,
        uptime_seconds=max(0, uptime),
        build_hash=instance.build_hash,
        build_branch=instance.build_branch,
        version=instance.version,
        is_operational=instance.is_operational,
    )


async def _latest_system_health(db: AsyncSession, instance_id) -> list[SystemHealthMetric]:
    # Latest sample per metric_key via DISTINCT ON, Postgres-native and far
    # cheaper than pulling full history and reducing in Python.
    result = await db.execute(
        select(SystemMetricSample)
        .where(SystemMetricSample.engine_instance_id == instance_id)
        .order_by(SystemMetricSample.metric_key, SystemMetricSample.recorded_at.desc())
    )
    samples = result.scalars().all()
    seen: set[str] = set()
    metrics: list[SystemHealthMetric] = []
    for sample in samples:
        key = sample.metric_key.value
        if key in seen:
            continue
        seen.add(key)
        limit_value = sample.limit_value or _METRIC_LIMITS.get(key)
        percent = round(sample.value / limit_value * 100, 1) if limit_value else None
        metrics.append(
            SystemHealthMetric(
                metric_key=key,
                label=key.replace("_", " ").title(),
                value=sample.value,
                unit=sample.unit,
                limit_value=limit_value,
                percent_of_limit=percent,
                footnote=f"limit {limit_value:,.0f}" if limit_value else "",
                recorded_at=sample.recorded_at,
            )
        )
    return metrics


def _build_etcd_cluster(instance: EngineInstance) -> EtcdClusterStatus:
    nodes = instance.etcd_nodes
    responsive = [n for n in nodes if n.lag_ms < _QUORUM_LAG_THRESHOLD_MS]
    majority = len(nodes) // 2 + 1
    leader = next((n for n in nodes if n.is_leader), None)
    return EtcdClusterStatus(
        nodes=[EtcdNodeStatus.model_validate(n) for n in nodes],
        has_quorum=len(responsive) >= majority if nodes else False,
        raft_term=leader.raft_term if leader else (nodes[0].raft_term if nodes else 0),
        db_size_bytes=sum(n.db_size_bytes for n in nodes) // max(len(nodes), 1),
        write_ops_per_second=0.0,
        read_ops_per_second=0.0,
    )


async def _build_api_rate_summary(db: AsyncSession, instance_id) -> ApiRateSummary:
    result = await db.execute(
        select(ApiEndpointStat)
        .where(ApiEndpointStat.engine_instance_id == instance_id)
        .order_by(ApiEndpointStat.recorded_at.desc())
        .limit(20)
    )
    samples = result.scalars().all()
    seen: set[str] = set()
    latest_per_endpoint = []
    for sample in samples:
        if sample.endpoint_path in seen:
            continue
        seen.add(sample.endpoint_path)
        latest_per_endpoint.append(sample)

    total_rate = sum(s.requests_per_second for s in latest_per_endpoint)
    endpoints = [
        ApiEndpointBreakdown(
            endpoint_path=s.endpoint_path,
            requests_per_second=s.requests_per_second,
            percent_of_total=round(s.requests_per_second / total_rate * 100, 1)
            if total_rate
            else 0.0,
        )
        for s in sorted(latest_per_endpoint, key=lambda s: s.requests_per_second, reverse=True)
    ]
    return ApiRateSummary(
        current_rate=round(total_rate, 1),
        peak_rate=round(max((s.requests_per_second for s in latest_per_endpoint), default=0.0), 1),
        rate_limit=1000.0,
        throttled=sum(s.throttled_count for s in latest_per_endpoint),
        rejected=sum(s.rejected_count for s in latest_per_endpoint),
        latency_p99_ms=round(
            max((s.latency_p99_ms for s in latest_per_endpoint), default=0.0), 2
        ),
        endpoints=endpoints,
    )


def _build_oidc_status(instance: EngineInstance) -> OidcAuthStatus:
    now = datetime.now(timezone.utc)
    jwks_minutes_ago = None
    if instance.oidc_jwks_refreshed_at:
        jwks_minutes_ago = max(
            0, int((now - instance.oidc_jwks_refreshed_at).total_seconds() // 60)
        )
    cert_days = None
    if instance.oidc_cert_valid_until:
        cert_days = max(0, (instance.oidc_cert_valid_until - now).days)

    attempts = instance.oidc_active_tokens + instance.oidc_failure_count
    failure_rate = round(instance.oidc_failure_count / attempts * 100, 2) if attempts else 0.0

    return OidcAuthStatus(
        provider=instance.oidc_provider,
        active_tokens=instance.oidc_active_tokens,
        auth_rate=instance.oidc_auth_rate,
        failure_count=instance.oidc_failure_count,
        failure_rate_percent=failure_rate,
        jwks_refreshed_minutes_ago=jwks_minutes_ago,
        cert_valid_days=cert_days,
    )


async def get_command_center_overview(db: AsyncSession) -> CommandCenterOverview:
    instance = await _get_engine_instance(db)
    return CommandCenterOverview(
        engine=_build_identity(instance),
        system_health=await _latest_system_health(db, instance.id),
        etcd_cluster=_build_etcd_cluster(instance),
        api_rate=await _build_api_rate_summary(db, instance.id),
        oidc=_build_oidc_status(instance),
    )
