"""Seed the database with a realistic demo dataset.

Run with:  .venv/bin/python -m scripts.seed_data

Idempotent-ish: re-running clears and repopulates the domain tables (but
never touches the audit log directly — entries are appended through
`audit_service.append_entry` so the hash chain stays internally consistent
across repeated runs).
"""

import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from sqlalchemy import delete, select  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.core.security import hash_password  # noqa: E402
from app.db.session import AsyncSessionLocal, engine  # noqa: E402
from app.models.anomaly import (  # noqa: E402
    AnomalyEvent,
    AnomalySeverity,
    AnomalyStatus,
    BehavioralBaseline,
    Incident,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.compliance import (  # noqa: E402
    ComplianceFramework,
    ComplianceScoreSnapshot,
    ComplianceViolation,
    ControlMapping,
    ControlStatus,
    FrameworkCode,
    SchemaValidationResult,
    ViolationSeverity,
    ViolationStatus,
)
from app.models.config import ConfigChange, ConfigChangeStatus, ConfigParameter  # noqa: E402
from app.models.config import ConfigTier, ConfigValueType  # noqa: E402
from app.models.config import Configuration, ConfigurationStatus  # noqa: E402
from app.models.engine import (  # noqa: E402
    ApiEndpointStat,
    ClusterRole,
    EngineInstance,
    EtcdNode,
    MetricKey,
    SystemMetricSample,
)
from app.models.notification import (  # noqa: E402
    AlertChannel,
    AlertRule,
    Notification,
    NotificationSeverity,
)
from app.models.operations import (  # noqa: E402
    ApplicationError,
    BackgroundJob,
    ErrorLevel,
    JobStatus,
)
from app.models.rbac import Permission, Role, RolePermission, UserRole  # noqa: E402
from app.models.hsm import (  # noqa: E402
    AttestationRun,
    Certificate,
    CertificateType,
    CeremonyStatus,
    CryptoAlgorithm,
    HsmSlot,
    KeyCeremony,
    KeyCustodianApproval,
    MasterKey,
    MasterKeyStatus,
    SecurityOperation,
    SecurityOperationStatus,
    SecurityOperationType,
    SecurityProvider,
    SecurityProviderType,
    SlotPurpose,
)
from app.models.tenancy import (  # noqa: E402
    BreachAlert,
    BreachSeverity,
    IsolationMode,
    ProvisioningJobStatus,
    SnapshotStatus,
    Tenant,
    TenantBackupSnapshot,
    TenantProvisioningJob,
    TenantSchemaValidation,
    TenantStatus,
    TenantTier,
)
from app.models.user import User  # noqa: E402
from app.schemas.audit import AuditLogEntryCreate  # noqa: E402
from app.services.audit_service import append_entry  # noqa: E402

NOW = datetime.now(timezone.utc)


def hours_ago(h: float) -> datetime:
    return NOW - timedelta(hours=h)


def days_ago(d: float) -> datetime:
    return NOW - timedelta(days=d)


def days_from_now(d: float) -> datetime:
    return NOW + timedelta(days=d)


async def _wipe_domain_tables(db: AsyncSession) -> None:
    """Clear everything except users/audit — re-seedable without duplicate
    key errors on unique columns (slug, key, ceremony_ref, ...).
    """
    for model in [
        # RBAC / notifications / operations (children before parents)
        UserRole,
        RolePermission,
        Role,
        Permission,
        Notification,
        AlertRule,
        BackgroundJob,
        ApplicationError,
        TenantBackupSnapshot,
        TenantSchemaValidation,
        TenantProvisioningJob,
        BreachAlert,
        KeyCustodianApproval,
        KeyCeremony,
        SecurityOperation,
        MasterKey,
        HsmSlot,
        Certificate,
        CryptoAlgorithm,
        AttestationRun,
        SecurityProvider,
        Configuration,
        ConfigChange,
        ConfigParameter,
        SchemaValidationResult,
        ComplianceScoreSnapshot,
        ComplianceViolation,
        ControlMapping,
        ComplianceFramework,
        Incident,
        AnomalyEvent,
        BehavioralBaseline,
        ApiEndpointStat,
        SystemMetricSample,
        EtcdNode,
        EngineInstance,
        Tenant,
    ]:
        await db.execute(delete(model))
    await db.commit()


async def seed_user(db: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(),
        email="admin@nexus",
        display_name="Admin",
        hashed_password=hash_password("NexusAdmin!2026"),
        is_active=True,
        is_admin=True,
    )
    db.add(user)
    await db.commit()
    return user


async def seed_engine(db: AsyncSession) -> EngineInstance:
    instance = EngineInstance(
        id=uuid.uuid4(),
        instance_uuid="01944f2c-7b3a-7000-8e4d-2f9a1b3c5d7e",
        name="nexus-primary-us-east-1",
        region="us-east-1",
        availability_zone="AZ-3",
        cluster_role=ClusterRole.PRIMARY,
        build_hash="a3f9c2d",
        build_branch="main",
        version="4.7.2",
        started_at=NOW - timedelta(days=47, hours=12, minutes=33),
        is_operational=True,
        oidc_provider="Keycloak 22.x",
        oidc_active_tokens=14821,
        oidc_auth_rate=342.0,
        oidc_failure_count=7,
        oidc_jwks_refreshed_at=hours_ago(4 / 60),
        oidc_cert_valid_until=days_from_now(89),
    )
    db.add(instance)
    await db.flush()

    for i, (name, addr, leader, term, lag, size) in enumerate(
        [
            ("etcd-0", "10.0.1.10", True, 47, 0.0, 4_700_000_000),
            ("etcd-1", "10.0.1.11", False, 47, 2.0, 4_698_000_000),
            ("etcd-2", "10.0.1.12", False, 47, 3.0, 4_699_500_000),
        ]
    ):
        db.add(
            EtcdNode(
                engine_instance_id=instance.id,
                node_name=name,
                address=addr,
                is_leader=leader,
                raft_term=term,
                lag_ms=lag,
                db_size_bytes=size,
            )
        )

    metrics = [
        (MetricKey.CPU_PERCENT, 34.0, "%", 100.0, "16 cores · 3.2GHz"),
        (MetricKey.MEMORY_PERCENT, 61.0, "%", 100.0, "49.2 / 80 GB"),
        (MetricKey.DISK_IO_MBPS, 2100.0, "MB/s", 5000.0, "NVMe · 5.0 max"),
        (MetricKey.NETWORK_MBPS, 847.0, "Mb/s", 1000.0, "up 412 / down 435"),
        (MetricKey.GOROUTINES, 4821.0, "count", 10000.0, "healthy"),
        (MetricKey.GC_PAUSE_MS, 0.8, "ms", 2.0, "p99 target <2ms"),
        (MetricKey.OPEN_FDS, 12447.0, "count", 65536.0, "limit 65,536"),
    ]
    for key, value, unit, limit, _note in metrics:
        db.add(
            SystemMetricSample(
                engine_instance_id=instance.id,
                metric_key=key,
                value=value,
                unit=unit,
                limit_value=limit,
                recorded_at=NOW,
            )
        )

    endpoints = [
        ("/api/v4/events", 341.0, 8, 2, 4.2),
        ("/api/v4/query", 210.0, 3, 1, 3.8),
        ("/api/v4/ingest", 192.0, 1, 0, 4.9),
    ]
    for path, rps, throttled, rejected, p99 in endpoints:
        db.add(
            ApiEndpointStat(
                engine_instance_id=instance.id,
                endpoint_path=path,
                requests_per_second=rps,
                throttled_count=throttled,
                rejected_count=rejected,
                latency_p99_ms=p99,
                recorded_at=NOW,
            )
        )

    await db.commit()
    return instance


async def seed_tenants(db: AsyncSession) -> dict[str, Tenant]:
    rows = [
        dict(
            slug="acme-corp", org_id="ORG-001", display_name="acme-corp",
            tier=TenantTier.ENTERPRISE, region="us-east-1",
            db_schema_name="schema_acme_corp", db_schema_valid=True,
            network_cidr="10.0.1.0/24", network_vpc="VPC-001", network_shared=False,
            dek_label="dek-acme-0x0001", encryption_valid=True, events_per_second=1247.0,
        ),
        dict(
            slug="fintech-labs", org_id="ORG-004", display_name="fintech-labs",
            tier=TenantTier.ENTERPRISE, region="us-east-1",
            db_schema_name="schema_fintech_labs", db_schema_valid=True,
            network_cidr="10.0.4.0/24", network_vpc="VPC-004", network_shared=False,
            dek_label="dek-fintech-0x0004", encryption_valid=True, events_per_second=892.0,
        ),
        dict(
            slug="healthsys-io", org_id="ORG-003", display_name="healthsys-io",
            tier=TenantTier.PREMIUM, region="us-east-1",
            db_schema_name="schema_healthsys_io", db_schema_valid=True,
            network_cidr="10.0.4.0/24", network_vpc="VPC-004", network_shared=True,
            dek_label="dek-health-0x0003", encryption_valid=True, events_per_second=634.0,
        ),
        dict(
            slug="retail-nexus", org_id="ORG-005", display_name="retail-nexus",
            tier=TenantTier.PREMIUM, region="us-east-1",
            db_schema_name="schema_retail_nexus", db_schema_valid=True,
            network_cidr="10.0.5.0/24", network_vpc="VPC-005", network_shared=False,
            dek_label="dek-retail-0x0005", encryption_valid=True, events_per_second=421.0,
        ),
        dict(
            slug="govcloud-fed", org_id="ORG-002", display_name="govcloud-fed",
            tier=TenantTier.ENTERPRISE, region="us-east-1",
            db_schema_name="schema_govcloud_fed", db_schema_valid=True,
            network_cidr="10.0.2.0/24", network_vpc="VPC-002", network_shared=False,
            dek_label="dek-gov-0x0002", encryption_valid=True, events_per_second=1089.0,
        ),
        dict(
            slug="startup-alpha", org_id="ORG-006", display_name="startup-alpha",
            tier=TenantTier.STANDARD, region="us-east-1",
            db_schema_name="schema_startup_alpha", db_schema_valid=True,
            network_cidr="10.0.6.0/24", network_vpc="VPC-006", network_shared=False,
            dek_label="dek-startup-0x0006", encryption_valid=True, events_per_second=87.0,
        ),
        dict(
            slug="media-stream-x", org_id="ORG-007", display_name="media-stream-x",
            tier=TenantTier.PREMIUM, region="us-east-1",
            db_schema_name="schema_media_x", db_schema_valid=False,
            network_cidr="10.0.7.0/24", network_vpc="VPC-007", network_shared=False,
            dek_label="dek-media-0x0047", encryption_valid=False, events_per_second=347.0,
        ),
        dict(
            slug="fintech-labs-2", org_id="ORG-025", display_name="fintech-labs-2",
            tier=TenantTier.ENTERPRISE, region="us-east-1",
            db_schema_name="schema_fintech_2", db_schema_valid=False,
            network_cidr="10.0.25.0/24", network_vpc=None, network_shared=False,
            dek_label=None, encryption_valid=False, events_per_second=0.0,
            status=TenantStatus.PROVISIONING,
        ),
    ]
    tenants: dict[str, Tenant] = {}
    for row in rows:
        status = row.pop("status", TenantStatus.ACTIVE)
        tenant = Tenant(
            id=uuid.uuid4(),
            isolation_mode=IsolationMode.STRICT,
            status=status,
            **row,
        )
        db.add(tenant)
        tenants[tenant.slug] = tenant
    await db.commit()
    return tenants


async def seed_anomalies(db: AsyncSession, tenants: dict[str, Tenant]) -> None:
    events = [
        ("STATE_CHANGE", 0.97, "PRIV_ESCALATION", "acme-corp",
         "Privilege escalation: svc-deploy-01 assumed IAM::AdminRole without MFA",
         "svc-deploy-01", "10.0.4.22", 4.7, hours_ago(0.02)),
        ("STATE_CHANGE", 0.94, "RATE_ANOMALY", "acme-corp",
         "API rate spike 3.2sigma above baseline — DDoS vector detected on /ingest",
         "engine-core", "203.0.113.0", 3.2, hours_ago(0.05)),
        ("POLICY_EVAL", 0.78, "LATENCY_BREACH", None,
         "etcd write latency p99 exceeded 15ms threshold — node etcd-1 degraded",
         "engine-core", None, 2.1, hours_ago(0.1)),
        ("KEY_OPERATION", 0.71, "HSM_CAPACITY", None,
         "HSM slot utilization approaching capacity (87%)", "engine-core", None, 1.9, hours_ago(0.2)),
        ("TENANT_LIFECYCLE", 0.42, "TENANT_CREATED", "fintech-labs-2",
         "New tenant provisioned — isolation boundary established", "tenant-provisioner", None, 0.5,
         hours_ago(0.35)),
    ]
    for category, score, subtype, tenant_slug, desc, actor, ip, sigma, occurred in events:
        db.add(
            AnomalyEvent(
                id=uuid.uuid4(),
                tenant_id=tenants[tenant_slug].id if tenant_slug else None,
                category=category,
                score=score,
                severity=AnomalySeverity.from_score(score),
                status=AnomalyStatus.OPEN,
                title=subtype.replace("_", " ").title(),
                description=desc,
                actor=actor,
                source_ip=ip,
                baseline_sigma=sigma,
                metadata_json={"event_subtype": subtype},
                occurred_at=occurred,
            )
        )

    baselines = [
        ("api_request_rate", "API Request Rate", 743.0, 3241.0, "req/s", 5000.0),
        ("auth_failure_rate", "Auth Failure Rate", 0.02, 0.31, "%", 5.0),
        ("outbound_transfer", "Outbound Transfer", 120.0, 2300.0, "MB/h", 5000.0),
        ("privilege_ops", "Privilege Ops/min", 12.0, 565.0, "ops/min", 600.0),
        ("etcd_write_p99", "etcd Write p99", 4.2, 18.3, "ms", 50.0),
    ]
    for key, label, baseline, current, unit, upper in baselines:
        db.add(
            BehavioralBaseline(
                metric_key=key, label=label, baseline_value=baseline,
                current_value=current, unit=unit, upper_bound=upper,
            )
        )

    db.add(
        Incident(
            id=uuid.uuid4(), code="INC-2026-0847", severity=IncidentSeverity.P1,
            status=IncidentStatus.UNASSIGNED,
            summary="Privilege escalation + DDoS vector — acme-corp tenant · 2 correlated anomalies",
            sla_minutes=60,
        )
    )
    db.add(
        Incident(
            id=uuid.uuid4(), code="INC-2026-0846", severity=IncidentSeverity.P2,
            status=IncidentStatus.IN_PROGRESS,
            summary="Data exfiltration pattern — healthsys-io · 2.3GB anomalous outbound transfer",
            sla_minutes=120,
        )
    )
    resolved_incident = Incident(
        id=uuid.uuid4(), code="INC-2026-0845", severity=IncidentSeverity.P3,
        status=IncidentStatus.RESOLVED,
        summary="HSM slot utilization spike — auto-remediated via key rotation policy",
        sla_minutes=240,
    )
    resolved_incident.resolved_at = hours_ago(0.3)
    db.add(resolved_incident)

    await db.commit()


async def seed_compliance(db: AsyncSession) -> None:
    frameworks_data = [
        (FrameworkCode.SOC2, "SOC2", "Type II", "Trust Services Criteria", "Deloitte",
         days_from_now(258), 92.8,
         [
             ("Access Control", "IAM · RBAC · MFA · SSO", "CC6", ControlStatus.MAPPED),
             ("Encryption & Crypto", "AES-256 · TLS 1.3 · HSM · Key Mgmt", "CC6.7", ControlStatus.MAPPED),
             ("Incident Response", "Detection · Escalation · Recovery · SLA", "CC7.2", ControlStatus.PARTIAL),
             ("Audit Logging", "Immutable · Merkle · Retention · SIEM", "CC7.3", ControlStatus.MAPPED),
             ("Data Residency", "Geo-fencing · Cross-border · Retention", "CC6.3", ControlStatus.MAPPED),
             ("Vulnerability Mgmt", "CVE scanning · Patch SLA · Pen testing", "CC7.1", ControlStatus.MAPPED),
             ("Tenant Isolation", "Network · Data · Compute · Namespace", "CC6.6", ControlStatus.MAPPED),
         ]),
        (FrameworkCode.ISO27001, "ISO", "27001:2022", "Information Security Mgmt", "BSI Group",
         days_from_now(620), 88.1,
         [
             ("Access Control", "IAM · RBAC · MFA · SSO", "A.9", ControlStatus.MAPPED),
             ("Encryption & Crypto", "AES-256 · TLS 1.3 · HSM · Key Mgmt", "A.10", ControlStatus.MAPPED),
             ("Incident Response", "Detection · Escalation · Recovery · SLA", "A.16", ControlStatus.MAPPED),
             ("Audit Logging", "Immutable · Merkle · Retention · SIEM", "A.12.4", ControlStatus.MAPPED),
             ("Data Residency", "Geo-fencing · Cross-border · Retention", "A.8.3", ControlStatus.PARTIAL),
             ("Vulnerability Mgmt", "CVE scanning · Patch SLA · Pen testing", "A.12.6", ControlStatus.MAPPED),
             ("Tenant Isolation", "Network · Data · Compute · Namespace", "A.13", ControlStatus.MAPPED),
         ]),
        (FrameworkCode.GDPR, "GDPR", "EU 2016/679", "Data Protection Regulation", "J. Schmidt (DPO)",
         days_from_now(17), 82.0,
         [
             ("Access Control", "IAM · RBAC · MFA · SSO", "Art.5", ControlStatus.MAPPED),
             ("Encryption & Crypto", "AES-256 · TLS 1.3 · HSM · Key Mgmt", "Art.32", ControlStatus.PARTIAL),
             ("Incident Response", "Detection · Escalation · Recovery · SLA", "Art.33", ControlStatus.MAPPED),
             ("Audit Logging", "Immutable · Merkle · Retention · SIEM", "Art.30", ControlStatus.MAPPED),
             ("Data Residency", "Geo-fencing · Cross-border · Retention", "Art.44", ControlStatus.MAPPED),
             ("Vulnerability Mgmt", "CVE scanning · Patch SLA · Pen testing", "Art.32", ControlStatus.MAPPED),
             ("Tenant Isolation", "Network · Data · Compute · Namespace", "Art.25", ControlStatus.MAPPED),
         ]),
        (FrameworkCode.HIPAA, "HIPAA", "45 CFR §164", "Health Data Security", "healthsys-io BAA",
         None, 90.0,
         [
             ("Access Control", "IAM · RBAC · MFA · SSO", "§308", ControlStatus.MAPPED),
             ("Encryption & Crypto", "AES-256 · TLS 1.3 · HSM · Key Mgmt", "§312", ControlStatus.MAPPED),
             ("Incident Response", "Detection · Escalation · Recovery · SLA", "§308(a)", ControlStatus.MAPPED),
             ("Audit Logging", "Immutable · Merkle · Retention · SIEM", "§312(b)", ControlStatus.MAPPED),
             ("Data Residency", "Geo-fencing · Cross-border · Retention", "N/A", ControlStatus.NOT_APPLICABLE),
             ("Vulnerability Mgmt", "CVE scanning · Patch SLA · Pen testing", "§308", ControlStatus.GAP),
             ("Tenant Isolation", "Network · Data · Compute · Namespace", "§312(a)", ControlStatus.MAPPED),
         ]),
    ]

    framework_objs: dict[FrameworkCode, ComplianceFramework] = {}
    for code, name, subtitle, desc, auditor, cert_expiry, score, controls in frameworks_data:
        framework = ComplianceFramework(
            id=uuid.uuid4(), code=code, display_name=name, subtitle=subtitle,
            description=desc, auditor=auditor, certified=True,
            cert_expires_at=cert_expiry, score=score,
        )
        db.add(framework)
        await db.flush()
        framework_objs[code] = framework
        for domain, control_desc, control_code, control_status in controls:
            db.add(
                ControlMapping(
                    framework_id=framework.id, control_domain=domain,
                    control_description=control_desc, control_code=control_code,
                    status=control_status,
                )
            )

    violations = [
        (FrameworkCode.GDPR, ViolationSeverity.VIOLATION, "CC6.1 · A.10.1",
         "Art.32 — Encryption at rest not verified",
         "Tenant healthsys-io · PHI data store · AES-256 key rotation overdue by 47 days",
         hours_ago(0.24)),
        (FrameworkCode.SOC2, ViolationSeverity.VIOLATION, "CC7.2",
         "CC7.2 — Incident response SLA exceeded",
         "Tenant acme-corp · INC-2026-0847 · P1 SLA breach by 14 minutes", hours_ago(0.25)),
        (FrameworkCode.HIPAA, ViolationSeverity.REVIEW, "§164.312(a)",
         "§164.312(a) — Access control audit pending",
         "Tenant media-stream-x · Unique user ID assignment review due", days_from_now(5)),
    ]
    for code, severity, ref, title, desc, detected in violations:
        db.add(
            ComplianceViolation(
                id=uuid.uuid4(), framework_id=framework_objs[code].id, severity=severity,
                status=ViolationStatus.OPEN, control_reference=ref, title=title,
                description=desc, detected_at=detected,
            )
        )

    resolved = ComplianceViolation(
        id=uuid.uuid4(), framework_id=framework_objs[FrameworkCode.SOC2].id,
        severity=ViolationSeverity.VIOLATION, status=ViolationStatus.RESOLVED,
        control_reference="CC6.2", title="MFA enforcement gap",
        description="MFA enforcement gap — remediated via policy push · auto-verified",
        detected_at=hours_ago(3), resolved_at=hours_ago(1.8),
        resolution_note="Remediated via automated policy push",
    )
    db.add(resolved)

    schema_results = [
        ("/api/v4/events", "EventPayload v2.4", False, "Required property 'tenantId' missing",
         "acme-corp", "evt_9f3a2c"),
        ("/api/v4/ingest", "IngestBatch v1.8", False, "Type mismatch: expected integer, got string",
         "startup-alpha", "batch_7d1e"),
        ("/api/v4/query", "QueryFilter v3.1", False, "Pattern validation failed: UUID format",
         "retail-nexus", "req_2b8f"),
    ]
    for endpoint, schema_ref, passed, error, tenant_slug, ref_id in schema_results:
        db.add(
            SchemaValidationResult(
                endpoint_path=endpoint, schema_ref=schema_ref, passed=passed,
                error_message=error, tenant_slug=tenant_slug, reference_id=ref_id,
                validated_at=hours_ago(0.1),
            )
        )
    for _ in range(1244):
        db.add(
            SchemaValidationResult(
                endpoint_path="/api/v4/events", schema_ref="EventPayload v2.4", passed=True,
                error_message=None, tenant_slug=None, reference_id=None, validated_at=hours_ago(2),
            )
        )

    await db.commit()


# Fixed per-step wiggle (13 steps) so the seeded history looks organic without
# needing randomness; each series still lands exactly on the framework's score.
_SNAPSHOT_WIGGLE = [0.0, -0.4, 0.5, -0.3, 0.2, -0.5, 0.6, -0.2, 0.3, -0.4, 0.5, -0.1, 0.0]


async def seed_score_snapshots(db: AsyncSession) -> None:
    """Record ~30 days of compliance score history per framework, trending up
    to each framework's current score. Idempotent and non-destructive to other
    tables: it only clears and repopulates compliance_score_snapshots."""
    await db.execute(delete(ComplianceScoreSnapshot))
    frameworks = (await db.execute(select(ComplianceFramework))).scalars().all()
    now = datetime.now(timezone.utc)
    steps = len(_SNAPSHOT_WIGGLE)
    for framework in frameworks:
        end_score = framework.score
        start_score = round(end_score - 3.0, 1)
        for i in range(steps):
            frac = i / (steps - 1)
            score = round(
                min(100.0, max(60.0, start_score + (end_score - start_score) * frac + _SNAPSHOT_WIGGLE[i])),
                1,
            )
            captured = now - timedelta(days=30) + timedelta(days=frac * 30)
            db.add(
                ComplianceScoreSnapshot(
                    id=uuid.uuid4(),
                    framework_id=framework.id,
                    score=score,
                    captured_at=captured,
                )
            )
    await db.commit()


async def seed_config(db: AsyncSession) -> None:
    # (key, section, tier, value_type, value, allowed_values, sensitive, requires_restart, desc)
    parameters = [
        # ---- Critical · Engine Identity ----
        ("engine.id", "Engine Identity", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "01944f2c-7b3a-7000-8e4d-2f9a1b3c5d7e", None, False, True,
         "Immutable cluster identity generated at boot"),
        ("engine.name", "Engine Identity", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "nexus-primary-us-east-1", None, False, True, "Human-readable engine instance name"),
        ("engine.region", "Engine Identity", ConfigTier.CRITICAL, ConfigValueType.ENUM,
         "us-east-1", "us-east-1,us-west-2,eu-west-1,ap-southeast-1", False, True, "Deployment region"),
        ("engine.az", "Engine Identity", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "AZ-3", None, False, True, "Availability zone"),
        ("engine.cluster_role", "Engine Identity", ConfigTier.CRITICAL, ConfigValueType.ENUM,
         "PRIMARY", "PRIMARY,REPLICA,STANDBY", False, True, "Raft cluster role"),
        # ---- Critical · State Persistence (etcd) ----
        ("etcd.endpoints", "State Persistence", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "https://10.0.1.10:2379,https://10.0.1.11:2379,https://10.0.1.12:2379", None, False, True,
         "Comma-separated etcd endpoints"),
        ("etcd.tls_cert_path", "State Persistence", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "/etc/nexus/etcd/tls/cert.pem", None, False, True, "etcd client TLS certificate path"),
        ("etcd.tls_key_path", "State Persistence", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "/etc/nexus/etcd/tls/key.pem", None, False, True, "etcd client TLS key path"),
        ("etcd.dial_timeout", "State Persistence", ConfigTier.CRITICAL, ConfigValueType.DURATION,
         "5s", None, False, True, "etcd client dial timeout"),
        ("etcd.request_timeout", "State Persistence", ConfigTier.CRITICAL, ConfigValueType.DURATION,
         "10s", None, False, True, "etcd request timeout"),
        ("etcd.keepalive", "State Persistence", ConfigTier.CRITICAL, ConfigValueType.DURATION,
         "30s", None, False, True, "etcd keepalive interval"),
        ("etcd.compaction_interval", "State Persistence", ConfigTier.CRITICAL, ConfigValueType.DURATION,
         "1h", None, False, True, "etcd history compaction interval"),
        ("etcd.defrag_interval", "State Persistence", ConfigTier.CRITICAL, ConfigValueType.DURATION,
         "24h", None, False, True, "etcd defragmentation interval"),
        # ---- Critical · Audit Sink ----
        ("audit.sink_type", "Audit Sink", ConfigTier.CRITICAL, ConfigValueType.ENUM,
         "IMMUTABLE_APPEND", "IMMUTABLE_APPEND,S3_WORM,KAFKA_IMMUTABLE", False, True,
         "Audit log persistence backend"),
        ("audit.sink_endpoint", "Audit Sink", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "https://audit-sink.nexus.internal:9443/v2/ingest", None, False, True, "Audit sink ingest endpoint"),
        ("audit.merkle_tree_depth", "Audit Sink", ConfigTier.CRITICAL, ConfigValueType.INTEGER,
         "32", None, False, False, "Merkle tree depth for tamper evidence"),
        ("audit.signing_algo", "Audit Sink", ConfigTier.CRITICAL, ConfigValueType.ENUM,
         "ECDSA-P384", "ECDSA-P384,RSA-4096,Ed25519", False, True, "Audit entry signing algorithm"),
        ("audit.flush_interval", "Audit Sink", ConfigTier.CRITICAL, ConfigValueType.DURATION,
         "500ms", None, False, False, "Audit buffer flush interval"),
        ("audit.batch_size", "Audit Sink", ConfigTier.CRITICAL, ConfigValueType.INTEGER,
         "1000", None, False, False, "Audit write batch size"),
        # ---- Critical · Auth Strategy (OIDC) ----
        ("auth.strategy", "Auth Strategy", ConfigTier.CRITICAL, ConfigValueType.ENUM,
         "OIDC", "OIDC,SAML2,mTLS,API_KEY", False, True, "Primary authentication strategy"),
        ("oidc.issuer_url", "Auth Strategy", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "https://auth.nexus.internal/realms/nexus-engine", None, False, True, "OIDC issuer URL"),
        ("oidc.client_id", "Auth Strategy", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "nexus-engine-v4", None, False, True, "OIDC client identifier"),
        ("oidc.client_secret", "Auth Strategy", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "s3cr3t-value-not-real", None, True, True, "OIDC client secret"),
        ("oidc.jwks_refresh_interval", "Auth Strategy", ConfigTier.CRITICAL, ConfigValueType.DURATION,
         "5m", None, False, False, "JWKS key-set refresh interval"),
        ("oidc.token_cache_ttl", "Auth Strategy", ConfigTier.CRITICAL, ConfigValueType.DURATION,
         "15m", None, False, False, "Validated-token cache TTL"),
        ("oidc.scopes", "Auth Strategy", ConfigTier.CRITICAL, ConfigValueType.STRING,
         "openid profile email nexus:admin nexus:read nexus:write", None, False, False, "Requested OIDC scopes"),
        # ---- Necessary · Crypto HSM (PKCS#11) ----
        ("pkcs11.library_path", "Crypto HSM", ConfigTier.NECESSARY, ConfigValueType.STRING,
         "/usr/lib/softhsm/libsofthsm2.so", None, False, False, "PKCS#11 library path"),
        ("pkcs11.slot_id", "Crypto HSM", ConfigTier.NECESSARY, ConfigValueType.INTEGER,
         "0", None, False, False, "PKCS#11 slot identifier"),
        ("pkcs11.pin", "Crypto HSM", ConfigTier.NECESSARY, ConfigValueType.STRING,
         "1234-not-real", None, True, False, "PKCS#11 slot PIN"),
        ("hsm.master_key_label", "Crypto HSM", ConfigTier.NECESSARY, ConfigValueType.STRING,
         "nexus-master-key-v4", None, False, False, "HSM master key label"),
        ("hsm.signing_key_label", "Crypto HSM", ConfigTier.NECESSARY, ConfigValueType.STRING,
         "nexus-signing-key-v4", None, False, False, "HSM signing key label"),
        ("hsm.supported_algorithms", "Crypto HSM", ConfigTier.NECESSARY, ConfigValueType.STRING,
         "AES-256-GCM,RSA-4096,ECDSA-P384,Ed25519", None, False, False, "HSM supported algorithms"),
        # ---- Necessary · Rate Limiting ----
        ("ratelimit.algorithm", "Rate Limiting", ConfigTier.NECESSARY, ConfigValueType.ENUM,
         "TOKEN_BUCKET", "TOKEN_BUCKET,SLIDING_WINDOW,LEAKY_BUCKET", False, False,
         "Rate limiting algorithm"),
        ("ratelimit.global_req_per_sec", "Rate Limiting", ConfigTier.NECESSARY, ConfigValueType.INTEGER,
         "1000", None, False, False, "Global requests per second"),
        ("ratelimit.global_burst_size", "Rate Limiting", ConfigTier.NECESSARY, ConfigValueType.INTEGER,
         "2000", None, False, False, "Global burst allowance"),
        ("ratelimit.throttle_action", "Rate Limiting", ConfigTier.NECESSARY, ConfigValueType.ENUM,
         "QUEUE_WITH_BACKPRESSURE", "QUEUE_WITH_BACKPRESSURE,REJECT_429,DROP", False, False,
         "Action taken when throttled"),
        ("ratelimit.retry_after_header", "Rate Limiting", ConfigTier.NECESSARY, ConfigValueType.DURATION,
         "1s", None, False, False, "Retry-After header value"),
        # ---- Necessary · Tenancy Isolation ----
        ("tenancy.isolation_model", "Tenancy Isolation", ConfigTier.NECESSARY, ConfigValueType.ENUM,
         "NAMESPACE", "NAMESPACE,PROCESS,VM", False, False, "Default tenant isolation model"),
        ("tenancy.network_isolation", "Tenancy Isolation", ConfigTier.NECESSARY, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Per-tenant VPC / eBPF network policies"),
        ("tenancy.data_isolation", "Tenancy Isolation", ConfigTier.NECESSARY, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Separate encryption keys per tenant"),
        ("tenancy.compute_isolation", "Tenancy Isolation", ConfigTier.NECESSARY, ConfigValueType.BOOLEAN,
         "true", None, False, False, "CPU/memory cgroup limits per tenant"),
        ("tenancy.audit_isolation", "Tenancy Isolation", ConfigTier.NECESSARY, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Separate audit streams per tenant"),
        ("tenancy.namespace_prefix", "Tenancy Isolation", ConfigTier.NECESSARY, ConfigValueType.STRING,
         "nexus-tenant-", None, False, False, "Tenant namespace prefix"),
        ("tenancy.max_tenants", "Tenancy Isolation", ConfigTier.NECESSARY, ConfigValueType.INTEGER,
         "100", None, False, False, "Maximum tenants per engine"),
        # ---- Necessary · Backup Intervals ----
        ("backup.interval", "Backup Intervals", ConfigTier.NECESSARY, ConfigValueType.DURATION,
         "6h", None, False, False, "Full snapshot cadence"),
        ("backup.destination", "Backup Intervals", ConfigTier.NECESSARY, ConfigValueType.STRING,
         "s3://nexus-backups-us-east-1/engine/snapshots/", None, False, False, "Backup destination URI"),
        ("backup.retention_count", "Backup Intervals", ConfigTier.NECESSARY, ConfigValueType.INTEGER,
         "30", None, False, False, "Number of snapshots retained"),
        ("backup.encryption", "Backup Intervals", ConfigTier.NECESSARY, ConfigValueType.ENUM,
         "AES-256-GCM", "AES-256-GCM,AES-128-GCM,ChaCha20-Poly1305", False, False, "Backup encryption algorithm"),
        ("backup.full_snapshot", "Backup Intervals", ConfigTier.NECESSARY, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Full snapshot enabled (etcd + config + state)"),
        ("backup.incremental_wal", "Backup Intervals", ConfigTier.NECESSARY, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Continuous incremental WAL to S3"),
        # ---- Optional · Redis Cache ----
        ("redis.endpoints", "Redis Cache", ConfigTier.OPTIONAL, ConfigValueType.STRING,
         "redis://redis-cluster.nexus.internal:6379", None, False, False, "Redis cluster endpoint"),
        ("redis.mode", "Redis Cache", ConfigTier.OPTIONAL, ConfigValueType.ENUM,
         "CLUSTER", "CLUSTER,SENTINEL,STANDALONE", False, False, "Redis deployment mode"),
        ("redis.default_ttl", "Redis Cache", ConfigTier.OPTIONAL, ConfigValueType.DURATION,
         "15m", None, False, False, "Default cache TTL"),
        ("redis.max_memory", "Redis Cache", ConfigTier.OPTIONAL, ConfigValueType.STRING,
         "8GB", None, False, False, "Maximum cache memory"),
        ("redis.token_cache", "Redis Cache", ConfigTier.OPTIONAL, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Cache validated tokens"),
        ("redis.schema_cache", "Redis Cache", ConfigTier.OPTIONAL, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Cache tenant schemas"),
        ("redis.rate_limit_counters", "Redis Cache", ConfigTier.OPTIONAL, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Store rate-limit counters in Redis"),
        ("redis.query_result_cache", "Redis Cache", ConfigTier.OPTIONAL, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Cache query results (L2)"),
        # ---- Optional · Geo-Redundancy ----
        ("geo.replication_mode", "Geo-Redundancy", ConfigTier.OPTIONAL, ConfigValueType.ENUM,
         "ACTIVE-PASSIVE", "ACTIVE-PASSIVE,ACTIVE-ACTIVE", False, False, "Cross-region replication mode"),
        ("geo.active_regions", "Geo-Redundancy", ConfigTier.OPTIONAL, ConfigValueType.STRING,
         "us-east-1,us-west-2,eu-west-1", None, False, False, "Active replication regions"),
        # ---- Optional · Data Retention ----
        ("retention.policy_mode", "Data Retention", ConfigTier.OPTIONAL, ConfigValueType.ENUM,
         "TIME_BASED", "TIME_BASED,SIZE_BASED,HYBRID", False, False, "Retention policy mode"),
        ("retention.audit_logs", "Data Retention", ConfigTier.OPTIONAL, ConfigValueType.DURATION,
         "5y", None, False, False, "Audit log retention period"),
        ("retention.event_streams", "Data Retention", ConfigTier.OPTIONAL, ConfigValueType.DURATION,
         "90d", None, False, False, "Event stream retention period"),
        ("retention.metrics", "Data Retention", ConfigTier.OPTIONAL, ConfigValueType.DURATION,
         "30d", None, False, False, "Metrics / telemetry retention period"),
        ("retention.anomaly_snapshots", "Data Retention", ConfigTier.OPTIONAL, ConfigValueType.DURATION,
         "180d", None, False, False, "Anomaly snapshot retention period"),
        ("retention.debug_logs", "Data Retention", ConfigTier.OPTIONAL, ConfigValueType.DURATION,
         "14d", None, False, False, "Debug/temp log retention period"),
        ("retention.purge_strategy", "Data Retention", ConfigTier.OPTIONAL, ConfigValueType.ENUM,
         "SOFT_DELETE_THEN_PURGE", "SOFT_DELETE_THEN_PURGE,HARD_DELETE,ARCHIVE_THEN_PURGE", False, False,
         "Data purge strategy"),
        ("retention.gdpr_erasure", "Data Retention", ConfigTier.OPTIONAL, ConfigValueType.BOOLEAN,
         "true", None, False, False, "Automated erasure on tenant request"),
    ]
    param_objs: dict[str, ConfigParameter] = {}
    for key, section, tier, value_type, value, allowed, sensitive, restart, desc in parameters:
        param = ConfigParameter(
            id=uuid.uuid4(), key=key, section=section, tier=tier, value_type=value_type,
            active_value=value, allowed_values=allowed, is_sensitive=sensitive,
            requires_restart=restart, description=desc,
        )
        db.add(param)
        param_objs[key] = param
    await db.flush()

    # Two staged-but-not-applied changes, matching the "pending changes" diff view.
    param_objs["retention.audit_logs"].pending_value = "7y"
    db.add(
        ConfigChange(
            parameter_id=param_objs["retention.audit_logs"].id, previous_value="5y",
            new_value="7y", reason="Compliance requirement update · GDPR Art.30",
            changed_by="admin@nexus", status=ConfigChangeStatus.PENDING,
        )
    )
    param_objs["retention.debug_logs"].pending_value = "7d"
    db.add(
        ConfigChange(
            parameter_id=param_objs["retention.debug_logs"].id, previous_value="14d",
            new_value="7d", reason="Cost optimization · reduce storage by ~40%",
            changed_by="admin@nexus", status=ConfigChangeStatus.PENDING,
        )
    )
    param_objs["redis.query_result_cache"].pending_value = "false"
    db.add(
        ConfigChange(
            parameter_id=param_objs["redis.query_result_cache"].id, previous_value="true",
            new_value="false", reason="Stale data risk · pending cache invalidation fix",
            changed_by="admin@nexus", status=ConfigChangeStatus.PENDING,
        )
    )

    await db.commit()


async def seed_configurations(db: AsyncSession) -> None:
    """Seed a few versioned configuration documents with a realistic lifecycle
    (archived history + one active version per name, plus a draft)."""
    from app.services.config_service import _checksum  # single source of truth

    # (name, version, status, payload, sensitive_keys, description, activated_at, archived_at)
    rows = [
        ("engine-runtime", 1, ConfigurationStatus.ARCHIVED,
         {"worker_pool_size": 8, "max_connections": 500, "request_timeout_s": 30, "log_level": "info"},
         [], "Initial runtime configuration", days_ago(60), days_ago(30)),
        ("engine-runtime", 2, ConfigurationStatus.ARCHIVED,
         {"worker_pool_size": 16, "max_connections": 1000, "request_timeout_s": 30, "log_level": "info"},
         [], "Tuned worker pool for higher throughput", days_ago(30), days_ago(5)),
        ("engine-runtime", 3, ConfigurationStatus.ACTIVE,
         {"worker_pool_size": 16, "max_connections": 2000, "request_timeout_s": 20,
          "log_level": "warn", "gc_target_ms": 2},
         [], "Current production runtime configuration", days_ago(5), None),
        ("rate-limit-policy", 1, ConfigurationStatus.ARCHIVED,
         {"algorithm": "token_bucket", "rps": 1000, "burst": 200},
         [], "Initial rate-limit policy", days_ago(40), days_ago(12)),
        ("rate-limit-policy", 2, ConfigurationStatus.ACTIVE,
         {"algorithm": "sliding_window", "rps": 2000, "burst": 400},
         [], "Sliding-window policy with higher ceiling", days_ago(12), None),
        ("oidc-integration", 1, ConfigurationStatus.DRAFT,
         {"provider": "keycloak", "client_id": "nexus-engine",
          "client_secret": "s3cr3t-value-not-real", "scopes": "openid profile nexus:read"},
         ["client_secret"], "Draft OIDC integration wiring", None, None),
        ("geo-replication", 1, ConfigurationStatus.ACTIVE,
         {"mode": "active-passive", "primary_region": "us-east-1",
          "replica_regions": ["us-west-2", "eu-west-1"], "rpo_seconds": 60},
         [], "Cross-region replication policy", days_ago(20), None),
    ]
    for name, version, status_val, payload, sensitive, description, activated, archived in rows:
        db.add(
            Configuration(
                id=uuid.uuid4(),
                name=name,
                version=version,
                status=status_val,
                payload=payload,
                sensitive_keys=sensitive,
                checksum=_checksum(payload),
                description=description,
                created_by="admin@nexus",
                activated_at=activated,
                archived_at=archived,
            )
        )
    await db.commit()


async def seed_hsm(db: AsyncSession) -> None:
    slots_data = [
        (0, "nexus-primary", SlotPurpose.PRIMARY, 487, 1250, 1247.0, "RNG,WRITE,LOGIN"),
        (1, "nexus-signing", SlotPurpose.SIGNING, 124, 1250, 892.0, "RNG,WRITE,LOGIN"),
        (2, "nexus-tenant-dek", SlotPurpose.TENANT_DEK, 1087, 1250, 708.0, "RNG,WRITE,LOGIN"),
        (3, "nexus-dr-backup", SlotPurpose.STANDBY, 0, 1250, 0.0, "STANDBY"),
    ]
    slots: dict[int, HsmSlot] = {}
    for number, label, purpose, count, capacity, ops, flags in slots_data:
        slot = HsmSlot(
            id=uuid.uuid4(), slot_number=number, label=label, purpose=purpose,
            is_active=purpose != SlotPurpose.STANDBY, object_count=count,
            capacity_max_objects=capacity, ops_per_second=ops, token_flags=flags,
        )
        db.add(slot)
        slots[number] = slot
    await db.flush()

    master_v5 = MasterKey(
        id=uuid.uuid4(), key_label="nexus-master-v5", slot_id=slots[0].id,
        hsm_object_id="0x0005", algorithm="AES-256", status=MasterKeyStatus.ACTIVE,
        rotation_policy_days=180, activated_at=NOW, expires_at=days_from_now(180),
        wraps_dek_count=1247, throughput_ops=1247.0,
    )
    signing_v4 = MasterKey(
        id=uuid.uuid4(), key_label="nexus-signing-v4", slot_id=slots[1].id,
        hsm_object_id="0x0014", algorithm="ECDSA-P384", status=MasterKeyStatus.EXPIRING,
        rotation_policy_days=365, activated_at=days_ago(184), expires_at=days_from_now(14),
        wraps_dek_count=0, throughput_ops=892.0,
    )
    tenant_dek_root = MasterKey(
        id=uuid.uuid4(), key_label="tenant-dek-root-v3", slot_id=slots[2].id,
        hsm_object_id="0x0023", algorithm="AES-256-GCM", status=MasterKeyStatus.ACTIVE,
        rotation_policy_days=180, activated_at=days_ago(104), expires_at=days_from_now(76),
        wraps_dek_count=24, throughput_ops=708.0,
    )
    master_v4 = MasterKey(
        id=uuid.uuid4(), key_label="nexus-master-v4", slot_id=slots[0].id,
        hsm_object_id="0x0004", algorithm="AES-256", status=MasterKeyStatus.RETIRED,
        rotation_policy_days=180, activated_at=days_ago(184), expires_at=NOW,
        retired_at=hours_ago(0.2), wraps_dek_count=1247, throughput_ops=0.0,
    )
    signing_v5 = MasterKey(
        id=uuid.uuid4(), key_label="nexus-signing-v5", slot_id=slots[1].id,
        hsm_object_id=None, algorithm="ECDSA-P384", status=MasterKeyStatus.PENDING,
        rotation_policy_days=365, activated_at=None, expires_at=None,
        wraps_dek_count=0, throughput_ops=0.0,
    )
    for key in (master_v5, signing_v4, tenant_dek_root, master_v4, signing_v5):
        db.add(key)
    await db.flush()

    master_v4.superseded_by_id = master_v5.id

    completed_ceremony = KeyCeremony(
        id=uuid.uuid4(), ceremony_ref="cer-20260703-001", master_key_id=master_v5.id,
        predecessor_label="nexus-master-v4", required_approvals=5,
        status=CeremonyStatus.COMPLETE, completed_at=hours_ago(0.2),
    )
    db.add(completed_ceremony)
    await db.flush()
    for custodian, minutes_before in [
        ("admin@nexus", 17), ("security@nexus", 15), ("cto@nexus", 13),
        ("compliance@nexus", 8), ("auditor@external", 2),
    ]:
        db.add(
            KeyCustodianApproval(
                ceremony_id=completed_ceremony.id, custodian_email=custodian,
                approved_at=hours_ago(minutes_before / 60),
            )
        )

    pending_ceremony = KeyCeremony(
        id=uuid.uuid4(), ceremony_ref="cer-20260717-001", master_key_id=signing_v5.id,
        predecessor_label="nexus-signing-v4", required_approvals=5,
        status=CeremonyStatus.PENDING, scheduled_at=days_from_now(14),
    )
    db.add(pending_ceremony)
    await db.flush()
    for custodian, approved in [
        ("admin@nexus", True), ("security@nexus", True), ("cto@nexus", True),
        ("compliance@nexus", False), ("auditor@external", False),
    ]:
        db.add(
            KeyCustodianApproval(
                ceremony_id=pending_ceremony.id, custodian_email=custodian,
                approved_at=hours_ago(0.3) if approved else None,
            )
        )

    certificates = [
        ("nexus-engine.internal", CertificateType.TLS_SERVER, "RSA-4096", "SHA-384",
         days_ago(365 * 2), days_from_now(365)),
        ("nexus-signing.internal", CertificateType.CODE_SIGN, "ECDSA-P384", "SHA-384",
         days_ago(365 * 2 - 17), days_from_now(17)),
        ("keycloak-oidc.internal", CertificateType.OIDC_JWT, "RSA-2048", "SHA-256",
         days_ago(365 * 2 - 10), days_from_now(24)),
        ("etcd-cluster.internal", CertificateType.MUTUAL_TLS, "ECDSA-P256", "SHA-256",
         days_ago(365), days_from_now(137)),
        ("nexus-ca-root", CertificateType.ROOT_CA, "RSA-4096", "SHA-512",
         days_ago(365 * 6), days_from_now(1812)),
        ("hsm-attestation.internal", CertificateType.ATTESTATION, "ECDSA-P384", "SHA-384",
         days_ago(365 * 2), days_from_now(712)),
    ]
    for cn, cert_type, key_algo, sig_algo, issued, expires in certificates:
        db.add(
            Certificate(
                id=uuid.uuid4(), common_name=cn, cert_type=cert_type, key_algorithm=key_algo,
                signature_algorithm=sig_algo, issued_at=issued, expires_at=expires, auto_renew=True,
            )
        )

    algorithms = [
        ("AES-256-GCM", "PRIMARY", True, False, 1847.0,
         {"key_size": "256-bit", "tag_size": "128-bit", "usage": "Data encryption"}),
        ("ECDSA-P384", "SIGNING", True, False, 892.0,
         {"curve": "P-384 (secp384r1)", "hash": "SHA-384", "usage": "Audit log signing"}),
        ("RSA-4096-OAEP", "KEY WRAP", True, False, 108.0,
         {"key_size": "4096-bit", "padding": "OAEP-SHA256", "usage": "DEK transport"}),
        ("SHA-384 / SHA-512", "HASHING", True, False, 4_721_000.0,
         {"digest_size": "384 / 512-bit", "standard": "FIPS 180-4", "usage": "Chain integrity"}),
        ("AES-128-CBC", "DEPRECATED", False, True, 0.0,
         {"note": "Disabled 2026-01-01 · NIST SP 800-131A Rev.2 · 0 active uses"}),
    ]
    for name, purpose, active, deprecated, ops, detail in algorithms:
        db.add(
            CryptoAlgorithm(
                id=uuid.uuid4(), name=name, purpose_label=purpose, is_active=active,
                is_deprecated=deprecated, deprecated_at=days_ago(180) if deprecated else None,
                ops_per_second=ops, detail_json=detail,
            )
        )

    checks_template = [
        {"key": "fips_mode", "label": "FIPS Mode", "passed": True, "detail": "FIPS 140-3 Level 3"},
        {"key": "tamper_seal", "label": "Tamper Seal", "passed": True, "detail": "seal intact"},
        {"key": "firmware_hash", "label": "Firmware Hash", "passed": True, "detail": "sha256 verified"},
        {"key": "rng_quality", "label": "RNG Quality", "passed": True, "detail": "entropy 7.99 bits"},
        {"key": "key_zeroize", "label": "Key Zeroize", "passed": True, "detail": "zeroization test passed"},
        {"key": "self_test", "label": "Self-Test", "passed": True, "detail": "12/12 KATs passed"},
        {"key": "attest_chain", "label": "Attest Chain", "passed": True, "detail": "3-cert chain valid"},
    ]
    for i in range(7):
        db.add(AttestationRun(ran_at=hours_ago(i * 6), checks=checks_template, all_passed=True))

    await db.commit()


async def seed_security(db: AsyncSession) -> None:
    """Seed configured crypto providers and key-operation history.

    Runs after ``seed_hsm`` so operation rows can be linked back to the master
    keys they reference (by label). Providers hold non-secret hardware metadata
    only — no key material.
    """
    providers = [
        dict(
            name="nexus-luna-primary",
            provider_type=SecurityProviderType.PKCS11,
            model="Thales Luna 7",
            manufacturer="Thales Group",
            library_path="/usr/lib/libCryptoki2_64.so",
            firmware_version="7.4.2-build.47",
            serial_number="TL7-US-E1-0042",
            fips_level="FIPS 140-3 Level 3",
            is_active=True,
            pool_active=8,
            pool_max=10,
            connection_timeout_seconds=5,
            avg_latency_ms=0.4,
            session_count=8,
            rw_session_count=3,
            error_count_24h=0,
            supported_mechanisms=[
                "CKM_AES_GCM", "CKM_RSA_PKCS", "CKM_ECDSA", "CKM_SHA256_HMAC",
                "CKM_ECDH1_DERIVE", "CKM_AES_KEY_WRAP", "CKM_RSA_OAEP", "CKM_SHA384",
            ],
            last_health_check_at=hours_ago(0.05),
        ),
        dict(
            name="nexus-luna-dr",
            provider_type=SecurityProviderType.PKCS11,
            model="Thales Luna 7",
            manufacturer="Thales Group",
            library_path="/usr/lib/libCryptoki2_64.so",
            firmware_version="7.4.2-build.47",
            serial_number="TL7-US-W2-0043",
            fips_level="FIPS 140-3 Level 3",
            is_active=True,
            pool_active=0,
            pool_max=4,
            connection_timeout_seconds=5,
            avg_latency_ms=0.6,
            session_count=0,
            rw_session_count=0,
            error_count_24h=0,
            supported_mechanisms=[
                "CKM_AES_GCM", "CKM_RSA_PKCS", "CKM_ECDSA", "CKM_SHA256_HMAC",
            ],
            last_health_check_at=hours_ago(0.1),
        ),
    ]
    for provider in providers:
        db.add(SecurityProvider(id=uuid.uuid4(), **provider))

    keys = {
        k.key_label: k
        for k in (await db.execute(select(MasterKey))).scalars().all()
    }

    operations = [
        (SecurityOperationType.KEY_ROTATE, "nexus-master-v5", "engine-core",
         "Rotated nexus-master-v4 -> nexus-master-v5 via provider abstraction · 1,247 DEKs re-wrapped",
         hours_ago(0.2)),
        (SecurityOperationType.CEREMONY_COMPLETE, "nexus-master-v5", "engine-core",
         "Key ceremony cer-20260703-001 completed · 5-of-5 custodian quorum", hours_ago(0.2)),
        (SecurityOperationType.KEY_CREATE, "nexus-signing-v5", "admin@nexus",
         "Registered key reference nexus-signing-v5 (ECDSA-P384) — pending ceremony", days_ago(1)),
        (SecurityOperationType.ATTESTATION_RUN, None, "scheduler",
         "Hardware attestation sweep passed · 7/7 checks", hours_ago(6)),
        (SecurityOperationType.KEY_ROTATE, "tenant-dek-root-v3", "engine-core",
         "Rotated tenant-dek-root-v2 -> tenant-dek-root-v3 · 24 tenant DEKs re-wrapped", days_ago(104)),
        (SecurityOperationType.KEY_DISABLE, "aes128-legacy-signing", "security@nexus",
         "Disabled legacy key aes128-legacy-signing · NIST SP 800-131A Rev.2", days_ago(180)),
    ]
    for op_type, label, actor, detail, occurred in operations:
        referenced = keys.get(label) if label else None
        db.add(
            SecurityOperation(
                id=uuid.uuid4(),
                operation_type=op_type,
                master_key_id=referenced.id if referenced else None,
                key_label=label,
                actor=actor,
                status=SecurityOperationStatus.SUCCESS,
                detail=detail,
                occurred_at=occurred,
            )
        )

    await db.commit()


async def seed_tenancy_extras(db: AsyncSession, tenants: dict[str, Tenant]) -> None:
    db.add(
        BreachAlert(
            id=uuid.uuid4(), severity=BreachSeverity.CRITICAL,
            title="Unauthorized cross-tenant data read attempt blocked",
            description="Unauthorized cross-tenant data read attempt blocked",
            source_tenant_id=tenants["media-stream-x"].id, target_tenant_id=tenants["acme-corp"].id,
            resource="events.acme_corp.raw", principal="svc-media-etl@media-stream-x",
            action_taken="BLOCKED · RLS enforced", detected_at=hours_ago(0.02),
        )
    )
    db.add(
        BreachAlert(
            id=uuid.uuid4(), severity=BreachSeverity.WARNING,
            title="Shared network namespace detected between tenants",
            description="Shared network namespace detected between tenants",
            source_tenant_id=tenants["healthsys-io"].id, target_tenant_id=tenants["retail-nexus"].id,
            resource="subnet-10.0.4.0/24", principal=None,
            action_taken="MEDIUM risk · network segmentation review", detected_at=hours_ago(0.07),
        )
    )
    db.add(
        BreachAlert(
            id=uuid.uuid4(), severity=BreachSeverity.WARNING,
            title="Encryption key referenced outside tenant boundary",
            description="Encryption key referenced outside tenant boundary",
            source_tenant_id=tenants["media-stream-x"].id, target_tenant_id=tenants["govcloud-fed"].id,
            resource="dek-media-0x0047", principal=None,
            action_taken="Scope violation flagged", detected_at=hours_ago(0.21),
        )
    )

    job = TenantProvisioningJob(
        id=uuid.uuid4(), tenant_id=tenants["fintech-labs-2"].id,
        status=ProvisioningJobStatus.RUNNING,
        completed_steps=["org_namespace_created", "network_policy_applied"],
        current_step="schema_migration", eta_seconds=240,
    )
    db.add(job)

    schema_validations = [
        ("acme-corp", "schema_acme_corp", "v2.14.1", 47, "VALID", "0 errors", hours_ago(0.03)),
        ("govcloud-fed", "schema_govcloud_fed", "v3.2.0", 63, "VALID", "0 errors", hours_ago(0.06)),
        ("media-stream-x", "schema_media_x", "v1.9.3", 29, "FAILED", "3 constraint violations", hours_ago(0.11)),
        ("fintech-labs-2", "schema_fintech_2", "v1.0.0", None, "MIGRATING", "47% complete", hours_ago(0.15)),
        ("healthsys-io", "schema_healthsys_io", "v2.7.1", 38, "WARN", "1 deprecated column", hours_ago(0.2)),
        ("fintech-labs", "schema_fintech_labs", "v4.1.0", 52, "VALID", "0 errors", hours_ago(0.28)),
        ("retail-nexus", "schema_retail_nexus", "v2.3.5", 41, "VALID", "0 errors", hours_ago(0.37)),
    ]
    for slug, schema_name, version, tables, status_val, detail, validated in schema_validations:
        db.add(
            TenantSchemaValidation(
                tenant_id=tenants[slug].id, schema_name=schema_name, schema_version=version,
                table_count=tables, status=status_val, detail=detail, validated_at=validated,
            )
        )

    snapshots = [
        ("acme-corp", SnapshotStatus.CURRENT, 4_700_000_000, hours_ago(0.53), 30, 12, None),
        ("govcloud-fed", SnapshotStatus.CURRENT, 8_200_000_000, hours_ago(0.53), 90, 24, None),
        ("media-stream-x", SnapshotStatus.STALE, 2_100_000_000, days_ago(1.083), 30, 8, "Schema migration"),
        ("fintech-labs", SnapshotStatus.CURRENT, 6_300_000_000, hours_ago(0.53), 30, 18, None),
        ("fintech-labs-2", SnapshotStatus.PENDING, None, None, 30, 0,
         "Initial snapshot scheduled after provisioning completes"),
    ]
    for slug, status_val, size, taken, retention, retained, reason in snapshots:
        db.add(
            TenantBackupSnapshot(
                tenant_id=tenants[slug].id, status=status_val, size_bytes=size, taken_at=taken,
                retention_days=retention, retained_count=retained, stale_reason=reason,
            )
        )

    await db.commit()


async def seed_audit_log(db: AsyncSession) -> None:
    entries = [
        ("critical", "state_change", "PRIV_ESCALATION", "svc-deploy-01",
         "Privilege escalation: svc-deploy-01 assumed IAM::AdminRole without MFA challenge.",
         "acme-corp", "10.0.4.22"),
        ("warning", "state_change", "LATENCY_BREACH", "engine-core",
         "etcd write latency p99 exceeded 15ms threshold — node etcd-1 degraded", None, None),
        ("info", "auth_event", "TOKEN_ISSUED", "keycloak-22",
         "OIDC token issued for user analyst@fintech-labs.com — scope: nexus:read",
         "fintech-labs", "172.16.4.8"),
        ("info", "config_change", "RETENTION_MOD", "admin@nexus",
         "Audit log retention policy updated: 5y -> 7y (GDPR Art.30 compliance)", None, "10.0.1.5"),
        ("info", "tenant_lifecycle", "TENANT_CREATED", "tenant-provisioner",
         "New tenant provisioned — namespace isolated, encryption keys generated, audit stream initialized",
         "fintech-labs", None),
        ("info", "key_operation", "KEY_ROTATION", "engine-core",
         "HSM master key rotation completed — nexus-master-key-v4 -> v5, 1,247 DEKs re-wrapped", None, None),
    ]
    for severity, event_type, subtype, actor, desc, tenant_slug, source_ip in entries:
        await append_entry(
            db,
            AuditLogEntryCreate(
                severity=severity, event_type=event_type, event_subtype=subtype, actor=actor,
                description=desc, tenant_slug=tenant_slug, source_ip=source_ip, metadata_json={},
            ),
        )


async def seed_rbac(db: AsyncSession, admin: User) -> None:
    """Seed the RBAC catalogue: permissions, roles, a handful of demo users, and
    their role assignments. Demo (non-admin) users are re-created each run so the
    admin account and its credentials are never disturbed."""
    # Remove prior demo users (everything but the primary admin). Their
    # user_roles rows are already cleared by the wipe step.
    await db.execute(delete(User).where(User.email != admin.email))
    await db.flush()

    # (name, resource, action, description)
    permission_defs = [
        ("dashboard:read", "dashboard", "read", "View the command-center dashboard"),
        ("tenants:read", "tenants", "read", "View tenants"),
        ("tenants:create", "tenants", "create", "Provision tenants"),
        ("tenants:update", "tenants", "update", "Modify tenants"),
        ("tenants:delete", "tenants", "delete", "Deactivate or remove tenants"),
        ("config:read", "config", "read", "View configuration"),
        ("config:update", "config", "update", "Stage configuration changes"),
        ("config:apply", "config", "apply", "Apply pending configuration changes"),
        ("audit:read", "audit", "read", "View the audit log"),
        ("audit:export", "audit", "export", "Export audit metadata"),
        ("audit:verify", "audit", "verify", "Verify the audit hash chain"),
        ("anomalies:read", "anomalies", "read", "View anomaly detections"),
        ("anomalies:manage", "anomalies", "manage", "Acknowledge / resolve anomalies"),
        ("compliance:read", "compliance", "read", "View compliance posture"),
        ("compliance:assess", "compliance", "assess", "Run compliance assessments"),
        ("security:read", "security", "read", "View HSM / security state"),
        ("security:rotate_key", "security", "rotate_key", "Rotate cryptographic keys"),
        ("rbac:read", "rbac", "read", "View users, roles and permissions"),
        ("rbac:manage", "rbac", "manage", "Manage users, roles and grants"),
        ("notifications:read", "notifications", "read", "View notifications"),
        ("alerts:manage", "alerts", "manage", "Manage alert rules"),
        ("operations:read", "operations", "read", "View operational observability"),
    ]
    permissions: dict[str, Permission] = {}
    for name, resource, action, description in permission_defs:
        perm = Permission(
            id=uuid.uuid4(), name=name, resource=resource, action=action, description=description
        )
        db.add(perm)
        permissions[name] = perm
    await db.flush()

    all_perm_names = [name for name, *_ in permission_defs]
    read_only_names = [n for n in all_perm_names if n.endswith(":read")]

    # (name, description, is_active, permission_names)
    role_defs = [
        ("Platform Admin", "Full administrative access to every module", True, all_perm_names),
        (
            "Security Officer",
            "HSM, key lifecycle, anomaly response and audit verification",
            True,
            [
                "dashboard:read", "security:read", "security:rotate_key", "audit:read",
                "audit:verify", "anomalies:read", "anomalies:manage", "operations:read",
            ],
        ),
        (
            "Compliance Auditor",
            "Compliance posture, assessments and audit export",
            True,
            [
                "dashboard:read", "compliance:read", "compliance:assess", "audit:read",
                "audit:export", "notifications:read",
            ],
        ),
        (
            "Tenant Operator",
            "Tenant provisioning and configuration read access",
            True,
            [
                "dashboard:read", "tenants:read", "tenants:create", "tenants:update",
                "tenants:delete", "config:read", "notifications:read",
            ],
        ),
        ("Read-Only Analyst", "View-only access across all modules", True, read_only_names),
        (
            "Legacy Integrator",
            "Deprecated service-integration role — retained for history",
            False,
            ["dashboard:read", "config:read"],
        ),
    ]
    roles: dict[str, Role] = {}
    for name, description, is_active, perm_names in role_defs:
        role = Role(id=uuid.uuid4(), name=name, description=description, is_active=is_active)
        db.add(role)
        await db.flush()
        roles[name] = role
        for perm_name in perm_names:
            db.add(RolePermission(role_id=role.id, permission_id=permissions[perm_name].id))

    # Demo users, one per operational role (admin keeps Platform Admin).
    demo_users = [
        ("sofia.security@nexus", "Sofia Okafor", True, False, "Security Officer"),
        ("carl.compliance@nexus", "Carl Devi", True, False, "Compliance Auditor"),
        ("tara.tenant@nexus", "Tara Nilsson", True, False, "Tenant Operator"),
        ("ravi.analyst@nexus", "Ravi Menon", True, False, "Read-Only Analyst"),
        ("leo.legacy@nexus", "Leo Prakash", False, False, "Legacy Integrator"),
    ]
    for email, display_name, is_active, is_admin, role_name in demo_users:
        user = User(
            id=uuid.uuid4(),
            email=email,
            display_name=display_name,
            hashed_password=hash_password("NexusDemo!2026"),
            is_active=is_active,
            is_admin=is_admin,
        )
        db.add(user)
        await db.flush()
        db.add(UserRole(user_id=user.id, role_id=roles[role_name].id, assigned_by=admin.email))

    # The primary admin is a Platform Admin.
    db.add(UserRole(user_id=admin.id, role_id=roles["Platform Admin"].id, assigned_by=admin.email))

    await db.commit()


async def seed_notifications(db: AsyncSession, admin: User) -> None:
    """Seed notifications for the admin inbox plus admin-configured alert rules."""
    # (severity, category, title, body, source, link, is_read, age_hours)
    notifications = [
        (NotificationSeverity.CRITICAL, "anomaly", "Privilege escalation detected",
         "svc-deploy-01 assumed IAM::AdminRole without MFA on tenant acme-corp.",
         "anomaly", "/anomalies", False, 0.02),
        (NotificationSeverity.CRITICAL, "security", "Signing key expiring in 14 days",
         "nexus-signing-v4 (ECDSA-P384) rotation ceremony cer-20260717-001 is pending quorum.",
         "security", "/hsm-security", False, 1.5),
        (NotificationSeverity.WARNING, "compliance", "GDPR encryption control drifted to partial",
         "healthsys-io PHI store · AES-256 key rotation overdue by 47 days.",
         "compliance", "/compliance", False, 3.0),
        (NotificationSeverity.WARNING, "tenancy", "Cross-tenant read attempt blocked",
         "media-stream-x attempted to read events.acme_corp.raw — blocked by RLS.",
         "tenancy", "/tenancy", False, 0.2),
        (NotificationSeverity.WARNING, "operations", "etcd write latency elevated",
         "etcd-1 write p99 exceeded 15ms threshold — node degraded.",
         "operations", "/command-center", True, 6.0),
        (NotificationSeverity.INFO, "security", "Key ceremony completed",
         "cer-20260703-001 reached 5-of-5 custodian quorum; nexus-master-v5 is active.",
         "security", "/hsm-security", True, 0.2),
        (NotificationSeverity.INFO, "config", "Configuration change staged",
         "audit.retention 5y → 7y staged by admin@nexus, awaiting apply.",
         "config", "/config-manager", False, 4.0),
        (NotificationSeverity.INFO, "compliance", "SOC2 assessment passed",
         "Deloitte Type II assessment recorded a score of 92.8.",
         "compliance", "/compliance", True, 26.0),
    ]
    for severity, category, title, body, source, link, is_read, age_hours in notifications:
        db.add(
            Notification(
                id=uuid.uuid4(),
                user_id=admin.id,
                severity=severity,
                category=category,
                title=title,
                body=body,
                source=source,
                link=link,
                is_read=is_read,
                read_at=hours_ago(age_hours) if is_read else None,
                created_at=hours_ago(age_hours),
            )
        )

    # (name, description, source, condition, threshold, channel, target, enabled, trigger_count, last_triggered_h)
    alert_rules = [
        ("Critical anomaly → security channel",
         "Page the security team when a critical anomaly is raised",
         "anomaly", "anomaly.severity == critical", NotificationSeverity.CRITICAL,
         AlertChannel.SLACK, "#sec-oncall", True, 12, 0.02),
        ("Certificate / key expiry warning",
         "Notify when a key or certificate is within 30 days of expiry",
         "security", "days_until_expiry <= 30", NotificationSeverity.WARNING,
         AlertChannel.EMAIL, "security@nexus", True, 3, 1.5),
        ("Compliance drift",
         "Raise when any framework control drifts from mapped",
         "compliance", "control.status != mapped", NotificationSeverity.WARNING,
         AlertChannel.IN_APP, "compliance-team", True, 5, 3.0),
        ("Tenant isolation breach",
         "Immediate alert on any cross-tenant access attempt",
         "tenancy", "breach.severity >= warning", NotificationSeverity.WARNING,
         AlertChannel.WEBHOOK, "https://hooks.nexus.internal/isolation", True, 8, 0.2),
        ("Audit chain verification failure",
         "Escalate if the audit hash chain fails verification",
         "audit", "integrity.is_valid == false", NotificationSeverity.CRITICAL,
         AlertChannel.EMAIL, "audit-oncall@nexus", False, 0, None),
    ]
    for (
        name, description, source, condition, threshold, channel, target, enabled, count, last_h
    ) in alert_rules:
        db.add(
            AlertRule(
                id=uuid.uuid4(),
                name=name,
                description=description,
                source=source,
                condition=condition,
                threshold_severity=threshold,
                channel=channel,
                target=target,
                is_enabled=enabled,
                created_by=admin.email,
                last_triggered_at=hours_ago(last_h) if last_h is not None else None,
                trigger_count=count,
            )
        )

    await db.commit()


async def seed_operations(db: AsyncSession) -> None:
    """Seed background-job runs and recent application errors for observability."""
    # (name, queue, status, progress, sched_h, start_h, finish_h, dur_ms, attempts, max_attempts, err, detail)
    jobs = [
        ("etcd-snapshot", "backups", JobStatus.SUCCEEDED, 100.0, 6.0, 6.0, 5.9, 5421.0, 1, 3,
         None, "Full etcd snapshot uploaded to s3://nexus-backups-us-east-1"),
        ("compliance-score-snapshot", "scheduler", JobStatus.SUCCEEDED, 100.0, 24.0, 24.0, 23.99,
         842.0, 1, 1, None, "Captured score snapshots for 4 frameworks"),
        ("hsm-attestation-sweep", "security", JobStatus.SUCCEEDED, 100.0, 6.0, 6.0, 5.98, 1203.0,
         1, 1, None, "7/7 attestation checks passed"),
        ("tenant-schema-migration", "provisioning", JobStatus.RUNNING, 47.0, 0.3, 0.25, None, None,
         1, 3, None, "fintech-labs-2 · schema_migration step in progress"),
        ("audit-chain-verify", "scheduler", JobStatus.QUEUED, 0.0, -0.05, None, None, None, 0, 1,
         None, "Scheduled full chain verification"),
        ("dek-rewrap", "security", JobStatus.FAILED, 62.0, 12.0, 12.0, 11.8, 9800.0, 2, 3,
         "provider timeout after 9.8s on slot 2", "Retry scheduled with backoff"),
    ]
    for (
        name, queue, status_val, progress, sched_h, start_h, finish_h, dur, attempts, max_att,
        err, detail,
    ) in jobs:
        db.add(
            BackgroundJob(
                id=uuid.uuid4(),
                name=name,
                queue=queue,
                status=status_val,
                progress_percent=progress,
                scheduled_at=hours_ago(sched_h) if sched_h is not None else None,
                started_at=hours_ago(start_h) if start_h is not None else None,
                finished_at=hours_ago(finish_h) if finish_h is not None else None,
                duration_ms=dur,
                attempts=attempts,
                max_attempts=max_att,
                last_error=err,
                detail=detail,
            )
        )

    # (level, error_type, message, source, request_path, status_code, occurrences, resolved, age_h)
    errors = [
        (ErrorLevel.ERROR, "ProviderTimeoutError",
         "HSM provider slot 2 did not respond within 10s during DEK re-wrap",
         "app.services.hsm_service", "/api/v1/hsm/keys/{id}/rotate", 504, 2, False, 11.8),
        (ErrorLevel.WARNING, "SlowQueryWarning",
         "audit-log chain verification exceeded 500ms on a 12k-entry chain",
         "app.services.audit_service", "/api/v1/audit-log/verify", None, 5, False, 6.0),
        (ErrorLevel.ERROR, "SchemaValidationError",
         "EventPayload v2.4 rejected: required property 'tenantId' missing",
         "app.api.v1.endpoints.tenancy", "/api/v4/events", 422, 47, False, 0.1),
        (ErrorLevel.CRITICAL, "IsolationBreachError",
         "cross-tenant read attempt blocked by row-level security",
         "app.services.tenancy_service", None, 403, 1, False, 0.2),
        (ErrorLevel.WARNING, "RateLimitExceeded",
         "global token bucket throttled 12 requests on /api/v4/events",
         "app.core.ratelimit", "/api/v4/events", 429, 12, True, 2.0),
    ]
    for (
        level, error_type, message, source, request_path, status_code, occurrences, resolved, age_h
    ) in errors:
        db.add(
            ApplicationError(
                id=uuid.uuid4(),
                occurred_at=hours_ago(age_h),
                level=level,
                error_type=error_type,
                message=message,
                source=source,
                request_path=request_path,
                status_code=status_code,
                occurrences=occurrences,
                resolved=resolved,
                created_at=hours_ago(age_h),
            )
        )

    await db.commit()


async def main() -> None:
    async with AsyncSessionLocal() as db:
        print("Wiping existing domain data...")
        await _wipe_domain_tables(db)

        print("Seeding user...")
        admin = (
            await db.execute(select(User).where(User.email == "admin@nexus"))
        ).scalar_one_or_none()
        if admin is None:
            admin = await seed_user(db)

        print("Seeding engine instance, etcd cluster, metrics...")
        await seed_engine(db)

        print("Seeding tenants...")
        tenants = await seed_tenants(db)

        print("Seeding anomalies, baselines, incidents...")
        await seed_anomalies(db, tenants)

        print("Seeding compliance frameworks, controls, violations, schema validation...")
        await seed_compliance(db)

        print("Seeding compliance score-trend history...")
        await seed_score_snapshots(db)

        print("Seeding config parameters and pending changes...")
        await seed_config(db)

        print("Seeding versioned configuration documents...")
        await seed_configurations(db)

        print("Seeding HSM slots, keys, ceremonies, certificates, algorithms, attestation...")
        await seed_hsm(db)

        print("Seeding security providers and key-operation history...")
        await seed_security(db)

        print("Seeding breach alerts, provisioning, tenant schema validation, snapshots...")
        await seed_tenancy_extras(db, tenants)

        print("Seeding RBAC permissions, roles, demo users, assignments...")
        await seed_rbac(db, admin)

        print("Seeding notifications and alert rules...")
        await seed_notifications(db, admin)

        print("Seeding background jobs and application errors...")
        await seed_operations(db)

        print("Appending audit log entries (hash chain)...")
        await seed_audit_log(db)

    await engine.dispose()
    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
