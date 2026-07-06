"""Pydantic data-validation tests for the schemas backing the newly added
system / auth / tenancy endpoints.

These are pure schema tests: they exercise Pydantic validation rules (required
fields, length bounds, enum membership, UUID parsing, type coercion) with no
database, network, or event loop, so they run fast and deterministically and
pin down the request/response contracts independently of the endpoints.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.models.tenancy import TenantMemberRole
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    SessionRead,
)
from app.schemas.system import (
    DependenciesResponse,
    DependencyHealth,
    LivenessResponse,
    ReadinessResponse,
    VersionResponse,
)
from app.schemas.compliance import (
    AssessmentCreate,
    AssessmentRead,
    ComplianceSummary,
    ControlRead,
    FrameworkScore,
    GapRead,
    ScoreTrendPoint,
    ScoreTrendSeries,
    ScoreTrendsResponse,
)
from app.schemas.config import (
    ConfigurationCreate,
    ConfigurationImportRequest,
    ConfigurationUpdate,
    ConfigurationValidateResponse,
)
from app.schemas.hsm import (
    MasterKeyCreate,
    MasterKeyRotateRequest,
    SecurityHealth,
    SecurityOperationRead,
    SecurityProviderRead,
    SecuritySummary,
)
from app.schemas.tenancy import (
    TenantMemberCreate,
    TenantMemberRead,
    TenantUsageSummary,
)


class _Attrs:
    """Minimal stand-in for an ORM row, for from_attributes validation."""

    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


# --------------------------------------------------------------------------- #
# Auth: ChangePasswordRequest
# --------------------------------------------------------------------------- #


def test_change_password_valid() -> None:
    model = ChangePasswordRequest(current_password="old-secret", new_password="new-secret-1")
    assert model.new_password == "new-secret-1"


def test_change_password_rejects_short_new_password() -> None:
    with pytest.raises(ValidationError):
        ChangePasswordRequest(current_password="old-secret", new_password="short7!")  # 7 chars


def test_change_password_rejects_overlong_new_password() -> None:
    with pytest.raises(ValidationError):
        ChangePasswordRequest(current_password="old", new_password="x" * 129)


def test_change_password_rejects_empty_current_password() -> None:
    with pytest.raises(ValidationError):
        ChangePasswordRequest(current_password="", new_password="new-secret-1")


def test_change_password_rejects_missing_field() -> None:
    with pytest.raises(ValidationError):
        ChangePasswordRequest(new_password="new-secret-1")  # type: ignore[call-arg]


# --------------------------------------------------------------------------- #
# Auth: ForgotPasswordRequest / ForgotPasswordResponse
# --------------------------------------------------------------------------- #


def test_forgot_password_valid() -> None:
    assert ForgotPasswordRequest(email="user@nexus.local").email == "user@nexus.local"


def test_forgot_password_rejects_too_short_email() -> None:
    with pytest.raises(ValidationError):
        ForgotPasswordRequest(email="ab")


def test_forgot_password_response_defaults_token_to_none() -> None:
    resp = ForgotPasswordResponse(detail="ok")
    assert resp.reset_token is None


def test_forgot_password_response_can_carry_token() -> None:
    resp = ForgotPasswordResponse(detail="ok", reset_token="raw-token")
    assert resp.reset_token == "raw-token"


# --------------------------------------------------------------------------- #
# Auth: ResetPasswordRequest
# --------------------------------------------------------------------------- #


def test_reset_password_valid() -> None:
    model = ResetPasswordRequest(token="a-token", new_password="new-secret-1")
    assert model.token == "a-token"


def test_reset_password_rejects_short_password() -> None:
    with pytest.raises(ValidationError):
        ResetPasswordRequest(token="a-token", new_password="tiny")


def test_reset_password_rejects_empty_token() -> None:
    with pytest.raises(ValidationError):
        ResetPasswordRequest(token="", new_password="new-secret-1")


# --------------------------------------------------------------------------- #
# Auth: SessionRead — from_attributes + no secret leakage
# --------------------------------------------------------------------------- #


def test_session_read_from_orm_attributes_excludes_secrets() -> None:
    now = datetime.now(timezone.utc)
    row = _Attrs(
        id=uuid.uuid4(),
        created_at=now,
        expires_at=now + timedelta(days=1),
        token_hash="super-secret-hash",  # must never surface
        user_id=uuid.uuid4(),
        revoked_at=None,
    )
    session = SessionRead.model_validate(row)
    dumped = session.model_dump()
    assert set(dumped.keys()) == {"id", "created_at", "expires_at"}
    assert "token_hash" not in dumped
    assert "user_id" not in dumped


# --------------------------------------------------------------------------- #
# Tenancy: TenantMemberCreate
# --------------------------------------------------------------------------- #


def test_tenant_member_create_defaults_to_viewer() -> None:
    model = TenantMemberCreate(user_id=uuid.uuid4())
    assert model.role is TenantMemberRole.VIEWER


def test_tenant_member_create_accepts_enum_value_string() -> None:
    model = TenantMemberCreate(user_id=uuid.uuid4(), role="analyst")
    assert model.role is TenantMemberRole.ANALYST


def test_tenant_member_create_rejects_unknown_role() -> None:
    with pytest.raises(ValidationError):
        TenantMemberCreate(user_id=uuid.uuid4(), role="superadmin")


def test_tenant_member_create_rejects_bad_uuid() -> None:
    with pytest.raises(ValidationError):
        TenantMemberCreate(user_id="not-a-uuid", role="viewer")


def test_tenant_member_create_parses_uuid_string() -> None:
    raw = str(uuid.uuid4())
    model = TenantMemberCreate(user_id=raw)
    assert str(model.user_id) == raw


# --------------------------------------------------------------------------- #
# Tenancy: TenantMemberRead / TenantUsageSummary
# --------------------------------------------------------------------------- #


def test_tenant_member_read_valid() -> None:
    model = TenantMemberRead(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        email="member@nexus.local",
        display_name="Member",
        role="owner",
        created_at=datetime.now(timezone.utc),
    )
    assert model.role == "owner"


def test_tenant_usage_summary_valid() -> None:
    model = TenantUsageSummary(
        tenant_id=uuid.uuid4(),
        slug="acme",
        display_name="Acme Corp",
        status="active",
        member_count=3,
        events_per_second=12.5,
        provisioning_jobs_total=2,
        active_provisioning_jobs=1,
        schema_validations_total=4,
        backup_snapshots_total=5,
        current_backup_snapshots=4,
        isolation_score=100.0,
        isolation_level="strict",
    )
    assert model.member_count == 3
    assert model.events_per_second == 12.5


def test_tenant_usage_summary_rejects_non_numeric_count() -> None:
    with pytest.raises(ValidationError):
        TenantUsageSummary(
            tenant_id=uuid.uuid4(),
            slug="acme",
            display_name="Acme Corp",
            status="active",
            member_count="not-a-number",
            events_per_second=0.0,
            provisioning_jobs_total=0,
            active_provisioning_jobs=0,
            schema_validations_total=0,
            backup_snapshots_total=0,
            current_backup_snapshots=0,
            isolation_score=0.0,
            isolation_level="pending",
        )


# --------------------------------------------------------------------------- #
# System: liveness / readiness / version / dependencies
# --------------------------------------------------------------------------- #


def test_liveness_response_valid() -> None:
    assert LivenessResponse(status="alive").status == "alive"


def test_dependency_health_detail_optional() -> None:
    assert DependencyHealth(name="database", status="up").detail is None
    assert DependencyHealth(name="database", status="down", detail="boom").detail == "boom"


def test_readiness_response_coerces_nested_dependencies() -> None:
    model = ReadinessResponse(
        status="ready",
        dependencies=[{"name": "database", "status": "up"}],
    )
    assert model.dependencies[0].name == "database"
    assert isinstance(model.dependencies[0], DependencyHealth)


def test_version_response_requires_all_fields() -> None:
    with pytest.raises(ValidationError):
        VersionResponse(name="Nexus", version="0.1.0")  # type: ignore[call-arg]


def test_dependencies_response_valid() -> None:
    model = DependenciesResponse(
        status="degraded",
        dependencies=[
            DependencyHealth(name="database", status="up"),
            DependencyHealth(name="audit_signing_key", status="down", detail="missing"),
        ],
    )
    assert model.status == "degraded"
    assert len(model.dependencies) == 2


# --------------------------------------------------------------------------- #
# Compliance: assessments / controls / summary / gaps
# --------------------------------------------------------------------------- #


def test_assessment_create_valid() -> None:
    model = AssessmentCreate(framework_id=uuid.uuid4())
    assert isinstance(model.framework_id, uuid.UUID)


def test_assessment_create_parses_uuid_string() -> None:
    raw = str(uuid.uuid4())
    assert str(AssessmentCreate(framework_id=raw).framework_id) == raw


def test_assessment_create_rejects_bad_uuid() -> None:
    with pytest.raises(ValidationError):
        AssessmentCreate(framework_id="not-a-uuid")


def test_assessment_create_requires_framework_id() -> None:
    with pytest.raises(ValidationError):
        AssessmentCreate()  # type: ignore[call-arg]


def test_assessment_read_allows_null_completion_fields() -> None:
    model = AssessmentRead(
        id=uuid.uuid4(),
        framework_id=uuid.uuid4(),
        framework_code="soc2",
        status="in_progress",
        started_by="admin@nexus.local",
        started_at=datetime.now(timezone.utc),
        completed_at=None,
        score=None,
        total_controls=None,
        mapped_controls=None,
        gap_controls=None,
        notes=None,
    )
    assert model.score is None
    assert model.status == "in_progress"


def test_control_read_valid() -> None:
    model = ControlRead(
        id=uuid.uuid4(),
        framework_id=uuid.uuid4(),
        framework_code="iso27001",
        control_domain="Access Control",
        control_description="RBAC enforced",
        control_code="A.9",
        status="mapped",
    )
    assert model.framework_code == "iso27001"


def test_framework_score_valid() -> None:
    model = FrameworkScore(
        code="gdpr", display_name="GDPR", score=88.5, certified=True, open_violation_count=2
    )
    assert model.score == 88.5


def test_compliance_summary_coerces_nested_frameworks() -> None:
    model = ComplianceSummary(
        overall_score=90.0,
        framework_count=1,
        certified_count=1,
        total_controls=10,
        mapped_controls=7,
        partial_controls=2,
        gap_controls=1,
        open_violation_count=3,
        frameworks=[
            {
                "code": "soc2",
                "display_name": "SOC 2",
                "score": 90.0,
                "certified": True,
                "open_violation_count": 0,
            }
        ],
    )
    assert isinstance(model.frameworks[0], FrameworkScore)
    assert model.frameworks[0].code == "soc2"


def test_compliance_summary_rejects_non_numeric_count() -> None:
    with pytest.raises(ValidationError):
        ComplianceSummary(
            overall_score=90.0,
            framework_count="lots",
            certified_count=1,
            total_controls=10,
            mapped_controls=7,
            partial_controls=2,
            gap_controls=1,
            open_violation_count=3,
            frameworks=[],
        )


def test_gap_read_valid() -> None:
    model = GapRead(
        framework_id=uuid.uuid4(),
        framework_code="hipaa",
        control_domain="Audit",
        control_description="Audit logging",
        control_code="164.312",
        status="gap",
    )
    assert model.status == "gap"


def test_score_trend_point_valid() -> None:
    point = ScoreTrendPoint(captured_at=datetime.now(timezone.utc), score=91.5)
    assert point.score == 91.5


def test_score_trend_series_coerces_points() -> None:
    series = ScoreTrendSeries(
        framework_id=uuid.uuid4(),
        code="soc2",
        display_name="SOC2",
        current_score=92.8,
        delta=1.2,
        points=[{"captured_at": datetime.now(timezone.utc), "score": 90.0}],
    )
    assert isinstance(series.points[0], ScoreTrendPoint)
    assert series.points[0].score == 90.0


def test_score_trends_response_valid() -> None:
    response = ScoreTrendsResponse(window_days=30, series=[])
    assert response.window_days == 30


def test_score_trends_response_rejects_bad_window() -> None:
    with pytest.raises(ValidationError):
        ScoreTrendsResponse(window_days="thirty", series=[])


# --------------------------------------------------------------------------- #
# HSM / Security: key management
# --------------------------------------------------------------------------- #


def test_master_key_create_valid_with_defaults() -> None:
    model = MasterKeyCreate(key_label="nexus-master-v6", algorithm="AES-256")
    assert model.rotation_policy_days == 180
    assert model.slot_id is None


def test_master_key_create_rejects_short_label() -> None:
    with pytest.raises(ValidationError):
        MasterKeyCreate(key_label="ab", algorithm="AES-256")


def test_master_key_create_rejects_overlong_label() -> None:
    with pytest.raises(ValidationError):
        MasterKeyCreate(key_label="x" * 81, algorithm="AES-256")


def test_master_key_create_rejects_missing_algorithm() -> None:
    with pytest.raises(ValidationError):
        MasterKeyCreate(key_label="nexus-master-v6")  # type: ignore[call-arg]


def test_master_key_create_rejects_out_of_range_rotation() -> None:
    with pytest.raises(ValidationError):
        MasterKeyCreate(key_label="nexus-master-v6", algorithm="AES-256", rotation_policy_days=0)
    with pytest.raises(ValidationError):
        MasterKeyCreate(key_label="nexus-master-v6", algorithm="AES-256", rotation_policy_days=4000)


def test_master_key_create_parses_slot_uuid_string() -> None:
    raw = str(uuid.uuid4())
    model = MasterKeyCreate(key_label="nexus-master-v6", algorithm="AES-256", slot_id=raw)
    assert str(model.slot_id) == raw


def test_master_key_create_rejects_bad_slot_uuid() -> None:
    with pytest.raises(ValidationError):
        MasterKeyCreate(key_label="nexus-master-v6", algorithm="AES-256", slot_id="not-a-uuid")


def test_master_key_rotate_request_optional_label() -> None:
    assert MasterKeyRotateRequest().new_label is None
    assert MasterKeyRotateRequest(new_label="nexus-master-v7").new_label == "nexus-master-v7"


def test_master_key_rotate_request_rejects_short_label() -> None:
    with pytest.raises(ValidationError):
        MasterKeyRotateRequest(new_label="ab")


# --------------------------------------------------------------------------- #
# HSM / Security: providers / operations / summary / health
# --------------------------------------------------------------------------- #


def test_security_provider_read_valid() -> None:
    model = SecurityProviderRead(
        id=uuid.uuid4(),
        name="nexus-luna-primary",
        provider_type="pkcs11",
        model="Thales Luna 7",
        manufacturer="Thales Group",
        library_path="/usr/lib/libCryptoki2_64.so",
        firmware_version="7.4.2",
        serial_number="TL7-US-E1-0042",
        fips_level="FIPS 140-3 Level 3",
        is_active=True,
        status="online",
        pool_active=8,
        pool_max=10,
        pool_utilization_percent=80.0,
        connection_timeout_seconds=5,
        avg_latency_ms=0.4,
        session_count=8,
        rw_session_count=3,
        error_count_24h=0,
        supported_mechanisms=["CKM_AES_GCM"],
        last_health_check_at=datetime.now(timezone.utc),
    )
    assert model.supported_mechanisms == ["CKM_AES_GCM"]
    assert model.library_path is not None


def test_security_provider_read_allows_null_optional_hardware_fields() -> None:
    model = SecurityProviderRead(
        id=uuid.uuid4(),
        name="soft-keystore",
        provider_type="software",
        model="in-memory",
        manufacturer="internal",
        library_path=None,
        firmware_version=None,
        serial_number=None,
        fips_level="",
        is_active=True,
        status="online",
        pool_active=0,
        pool_max=1,
        pool_utilization_percent=0.0,
        connection_timeout_seconds=5,
        avg_latency_ms=0.0,
        session_count=0,
        rw_session_count=0,
        error_count_24h=0,
        supported_mechanisms=[],
        last_health_check_at=None,
    )
    assert model.serial_number is None


def test_security_operation_read_allows_null_key_reference() -> None:
    model = SecurityOperationRead(
        id=uuid.uuid4(),
        operation_type="attestation_run",
        master_key_id=None,
        key_label=None,
        actor="scheduler",
        status="success",
        detail="attestation passed",
        occurred_at=datetime.now(timezone.utc),
    )
    assert model.master_key_id is None
    assert model.operation_type == "attestation_run"


def test_security_summary_valid() -> None:
    model = SecuritySummary(
        module_serial="TL7-US-E1-0042",
        overall_status="healthy",
        provider_count=1,
        active_provider_count=1,
        total_keys=5,
        active_keys=2,
        expiring_keys=1,
        pending_keys=1,
        retired_keys=1,
        disabled_keys=0,
        key_ops_per_second=2847.0,
        slot_count=4,
        active_slots=3,
        near_capacity_slots=1,
        certificate_count=84,
        expiring_certificates=2,
        algorithm_count=5,
        deprecated_algorithm_count=1,
        pending_ceremonies=1,
        next_rotation_days=14,
        latest_attestation_passed=True,
        attestation_pass_rate=100.0,
    )
    assert model.next_rotation_days == 14
    assert model.overall_status == "healthy"


def test_security_summary_allows_null_next_rotation_and_attestation() -> None:
    model = SecuritySummary(
        module_serial="TL7",
        overall_status="healthy",
        provider_count=0,
        active_provider_count=0,
        total_keys=0,
        active_keys=0,
        expiring_keys=0,
        pending_keys=0,
        retired_keys=0,
        disabled_keys=0,
        key_ops_per_second=0.0,
        slot_count=0,
        active_slots=0,
        near_capacity_slots=0,
        certificate_count=0,
        expiring_certificates=0,
        algorithm_count=0,
        deprecated_algorithm_count=0,
        pending_ceremonies=0,
        next_rotation_days=None,
        latest_attestation_passed=None,
        attestation_pass_rate=100.0,
    )
    assert model.next_rotation_days is None
    assert model.latest_attestation_passed is None


def test_security_summary_rejects_non_numeric_count() -> None:
    with pytest.raises(ValidationError):
        SecuritySummary(
            module_serial="TL7",
            overall_status="healthy",
            provider_count="lots",
            active_provider_count=0,
            total_keys=0,
            active_keys=0,
            expiring_keys=0,
            pending_keys=0,
            retired_keys=0,
            disabled_keys=0,
            key_ops_per_second=0.0,
            slot_count=0,
            active_slots=0,
            near_capacity_slots=0,
            certificate_count=0,
            expiring_certificates=0,
            algorithm_count=0,
            deprecated_algorithm_count=0,
            pending_ceremonies=0,
            next_rotation_days=None,
            latest_attestation_passed=None,
            attestation_pass_rate=100.0,
        )


def test_security_health_coerces_nested_checks_and_providers() -> None:
    model = SecurityHealth(
        overall_status="healthy",
        checked_at=datetime.now(timezone.utc),
        db_reachable=True,
        providers=[{"name": "nexus-luna-primary", "status": "online", "detail": "pool 8/10"}],
        checks=[{"key": "database", "label": "Database Connectivity", "passed": True, "detail": "reachable"}],
    )
    assert model.providers[0].name == "nexus-luna-primary"
    assert model.checks[0].passed is True


# --------------------------------------------------------------------------- #
# Config Management: versioned configuration documents
# --------------------------------------------------------------------------- #


def test_configuration_create_valid_with_defaults() -> None:
    model = ConfigurationCreate(name="engine-runtime", payload={"workers": 8})
    assert model.sensitive_keys == []
    assert model.description is None


def test_configuration_create_rejects_short_name() -> None:
    with pytest.raises(ValidationError):
        ConfigurationCreate(name="a", payload={"workers": 8})


def test_configuration_create_rejects_missing_payload() -> None:
    with pytest.raises(ValidationError):
        ConfigurationCreate(name="engine-runtime")  # type: ignore[call-arg]


def test_configuration_create_rejects_non_dict_payload() -> None:
    with pytest.raises(ValidationError):
        ConfigurationCreate(name="engine-runtime", payload=["not", "a", "dict"])


def test_configuration_update_sensitive_keys_optional() -> None:
    model = ConfigurationUpdate(payload={"a": 1})
    assert model.sensitive_keys is None


def test_configuration_validate_response_valid() -> None:
    model = ConfigurationValidateResponse(valid=False, errors=["payload must be a non-empty object"], checksum=None)
    assert model.valid is False
    assert model.checksum is None


def test_configuration_import_request_requires_at_least_one_item() -> None:
    with pytest.raises(ValidationError):
        ConfigurationImportRequest(items=[])


def test_configuration_import_request_valid() -> None:
    model = ConfigurationImportRequest(items=[{"name": "cfg-a", "payload": {"x": 1}}])
    assert model.items[0].name == "cfg-a"
    assert model.items[0].sensitive_keys == []
