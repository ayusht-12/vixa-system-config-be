import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class HsmSlotRead(BaseModel):
    id: uuid.UUID
    slot_number: int
    label: str
    purpose: str
    is_active: bool
    object_count: int
    capacity_max_objects: int
    capacity_percent: float
    ops_per_second: float
    token_flags: str


class MasterKeyRead(BaseModel):
    id: uuid.UUID
    key_label: str
    slot_label: str | None
    algorithm: str
    status: str
    effective_status: str
    rotation_policy_days: int
    rotation_percent: float
    activated_at: datetime | None
    expires_at: datetime | None
    days_until_rotation: int | None
    wraps_dek_count: int
    throughput_ops: float


class CustodianApprovalRead(BaseModel):
    custodian_email: str
    approved_at: datetime | None


class KeyCeremonyRead(BaseModel):
    id: uuid.UUID
    ceremony_ref: str
    master_key_label: str
    predecessor_label: str | None
    required_approvals: int
    approval_count: int
    quorum_met: bool
    status: str
    scheduled_at: datetime | None
    completed_at: datetime | None
    approvals: list[CustodianApprovalRead]


class KeyCeremonyCreate(BaseModel):
    master_key_id: uuid.UUID
    predecessor_key_id: uuid.UUID | None = None
    required_approvals: int = Field(default=5, ge=1, le=10)
    scheduled_at: datetime | None = None

    @field_validator("scheduled_at")
    @classmethod
    def scheduled_at_must_be_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("scheduled_at must include timezone information")
        return value


class CertificateRead(BaseModel):
    id: uuid.UUID
    common_name: str
    cert_type: str
    key_algorithm: str
    signature_algorithm: str
    issued_at: datetime
    expires_at: datetime
    days_left: int
    status: str
    auto_renew: bool


class CryptoAlgorithmRead(BaseModel):
    id: uuid.UUID
    name: str
    purpose_label: str
    is_active: bool
    is_deprecated: bool
    deprecated_at: datetime | None
    ops_per_second: float
    detail_json: dict


class AttestationCheckResult(BaseModel):
    key: str
    label: str
    passed: bool
    detail: str


class AttestationRunRead(BaseModel):
    id: uuid.UUID
    ran_at: datetime
    all_passed: bool
    pass_count: int
    total_checks: int
    checks: list[AttestationCheckResult]


class AttestationHistoryPoint(BaseModel):
    ran_at: datetime
    all_passed: bool


class HsmOverview(BaseModel):
    module_serial: str
    slots: list[HsmSlotRead]
    master_keys: list[MasterKeyRead]
    ceremonies: list[KeyCeremonyRead]
    certificates: list[CertificateRead]
    algorithms: list[CryptoAlgorithmRead]
    latest_attestation: AttestationRunRead | None
    attestation_history: list[AttestationHistoryPoint]


# --------------------------------------------------------------------------- #
# Key management (list / create / rotate / disable)
# --------------------------------------------------------------------------- #


class MasterKeyCreate(BaseModel):
    """Registers a new master-key *reference* (metadata only — no key material).

    Newly created keys start life as ``pending``; they are activated when a
    custodian-quorum ceremony completes.
    """

    key_label: str = Field(min_length=3, max_length=80)
    algorithm: str = Field(min_length=2, max_length=40)
    slot_id: uuid.UUID | None = None
    rotation_policy_days: int = Field(default=180, ge=1, le=3650)


class MasterKeyRotateRequest(BaseModel):
    # Optional explicit successor label; auto-versioned from the predecessor
    # (e.g. ``nexus-master-v5`` -> ``nexus-master-v6``) when omitted.
    new_label: str | None = Field(default=None, min_length=3, max_length=80)


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #


class SecurityProviderRead(BaseModel):
    id: uuid.UUID
    name: str
    provider_type: str
    model: str
    manufacturer: str
    library_path: str | None
    firmware_version: str | None
    serial_number: str | None
    fips_level: str
    is_active: bool
    status: str
    pool_active: int
    pool_max: int
    pool_utilization_percent: float
    connection_timeout_seconds: int
    avg_latency_ms: float
    session_count: int
    rw_session_count: int
    error_count_24h: int
    supported_mechanisms: list[str]
    last_health_check_at: datetime | None


# --------------------------------------------------------------------------- #
# Operation history
# --------------------------------------------------------------------------- #


class SecurityOperationRead(BaseModel):
    id: uuid.UUID
    operation_type: str
    master_key_id: uuid.UUID | None
    key_label: str | None
    actor: str
    status: str
    detail: str
    occurred_at: datetime


# --------------------------------------------------------------------------- #
# Posture summary
# --------------------------------------------------------------------------- #


class SecuritySummary(BaseModel):
    module_serial: str
    overall_status: str
    provider_count: int
    active_provider_count: int
    total_keys: int
    active_keys: int
    expiring_keys: int
    pending_keys: int
    retired_keys: int
    disabled_keys: int
    key_ops_per_second: float
    slot_count: int
    active_slots: int
    near_capacity_slots: int
    certificate_count: int
    expiring_certificates: int
    algorithm_count: int
    deprecated_algorithm_count: int
    pending_ceremonies: int
    next_rotation_days: int | None
    latest_attestation_passed: bool | None
    attestation_pass_rate: float


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


class SecurityHealthCheck(BaseModel):
    key: str
    label: str
    passed: bool
    detail: str


class SecurityProviderHealth(BaseModel):
    name: str
    status: str
    detail: str


class SecurityHealth(BaseModel):
    overall_status: str
    checked_at: datetime
    db_reachable: bool
    providers: list[SecurityProviderHealth]
    checks: list[SecurityHealthCheck]
