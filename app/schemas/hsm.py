import uuid
from datetime import datetime

from pydantic import BaseModel


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
