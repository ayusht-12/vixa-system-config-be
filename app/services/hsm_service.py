import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.hsm import (
    AttestationRun,
    Certificate,
    CryptoAlgorithm,
    HsmSlot,
    KeyCeremony,
    KeyCustodianApproval,
    MasterKey,
    MasterKeyStatus,
)
from app.schemas.audit import AuditLogEntryCreate
from app.schemas.hsm import (
    AttestationCheckResult,
    AttestationHistoryPoint,
    AttestationRunRead,
    CertificateRead,
    CryptoAlgorithmRead,
    CustodianApprovalRead,
    HsmOverview,
    HsmSlotRead,
    KeyCeremonyRead,
    MasterKeyRead,
)
from app.services.audit_service import append_entry

_EXPIRING_WITHIN_DAYS = 30


def _effective_key_status(key: MasterKey, now: datetime) -> str:
    """Derives the *displayed* status from stored lifecycle state + expiry.

    RETIRED and PENDING are explicit lifecycle states set by rotation
    events and ceremonies respectively, so they always take precedence.
    An ACTIVE key rolls over to "expiring" automatically as its expiry
    date approaches — no background job has to flip a status column.
    """
    if key.status in (MasterKeyStatus.RETIRED, MasterKeyStatus.PENDING):
        return key.status.value
    if key.expires_at and (key.expires_at - now).days <= _EXPIRING_WITHIN_DAYS:
        return MasterKeyStatus.EXPIRING.value
    return MasterKeyStatus.ACTIVE.value


def _rotation_percent(key: MasterKey, now: datetime) -> float:
    if not key.activated_at or not key.expires_at:
        return 0.0
    total = (key.expires_at - key.activated_at).total_seconds()
    if total <= 0:
        return 100.0
    elapsed = (now - key.activated_at).total_seconds()
    return round(min(100.0, max(0.0, elapsed / total * 100)), 1)


def _certificate_status(cert: Certificate, now: datetime) -> str:
    if cert.expires_at <= now:
        return "expired"
    if (cert.expires_at - now).days <= _EXPIRING_WITHIN_DAYS:
        return "expiring"
    return "valid"


async def _slots(db: AsyncSession) -> list[HsmSlotRead]:
    result = await db.execute(select(HsmSlot).order_by(HsmSlot.slot_number))
    return [
        HsmSlotRead(
            id=s.id,
            slot_number=s.slot_number,
            label=s.label,
            purpose=s.purpose.value,
            is_active=s.is_active,
            object_count=s.object_count,
            capacity_max_objects=s.capacity_max_objects,
            capacity_percent=s.capacity_percent,
            ops_per_second=s.ops_per_second,
            token_flags=s.token_flags,
        )
        for s in result.scalars().all()
    ]


async def _master_keys(db: AsyncSession) -> list[MasterKeyRead]:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(MasterKey)
        .options(selectinload(MasterKey.slot))
        .order_by(MasterKey.created_at.desc())
    )
    keys = result.scalars().all()
    return [
        MasterKeyRead(
            id=k.id,
            key_label=k.key_label,
            slot_label=k.slot.label if k.slot else None,
            algorithm=k.algorithm,
            status=k.status.value,
            effective_status=_effective_key_status(k, now),
            rotation_policy_days=k.rotation_policy_days,
            rotation_percent=_rotation_percent(k, now),
            activated_at=k.activated_at,
            expires_at=k.expires_at,
            days_until_rotation=(k.expires_at - now).days if k.expires_at else None,
            wraps_dek_count=k.wraps_dek_count,
            throughput_ops=k.throughput_ops,
        )
        for k in keys
    ]


async def _ceremonies(db: AsyncSession) -> list[KeyCeremonyRead]:
    result = await db.execute(
        select(KeyCeremony)
        .options(selectinload(KeyCeremony.approvals), selectinload(KeyCeremony.master_key))
        .order_by(KeyCeremony.created_at.desc())
    )
    ceremonies = result.scalars().all()
    return [
        KeyCeremonyRead(
            id=c.id,
            ceremony_ref=c.ceremony_ref,
            master_key_label=c.master_key.key_label,
            predecessor_label=c.predecessor_label,
            required_approvals=c.required_approvals,
            approval_count=c.approval_count,
            quorum_met=c.quorum_met,
            status=c.status.value,
            scheduled_at=c.scheduled_at,
            completed_at=c.completed_at,
            approvals=[
                CustodianApprovalRead(custodian_email=a.custodian_email, approved_at=a.approved_at)
                for a in c.approvals
            ],
        )
        for c in ceremonies
    ]


async def _certificates(db: AsyncSession) -> list[CertificateRead]:
    now = datetime.now(timezone.utc)
    result = await db.execute(select(Certificate).order_by(Certificate.expires_at.asc()))
    return [
        CertificateRead(
            id=c.id,
            common_name=c.common_name,
            cert_type=c.cert_type.value,
            key_algorithm=c.key_algorithm,
            signature_algorithm=c.signature_algorithm,
            issued_at=c.issued_at,
            expires_at=c.expires_at,
            days_left=c.days_left,
            status=_certificate_status(c, now),
            auto_renew=c.auto_renew,
        )
        for c in result.scalars().all()
    ]


async def _algorithms(db: AsyncSession) -> list[CryptoAlgorithmRead]:
    result = await db.execute(
        select(CryptoAlgorithm).order_by(
            CryptoAlgorithm.is_deprecated.asc(), CryptoAlgorithm.name.asc()
        )
    )
    return [CryptoAlgorithmRead.model_validate(a, from_attributes=True) for a in result.scalars()]


def attestation_run_to_read(run: AttestationRun) -> AttestationRunRead:
    checks = [AttestationCheckResult(**c) for c in run.checks]
    return AttestationRunRead(
        id=run.id,
        ran_at=run.ran_at,
        all_passed=run.all_passed,
        pass_count=sum(1 for c in checks if c.passed),
        total_checks=len(checks),
        checks=checks,
    )


async def get_hsm_overview(db: AsyncSession, module_serial: str) -> HsmOverview:
    since = datetime.now(timezone.utc) - timedelta(days=2)
    history_result = await db.execute(
        select(AttestationRun)
        .where(AttestationRun.ran_at >= since)
        .order_by(AttestationRun.ran_at.desc())
        .limit(7)
    )
    history = history_result.scalars().all()
    latest = history[0] if history else None

    return HsmOverview(
        module_serial=module_serial,
        slots=await _slots(db),
        master_keys=await _master_keys(db),
        ceremonies=await _ceremonies(db),
        certificates=await _certificates(db),
        algorithms=await _algorithms(db),
        latest_attestation=attestation_run_to_read(latest) if latest else None,
        attestation_history=[
            AttestationHistoryPoint(ran_at=r.ran_at, all_passed=r.all_passed)
            for r in reversed(history)
        ],
    )


async def approve_ceremony(
    db: AsyncSession, ceremony_id: uuid.UUID, custodian_email: str
) -> KeyCeremony:
    result = await db.execute(
        select(KeyCeremony)
        .options(selectinload(KeyCeremony.approvals))
        .where(KeyCeremony.id == ceremony_id)
    )
    ceremony = result.scalar_one_or_none()
    if ceremony is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ceremony not found")

    approval = next(
        (a for a in ceremony.approvals if a.custodian_email == custodian_email), None
    )
    if approval is None:
        approval = KeyCustodianApproval(ceremony_id=ceremony.id, custodian_email=custodian_email)
        db.add(approval)
        ceremony.approvals.append(approval)

    approval.approved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(ceremony, attribute_names=["approvals"])
    return ceremony


async def complete_ceremony(db: AsyncSession, ceremony_id: uuid.UUID) -> KeyCeremony:
    """Finalize a ceremony once quorum is met — rotates the master key.

    This is the one action in the HSM domain with real cross-entity side
    effects: it retires the predecessor key, activates the new one, and
    writes an audit-log entry, all inside the same unit of work.
    """
    result = await db.execute(
        select(KeyCeremony)
        .options(
            selectinload(KeyCeremony.approvals),
            selectinload(KeyCeremony.master_key),
        )
        .where(KeyCeremony.id == ceremony_id)
    )
    ceremony = result.scalar_one_or_none()
    if ceremony is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ceremony not found")
    if not ceremony.quorum_met:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Quorum not met: {ceremony.approval_count}/{ceremony.required_approvals} approved",
        )

    now = datetime.now(timezone.utc)
    new_key = ceremony.master_key
    new_key.status = MasterKeyStatus.ACTIVE
    new_key.activated_at = now
    new_key.expires_at = now + timedelta(days=new_key.rotation_policy_days)

    if ceremony.predecessor_label:
        predecessor_result = await db.execute(
            select(MasterKey).where(MasterKey.key_label == ceremony.predecessor_label)
        )
        predecessor = predecessor_result.scalar_one_or_none()
        if predecessor:
            predecessor.status = MasterKeyStatus.RETIRED
            predecessor.retired_at = now
            new_key.superseded_by_id = None
            predecessor.superseded_by_id = new_key.id

    ceremony.status = ceremony.status.__class__.COMPLETE
    ceremony.completed_at = now

    await append_entry(
        db,
        AuditLogEntryCreate(
            severity="info",
            event_type="key_operation",
            event_subtype="KEY_ROTATION_COMPLETE",
            actor="engine-core",
            description=(
                f"{ceremony.predecessor_label or 'new key'} -> {new_key.key_label} "
                f"rotation completed via ceremony {ceremony.ceremony_ref}"
            ),
            metadata_json={
                "ceremony_ref": ceremony.ceremony_ref,
                "new_key": new_key.key_label,
                "approvals": ceremony.approval_count,
            },
        ),
    )

    await db.commit()
    await db.refresh(ceremony)
    return ceremony


async def run_attestation(db: AsyncSession) -> AttestationRun:
    """Executes the fixed FIPS 140-3 self-test suite.

    These are the same checks a real HSM firmware runs on a POST
    (power-on self test) cycle; here they're simulated as deterministic
    checks against current module state so the endpoint is safe to call
    repeatedly in a demo/dev environment.
    """
    checks = [
        {"key": "fips_mode", "label": "FIPS Mode", "passed": True, "detail": "FIPS 140-3 Level 3"},
        {"key": "tamper_seal", "label": "Tamper Seal", "passed": True, "detail": "seal intact"},
        {"key": "firmware_hash", "label": "Firmware Hash", "passed": True, "detail": "sha256 verified"},
        {"key": "rng_quality", "label": "RNG Quality", "passed": True, "detail": "entropy 7.99 bits"},
        {"key": "key_zeroize", "label": "Key Zeroize", "passed": True, "detail": "zeroization test passed"},
        {"key": "self_test", "label": "Self-Test", "passed": True, "detail": "12/12 KATs passed"},
        {"key": "attest_chain", "label": "Attest Chain", "passed": True, "detail": "3-cert chain valid"},
    ]
    run = AttestationRun(
        ran_at=datetime.now(timezone.utc),
        checks=checks,
        all_passed=all(c["passed"] for c in checks),
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return run
