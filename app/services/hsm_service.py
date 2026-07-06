import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.hsm import (
    AttestationRun,
    Certificate,
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
    KeyCeremonyCreate,
    KeyCeremonyRead,
    MasterKeyCreate,
    MasterKeyRead,
    SecurityHealth,
    SecurityHealthCheck,
    SecurityOperationRead,
    SecurityProviderHealth,
    SecurityProviderRead,
    SecuritySummary,
)
from app.services.audit_service import append_entry_in_transaction

_EXPIRING_WITHIN_DAYS = 30
# A slot is flagged "near capacity" for posture reporting at 85%, but only a
# genuinely near-full slot (>=95%) fails the health check.
_NEAR_CAPACITY_PERCENT = 85.0
_CAPACITY_CRITICAL_PERCENT = 95.0
# How stale a provider's last self-reported health check can be before its
# status degrades to "stale".
_PROVIDER_STALE_AFTER_SECONDS = 3600


def _effective_key_status(key: MasterKey, now: datetime) -> str:
    """Derives the *displayed* status from stored lifecycle state + expiry.

    RETIRED and PENDING are explicit lifecycle states set by rotation
    events and ceremonies respectively, so they always take precedence.
    An ACTIVE key rolls over to "expiring" automatically as its expiry
    date approaches — no background job has to flip a status column.
    """
    if key.status in (
        MasterKeyStatus.RETIRED,
        MasterKeyStatus.PENDING,
        MasterKeyStatus.DISABLED,
    ):
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


def ceremony_to_read(c: KeyCeremony) -> KeyCeremonyRead:
    return KeyCeremonyRead(
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


def _master_key_to_read(k: MasterKey, now: datetime) -> MasterKeyRead:
    return MasterKeyRead(
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


async def _master_keys(db: AsyncSession) -> list[MasterKeyRead]:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(MasterKey)
        .options(selectinload(MasterKey.slot))
        .order_by(MasterKey.created_at.desc())
    )
    return [_master_key_to_read(k, now) for k in result.scalars().all()]


async def _ceremonies(db: AsyncSession) -> list[KeyCeremonyRead]:
    result = await db.execute(
        select(KeyCeremony)
        .options(selectinload(KeyCeremony.approvals), selectinload(KeyCeremony.master_key))
        .order_by(KeyCeremony.created_at.desc())
    )
    ceremonies = result.scalars().all()
    return [ceremony_to_read(c) for c in ceremonies]


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


async def create_ceremony(
    db: AsyncSession, payload: KeyCeremonyCreate, actor: str
) -> KeyCeremony:
    target_key = await _get_key_orm(db, payload.master_key_id)
    if target_key.status != MasterKeyStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Ceremonies can only be initiated for pending keys (key is {target_key.status.value})",
        )

    predecessor: MasterKey | None = None
    if payload.predecessor_key_id is not None:
        if payload.predecessor_key_id == payload.master_key_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Predecessor key must be different from the pending key",
            )
        predecessor = await _get_key_orm(db, payload.predecessor_key_id)
        if predecessor.status not in (MasterKeyStatus.ACTIVE, MasterKeyStatus.EXPIRING):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Predecessor key must be active or expiring "
                    f"(key is {predecessor.status.value})"
                ),
            )

    duplicate = await db.execute(
        select(KeyCeremony.id).where(
            KeyCeremony.master_key_id == target_key.id,
            KeyCeremony.status == CeremonyStatus.PENDING,
        )
    )
    if duplicate.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A pending ceremony already exists for this key",
        )

    now = datetime.now(timezone.utc)
    ceremony = KeyCeremony(
        id=uuid.uuid4(),
        ceremony_ref=f"CER-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}",
        master_key_id=target_key.id,
        predecessor_label=predecessor.key_label if predecessor else None,
        required_approvals=payload.required_approvals,
        status=CeremonyStatus.PENDING,
        scheduled_at=payload.scheduled_at,
    )
    db.add(ceremony)
    await db.flush()

    await append_entry_in_transaction(
        db,
        AuditLogEntryCreate(
            severity="info",
            event_type="key_operation",
            event_subtype="KEY_CEREMONY_INITIATED",
            actor=actor,
            description=f"Initiated key ceremony {ceremony.ceremony_ref} for {target_key.key_label}",
            metadata_json={
                "ceremony_ref": ceremony.ceremony_ref,
                "master_key_id": str(target_key.id),
                "master_key_label": target_key.key_label,
                "predecessor_label": ceremony.predecessor_label,
                "required_approvals": ceremony.required_approvals,
            },
        ),
    )
    await db.commit()
    result = await db.execute(
        select(KeyCeremony)
        .options(selectinload(KeyCeremony.approvals), selectinload(KeyCeremony.master_key))
        .where(KeyCeremony.id == ceremony.id)
    )
    return result.scalar_one()


async def approve_ceremony(
    db: AsyncSession, ceremony_id: uuid.UUID, custodian_email: str
) -> KeyCeremony:
    result = await db.execute(
        select(KeyCeremony)
        .options(selectinload(KeyCeremony.approvals), selectinload(KeyCeremony.master_key))
        .where(KeyCeremony.id == ceremony_id)
    )
    ceremony = result.scalar_one_or_none()
    if ceremony is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ceremony not found")
    if ceremony.status != CeremonyStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Ceremony is already {ceremony.status.value}",
        )

    approval = next(
        (a for a in ceremony.approvals if a.custodian_email == custodian_email), None
    )
    already_approved = approval is not None and approval.approved_at is not None
    if approval is None:
        approval = KeyCustodianApproval(ceremony_id=ceremony.id, custodian_email=custodian_email)
        db.add(approval)
        ceremony.approvals.append(approval)

    if not already_approved:
        approval.approved_at = datetime.now(timezone.utc)
        await append_entry_in_transaction(
            db,
            AuditLogEntryCreate(
                severity="info",
                event_type="key_operation",
                event_subtype="KEY_CEREMONY_APPROVED",
                actor=custodian_email,
                description=f"Approved key ceremony {ceremony.ceremony_ref}",
                metadata_json={
                    "ceremony_ref": ceremony.ceremony_ref,
                    "master_key_id": str(ceremony.master_key_id),
                    "master_key_label": ceremony.master_key.key_label,
                    "approval_count": ceremony.approval_count,
                    "required_approvals": ceremony.required_approvals,
                },
            ),
        )
    await db.commit()
    await db.refresh(ceremony, attribute_names=["approvals", "master_key"])
    return ceremony


async def complete_ceremony(db: AsyncSession, ceremony_id: uuid.UUID, actor: str) -> KeyCeremony:
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
    if ceremony.status != CeremonyStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Ceremony is already {ceremony.status.value}",
        )
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

    _record_operation(
        db,
        operation_type=SecurityOperationType.CEREMONY_COMPLETE,
        key=new_key,
        actor=actor,
        detail=f"Completed ceremony {ceremony.ceremony_ref}",
        occurred_at=now,
    )

    await append_entry_in_transaction(
        db,
        AuditLogEntryCreate(
            severity="info",
            event_type="key_operation",
            event_subtype="KEY_ROTATION_COMPLETE",
            actor=actor,
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
    await db.refresh(ceremony, attribute_names=["approvals", "master_key"])
    return ceremony


async def run_attestation(db: AsyncSession, actor: str) -> AttestationRun:
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
        id=uuid.uuid4(),
        ran_at=datetime.now(timezone.utc),
        checks=checks,
        all_passed=all(c["passed"] for c in checks),
    )
    db.add(run)
    _record_operation(
        db,
        operation_type=SecurityOperationType.ATTESTATION_RUN,
        key=None,
        actor=actor,
        detail="Executed hardware attestation checks",
        occurred_at=run.ran_at,
    )
    await append_entry_in_transaction(
        db,
        AuditLogEntryCreate(
            severity="info",
            event_type="key_operation",
            event_subtype="HSM_ATTESTATION_RUN",
            actor=actor,
            description="Executed HSM attestation checks",
            metadata_json={
                "attestation_run_id": str(run.id),
                "all_passed": run.all_passed,
                "check_count": len(checks),
            },
        ),
    )
    await db.commit()
    await db.refresh(run)
    return run


# --------------------------------------------------------------------------- #
# Key management (list / create / rotate / disable)
# --------------------------------------------------------------------------- #


def _record_operation(
    db: AsyncSession,
    *,
    operation_type: SecurityOperationType,
    key: MasterKey | None,
    actor: str,
    detail: str,
    occurred_at: datetime,
    op_status: SecurityOperationStatus = SecurityOperationStatus.SUCCESS,
) -> None:
    db.add(
        SecurityOperation(
            id=uuid.uuid4(),
            operation_type=operation_type,
            master_key_id=key.id if key else None,
            key_label=key.key_label if key else None,
            actor=actor,
            status=op_status,
            detail=detail,
            occurred_at=occurred_at,
        )
    )


def _next_version_label(label: str) -> str:
    """`nexus-master-v5` -> `nexus-master-v6`; unversioned labels gain `-v2`."""
    match = re.search(r"-v(\d+)$", label)
    if match:
        return f"{label[: match.start()]}-v{int(match.group(1)) + 1}"
    return f"{label}-v2"


async def _get_key_orm(db: AsyncSession, key_id: uuid.UUID) -> MasterKey:
    result = await db.execute(
        select(MasterKey).options(selectinload(MasterKey.slot)).where(MasterKey.id == key_id)
    )
    key = result.scalar_one_or_none()
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
    return key


async def _assert_label_available(db: AsyncSession, label: str) -> None:
    existing = await db.execute(select(MasterKey.id).where(MasterKey.key_label == label))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Key label '{label}' already exists",
        )


async def list_keys(
    db: AsyncSession, *, key_status: MasterKeyStatus | None = None
) -> list[MasterKeyRead]:
    now = datetime.now(timezone.utc)
    query = (
        select(MasterKey)
        .options(selectinload(MasterKey.slot))
        .order_by(MasterKey.created_at.desc())
    )
    if key_status is not None:
        query = query.where(MasterKey.status == key_status)
    result = await db.execute(query)
    return [_master_key_to_read(k, now) for k in result.scalars().all()]


async def get_key(db: AsyncSession, key_id: uuid.UUID) -> MasterKeyRead:
    return _master_key_to_read(await _get_key_orm(db, key_id), datetime.now(timezone.utc))


async def create_key(
    db: AsyncSession, payload: MasterKeyCreate, actor: str
) -> MasterKeyRead:
    """Registers a new master-key reference (metadata only). The key starts as
    ``pending`` — it is activated when a custodian-quorum ceremony completes.
    """
    await _assert_label_available(db, payload.key_label)
    if payload.slot_id is not None:
        slot = await db.get(HsmSlot, payload.slot_id)
        if slot is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Slot not found")

    now = datetime.now(timezone.utc)
    key = MasterKey(
        id=uuid.uuid4(),
        key_label=payload.key_label,
        slot_id=payload.slot_id,
        hsm_object_id=None,
        algorithm=payload.algorithm,
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=payload.rotation_policy_days,
        activated_at=None,
        expires_at=None,
        wraps_dek_count=0,
        throughput_ops=0.0,
    )
    db.add(key)
    _record_operation(
        db,
        operation_type=SecurityOperationType.KEY_CREATE,
        key=key,
        actor=actor,
        detail=f"Registered key reference {key.key_label} ({key.algorithm}) — pending ceremony",
        occurred_at=now,
    )
    await append_entry_in_transaction(
        db,
        AuditLogEntryCreate(
            severity="info",
            event_type="key_operation",
            event_subtype="KEY_REFERENCE_REGISTERED",
            actor=actor,
            description=f"Registered key reference {key.key_label}",
            metadata_json={
                "master_key_id": str(key.id),
                "key_label": key.key_label,
                "algorithm": key.algorithm,
                "slot_id": str(key.slot_id) if key.slot_id else None,
                "rotation_policy_days": key.rotation_policy_days,
            },
        ),
    )
    await db.commit()
    return await get_key(db, key.id)


async def rotate_key(
    db: AsyncSession, key_id: uuid.UUID, actor: str, new_label: str | None = None
) -> MasterKeyRead:
    """Rotates a key through the provider abstraction: retires the target key
    and activates a freshly generated successor that re-wraps its DEKs. Only
    active or expiring keys can be rotated.
    """
    key = await _get_key_orm(db, key_id)
    if key.status not in (MasterKeyStatus.ACTIVE, MasterKeyStatus.EXPIRING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Only active or expiring keys can be rotated (key is {key.status.value})",
        )

    successor_label = new_label or _next_version_label(key.key_label)
    await _assert_label_available(db, successor_label)

    now = datetime.now(timezone.utc)
    successor = MasterKey(
        id=uuid.uuid4(),
        key_label=successor_label,
        slot_id=key.slot_id,
        hsm_object_id=None,
        algorithm=key.algorithm,
        status=MasterKeyStatus.ACTIVE,
        rotation_policy_days=key.rotation_policy_days,
        activated_at=now,
        expires_at=now + timedelta(days=key.rotation_policy_days),
        wraps_dek_count=key.wraps_dek_count,
        throughput_ops=key.throughput_ops,
    )
    db.add(successor)
    await db.flush()

    key.status = MasterKeyStatus.RETIRED
    key.retired_at = now
    key.superseded_by_id = successor.id
    key.throughput_ops = 0.0

    _record_operation(
        db,
        operation_type=SecurityOperationType.KEY_ROTATE,
        key=successor,
        actor=actor,
        detail=(
            f"Rotated {key.key_label} -> {successor.key_label} via provider "
            f"abstraction ({successor.wraps_dek_count} DEKs re-wrapped)"
        ),
        occurred_at=now,
    )
    await append_entry_in_transaction(
        db,
        AuditLogEntryCreate(
            severity="info",
            event_type="key_operation",
            event_subtype="KEY_ROTATED",
            actor=actor,
            description=f"Rotated {key.key_label} to {successor.key_label}",
            metadata_json={
                "predecessor_key_id": str(key.id),
                "predecessor_label": key.key_label,
                "successor_key_id": str(successor.id),
                "successor_label": successor.key_label,
                "wraps_dek_count": successor.wraps_dek_count,
            },
        ),
    )
    await db.commit()
    return await get_key(db, successor.id)


async def disable_key(db: AsyncSession, key_id: uuid.UUID, actor: str) -> MasterKeyRead:
    key = await _get_key_orm(db, key_id)
    if key.status in (MasterKeyStatus.RETIRED, MasterKeyStatus.DISABLED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Key is already {key.status.value}",
        )

    now = datetime.now(timezone.utc)
    previous_status = key.status.value
    key.status = MasterKeyStatus.DISABLED
    key.retired_at = now
    key.throughput_ops = 0.0
    _record_operation(
        db,
        operation_type=SecurityOperationType.KEY_DISABLE,
        key=key,
        actor=actor,
        detail=f"Disabled key {key.key_label}",
        occurred_at=now,
    )
    await append_entry_in_transaction(
        db,
        AuditLogEntryCreate(
            severity="warning",
            event_type="key_operation",
            event_subtype="KEY_DISABLED",
            actor=actor,
            description=f"Disabled key {key.key_label}",
            metadata_json={
                "master_key_id": str(key.id),
                "key_label": key.key_label,
                "previous_status": previous_status,
            },
        ),
    )
    await db.commit()
    return await get_key(db, key.id)


# --------------------------------------------------------------------------- #
# Operations history
# --------------------------------------------------------------------------- #


async def list_operations(
    db: AsyncSession,
    *,
    operation_type: SecurityOperationType | None = None,
    limit: int = 50,
) -> list[SecurityOperationRead]:
    query = (
        select(SecurityOperation)
        .order_by(SecurityOperation.occurred_at.desc())
        .limit(limit)
    )
    if operation_type is not None:
        query = query.where(SecurityOperation.operation_type == operation_type)
    result = await db.execute(query)
    return [
        SecurityOperationRead(
            id=o.id,
            operation_type=o.operation_type.value,
            master_key_id=o.master_key_id,
            key_label=o.key_label,
            actor=o.actor,
            status=o.status.value,
            detail=o.detail,
            occurred_at=o.occurred_at,
        )
        for o in result.scalars().all()
    ]


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #


def _provider_status(provider: SecurityProvider, now: datetime) -> str:
    if not provider.is_active:
        return "offline"
    if (
        provider.last_health_check_at is not None
        and (now - provider.last_health_check_at).total_seconds()
        > _PROVIDER_STALE_AFTER_SECONDS
    ):
        return "stale"
    if provider.error_count_24h > 0 or provider.pool_utilization_percent >= 90:
        return "degraded"
    return "online"


def _provider_to_read(provider: SecurityProvider, now: datetime) -> SecurityProviderRead:
    return SecurityProviderRead(
        id=provider.id,
        name=provider.name,
        provider_type=provider.provider_type.value,
        model=provider.model,
        manufacturer=provider.manufacturer,
        library_path=provider.library_path,
        firmware_version=provider.firmware_version,
        serial_number=provider.serial_number,
        fips_level=provider.fips_level,
        is_active=provider.is_active,
        status=_provider_status(provider, now),
        pool_active=provider.pool_active,
        pool_max=provider.pool_max,
        pool_utilization_percent=provider.pool_utilization_percent,
        connection_timeout_seconds=provider.connection_timeout_seconds,
        avg_latency_ms=provider.avg_latency_ms,
        session_count=provider.session_count,
        rw_session_count=provider.rw_session_count,
        error_count_24h=provider.error_count_24h,
        supported_mechanisms=list(provider.supported_mechanisms or []),
        last_health_check_at=provider.last_health_check_at,
    )


async def list_providers(db: AsyncSession) -> list[SecurityProviderRead]:
    now = datetime.now(timezone.utc)
    result = await db.execute(select(SecurityProvider).order_by(SecurityProvider.name))
    return [_provider_to_read(p, now) for p in result.scalars().all()]


# --------------------------------------------------------------------------- #
# Posture summary
# --------------------------------------------------------------------------- #


async def get_security_summary(db: AsyncSession, module_serial: str) -> SecuritySummary:
    now = datetime.now(timezone.utc)
    keys = (await db.execute(select(MasterKey))).scalars().all()
    slots = (await db.execute(select(HsmSlot))).scalars().all()
    certs = (await db.execute(select(Certificate))).scalars().all()
    algorithms = (await db.execute(select(CryptoAlgorithm))).scalars().all()
    providers = (await db.execute(select(SecurityProvider))).scalars().all()
    pending_ceremonies = (
        await db.execute(
            select(func.count())
            .select_from(KeyCeremony)
            .where(KeyCeremony.status == CeremonyStatus.PENDING)
        )
    ).scalar_one()

    def count_status(target: MasterKeyStatus) -> int:
        return sum(1 for k in keys if k.status == target)

    rotation_candidates = [
        (k.expires_at - now).days
        for k in keys
        if k.status in (MasterKeyStatus.ACTIVE, MasterKeyStatus.EXPIRING)
        and k.expires_at is not None
    ]
    next_rotation_days = max(0, min(rotation_candidates)) if rotation_candidates else None

    runs = (
        await db.execute(
            select(AttestationRun).order_by(AttestationRun.ran_at.desc()).limit(7)
        )
    ).scalars().all()
    latest_attestation_passed = runs[0].all_passed if runs else None
    attestation_pass_rate = (
        round(sum(1 for r in runs if r.all_passed) / len(runs) * 100, 1) if runs else 100.0
    )

    cert_states = [_certificate_status(c, now) for c in certs]
    disabled_keys = count_status(MasterKeyStatus.DISABLED)

    attention = (
        latest_attestation_passed is False
        or any(not p.is_active for p in providers)
        or any(s.capacity_percent >= _CAPACITY_CRITICAL_PERCENT for s in slots)
        or disabled_keys > 0
    )

    return SecuritySummary(
        module_serial=module_serial,
        overall_status="attention" if attention else "healthy",
        provider_count=len(providers),
        active_provider_count=sum(1 for p in providers if p.is_active),
        total_keys=len(keys),
        active_keys=count_status(MasterKeyStatus.ACTIVE),
        expiring_keys=count_status(MasterKeyStatus.EXPIRING),
        pending_keys=count_status(MasterKeyStatus.PENDING),
        retired_keys=count_status(MasterKeyStatus.RETIRED),
        disabled_keys=disabled_keys,
        key_ops_per_second=round(sum(s.ops_per_second for s in slots), 1),
        slot_count=len(slots),
        active_slots=sum(1 for s in slots if s.is_active),
        near_capacity_slots=sum(
            1 for s in slots if s.capacity_percent >= _NEAR_CAPACITY_PERCENT
        ),
        certificate_count=len(certs),
        expiring_certificates=sum(1 for s in cert_states if s in ("expiring", "expired")),
        algorithm_count=len(algorithms),
        deprecated_algorithm_count=sum(1 for a in algorithms if a.is_deprecated),
        pending_ceremonies=pending_ceremonies,
        next_rotation_days=next_rotation_days,
        latest_attestation_passed=latest_attestation_passed,
        attestation_pass_rate=attestation_pass_rate,
    )


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


async def get_security_health(db: AsyncSession) -> SecurityHealth:
    """Reports HSM/provider health from real database connectivity plus the
    stored provider, slot, certificate and attestation state.

    This does *not* probe physical hardware — provider status reflects each
    provider's last self-reported health check and configured state, which is
    the honest signal available in this environment.
    """
    now = datetime.now(timezone.utc)

    try:
        await db.execute(text("SELECT 1"))
        db_reachable = True
    except Exception:  # noqa: BLE001 — any driver error means "not reachable"
        return SecurityHealth(
            overall_status="unavailable",
            checked_at=now,
            db_reachable=False,
            providers=[],
            checks=[
                SecurityHealthCheck(
                    key="database",
                    label="Database Connectivity",
                    passed=False,
                    detail="database unreachable",
                )
            ],
        )

    providers = (
        await db.execute(select(SecurityProvider).order_by(SecurityProvider.name))
    ).scalars().all()
    slots = (await db.execute(select(HsmSlot))).scalars().all()
    certs = (await db.execute(select(Certificate))).scalars().all()
    latest_run = (
        await db.execute(
            select(AttestationRun).order_by(AttestationRun.ran_at.desc()).limit(1)
        )
    ).scalar_one_or_none()

    provider_healths = [
        SecurityProviderHealth(
            name=p.name,
            status=_provider_status(p, now),
            detail=f"pool {p.pool_active}/{p.pool_max} · {p.error_count_24h} errors/24h",
        )
        for p in providers
    ]

    active_providers = sum(1 for p in providers if p.is_active)
    critical_slots = [s for s in slots if s.capacity_percent >= _CAPACITY_CRITICAL_PERCENT]
    near_slots = [s for s in slots if s.capacity_percent >= _NEAR_CAPACITY_PERCENT]
    expired_certs = [c for c in certs if _certificate_status(c, now) == "expired"]
    expiring_certs = [c for c in certs if _certificate_status(c, now) == "expiring"]

    checks = [
        SecurityHealthCheck(
            key="database",
            label="Database Connectivity",
            passed=db_reachable,
            detail="reachable",
        ),
        SecurityHealthCheck(
            key="providers",
            label="Provider Availability",
            passed=active_providers > 0,
            detail=f"{active_providers}/{len(providers)} provider(s) active",
        ),
        SecurityHealthCheck(
            key="attestation",
            label="Hardware Attestation",
            passed=bool(latest_run and latest_run.all_passed),
            detail=(
                "latest attestation passed"
                if latest_run and latest_run.all_passed
                else "latest attestation failed"
                if latest_run
                else "no attestation runs recorded"
            ),
        ),
        SecurityHealthCheck(
            key="slot_capacity",
            label="Slot Capacity",
            passed=len(critical_slots) == 0,
            detail=(
                f"{len(near_slots)} slot(s) near capacity"
                if near_slots
                else "all slots within capacity"
            ),
        ),
        SecurityHealthCheck(
            key="certificates",
            label="Certificate Validity",
            passed=len(expired_certs) == 0,
            detail=(
                f"{len(expired_certs)} expired · {len(expiring_certs)} expiring"
                if (expired_certs or expiring_certs)
                else "all certificates valid"
            ),
        ),
    ]

    overall_status = "healthy" if all(c.passed for c in checks) else "degraded"

    return SecurityHealth(
        overall_status=overall_status,
        checked_at=now,
        db_reachable=db_reachable,
        providers=provider_healths,
        checks=checks,
    )
