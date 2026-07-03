import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.user import User
from app.schemas.hsm import AttestationRunRead, HsmOverview, KeyCeremonyRead
from app.services.hsm_service import (
    approve_ceremony,
    attestation_run_to_read,
    complete_ceremony,
    get_hsm_overview,
    run_attestation,
)

router = APIRouter()

_MODULE_SERIAL = "TL7-US-E1-0042"


@router.get("/overview", response_model=HsmOverview)
async def read_hsm_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> HsmOverview:
    return await get_hsm_overview(db, module_serial=_MODULE_SERIAL)


@router.post("/ceremonies/{ceremony_id}/approve", response_model=KeyCeremonyRead)
async def approve_key_ceremony(
    ceremony_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> KeyCeremonyRead:
    ceremony = await approve_ceremony(db, ceremony_id, current_user.email)
    return KeyCeremonyRead(
        id=ceremony.id,
        ceremony_ref=ceremony.ceremony_ref,
        master_key_label=ceremony.master_key.key_label,
        predecessor_label=ceremony.predecessor_label,
        required_approvals=ceremony.required_approvals,
        approval_count=ceremony.approval_count,
        quorum_met=ceremony.quorum_met,
        status=ceremony.status.value,
        scheduled_at=ceremony.scheduled_at,
        completed_at=ceremony.completed_at,
        approvals=[
            {"custodian_email": a.custodian_email, "approved_at": a.approved_at}
            for a in ceremony.approvals
        ],
    )


@router.post("/ceremonies/{ceremony_id}/complete", response_model=KeyCeremonyRead)
async def complete_key_ceremony(
    ceremony_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> KeyCeremonyRead:
    ceremony = await complete_ceremony(db, ceremony_id)
    return KeyCeremonyRead(
        id=ceremony.id,
        ceremony_ref=ceremony.ceremony_ref,
        master_key_label=ceremony.master_key.key_label,
        predecessor_label=ceremony.predecessor_label,
        required_approvals=ceremony.required_approvals,
        approval_count=ceremony.approval_count,
        quorum_met=ceremony.quorum_met,
        status=ceremony.status.value,
        scheduled_at=ceremony.scheduled_at,
        completed_at=ceremony.completed_at,
        approvals=[
            {"custodian_email": a.custodian_email, "approved_at": a.approved_at}
            for a in ceremony.approvals
        ],
    )


@router.post("/attestation/run", response_model=AttestationRunRead)
async def trigger_attestation_run(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> AttestationRunRead:
    run = await run_attestation(db)
    return attestation_run_to_read(run)
