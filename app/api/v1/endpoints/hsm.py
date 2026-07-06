import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.hsm import MasterKeyStatus, SecurityOperationType
from app.models.user import User
from app.schemas.hsm import (
    AttestationRunRead,
    HsmOverview,
    KeyCeremonyCreate,
    KeyCeremonyRead,
    MasterKeyCreate,
    MasterKeyRead,
    MasterKeyRotateRequest,
    SecurityHealth,
    SecurityOperationRead,
    SecurityProviderRead,
    SecuritySummary,
)
from app.services.hsm_service import (
    approve_ceremony,
    attestation_run_to_read,
    ceremony_to_read,
    complete_ceremony,
    create_ceremony,
    create_key,
    disable_key,
    get_hsm_overview,
    get_key,
    get_security_health,
    get_security_summary,
    list_keys,
    list_operations,
    list_providers,
    rotate_key,
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
    return ceremony_to_read(ceremony)


@router.post("/ceremonies", response_model=KeyCeremonyRead, status_code=201)
async def initiate_key_ceremony(
    payload: KeyCeremonyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> KeyCeremonyRead:
    ceremony = await create_ceremony(db, payload, current_user.email)
    return ceremony_to_read(ceremony)


@router.post("/ceremonies/{ceremony_id}/complete", response_model=KeyCeremonyRead)
async def complete_key_ceremony(
    ceremony_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> KeyCeremonyRead:
    ceremony = await complete_ceremony(db, ceremony_id, current_user.email)
    return ceremony_to_read(ceremony)


@router.post("/attestation/run", response_model=AttestationRunRead)
async def trigger_attestation_run(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> AttestationRunRead:
    run = await run_attestation(db, current_user.email)
    return attestation_run_to_read(run)


@router.get("/summary", response_model=SecuritySummary)
async def read_security_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> SecuritySummary:
    return await get_security_summary(db, module_serial=_MODULE_SERIAL)


@router.get("/keys", response_model=list[MasterKeyRead])
async def read_keys(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    status_filter: MasterKeyStatus | None = Query(default=None, alias="status"),
) -> list[MasterKeyRead]:
    return await list_keys(db, key_status=status_filter)


@router.post("/keys", response_model=MasterKeyRead, status_code=201)
async def register_key(
    payload: MasterKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> MasterKeyRead:
    return await create_key(db, payload, actor=current_user.email)


@router.get("/keys/{key_id}", response_model=MasterKeyRead)
async def read_key(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> MasterKeyRead:
    return await get_key(db, key_id)


@router.post("/keys/{key_id}/rotate", response_model=MasterKeyRead)
async def rotate_master_key(
    key_id: uuid.UUID,
    payload: MasterKeyRotateRequest | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> MasterKeyRead:
    new_label = payload.new_label if payload else None
    return await rotate_key(db, key_id, actor=current_user.email, new_label=new_label)


@router.post("/keys/{key_id}/disable", response_model=MasterKeyRead)
async def disable_master_key(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> MasterKeyRead:
    return await disable_key(db, key_id, actor=current_user.email)


@router.get("/operations", response_model=list[SecurityOperationRead])
async def read_operations(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    operation_type: SecurityOperationType | None = Query(default=None, alias="type"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[SecurityOperationRead]:
    return await list_operations(db, operation_type=operation_type, limit=limit)


@router.get("/providers", response_model=list[SecurityProviderRead])
async def read_providers(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[SecurityProviderRead]:
    return await list_providers(db)


@router.get("/health", response_model=SecurityHealth)
async def read_security_health(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> SecurityHealth:
    return await get_security_health(db)
