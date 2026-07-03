import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.user import User
from app.schemas.common import Message
from app.schemas.config import ConfigManagerOverview, ConfigParameterRead, ConfigParameterStage
from app.services.config_service import (
    apply_pending_changes,
    get_config_manager_overview,
    revert_config_change,
    stage_config_change,
)

router = APIRouter()


@router.get("/overview", response_model=ConfigManagerOverview)
async def read_config_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ConfigManagerOverview:
    return await get_config_manager_overview(db)


@router.patch("/parameters/{parameter_id}", response_model=ConfigParameterRead)
async def stage_parameter_change(
    parameter_id: uuid.UUID,
    payload: ConfigParameterStage,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> ConfigParameterRead:
    parameter = await stage_config_change(db, parameter_id, payload)
    return ConfigParameterRead.from_model(parameter)


@router.post("/parameters/{parameter_id}/revert", response_model=ConfigParameterRead)
async def revert_parameter_change(
    parameter_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> ConfigParameterRead:
    parameter = await revert_config_change(db, parameter_id)
    return ConfigParameterRead.from_model(parameter)


@router.post("/apply", response_model=Message)
async def apply_all_pending_changes(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Message:
    count = await apply_pending_changes(db, changed_by=current_user.email)
    return Message(detail=f"Applied {count} pending change(s)")
