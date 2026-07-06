import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.config import ConfigurationStatus
from app.models.user import User
from app.schemas.common import Message
from app.schemas.config import (
    ConfigManagerOverview,
    ConfigParameterRead,
    ConfigParameterStage,
    ConfigurationCompareResponse,
    ConfigurationCreate,
    ConfigurationExportResponse,
    ConfigurationImportRequest,
    ConfigurationImportResponse,
    ConfigurationRead,
    ConfigurationUpdate,
    ConfigurationValidateRequest,
    ConfigurationValidateResponse,
)
from app.services.config_service import (
    activate_configuration,
    apply_pending_changes,
    archive_configuration,
    compare_configurations,
    create_configuration,
    create_successor_version,
    delete_configuration,
    export_configurations,
    get_config_manager_overview,
    get_configuration,
    get_configuration_history,
    get_latest_active_configuration,
    get_latest_configuration,
    import_configurations,
    list_configurations,
    revert_config_change,
    rollback_configuration,
    stage_config_change,
    validate_configuration_payload,
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


# --------------------------------------------------------------------------- #
# Versioned configuration documents
#
# NOTE: the literal routes (/configurations/latest, /export, /validate, ...)
# are declared BEFORE /configurations/{configuration_id} so FastAPI matches
# them first instead of trying to parse "latest" as a UUID path param.
# --------------------------------------------------------------------------- #


@router.get("/configurations", response_model=list[ConfigurationRead])
async def read_configurations(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    name: str | None = Query(default=None),
    status_filter: ConfigurationStatus | None = Query(default=None, alias="status"),
    include_deleted: bool = Query(default=False),
) -> list[ConfigurationRead]:
    return await list_configurations(
        db, name=name, config_status=status_filter, include_deleted=include_deleted
    )


@router.post("/configurations", response_model=ConfigurationRead, status_code=201)
async def create_new_configuration(
    payload: ConfigurationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ConfigurationRead:
    return await create_configuration(db, payload, created_by=current_user.email)


@router.get("/configurations/latest", response_model=ConfigurationRead)
async def read_latest_configuration(
    name: str = Query(..., min_length=2, max_length=120),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ConfigurationRead:
    return await get_latest_configuration(db, name=name)


@router.get("/configurations/latest-active", response_model=ConfigurationRead)
async def read_latest_active_configuration(
    name: str = Query(..., min_length=2, max_length=120),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ConfigurationRead:
    return await get_latest_active_configuration(db, name=name)


@router.get("/configurations/export", response_model=ConfigurationExportResponse)
async def export_all_configurations(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ConfigurationExportResponse:
    return await export_configurations(db)


@router.post("/configurations/validate", response_model=ConfigurationValidateResponse)
async def validate_configuration(
    payload: ConfigurationValidateRequest,
    _: User = Depends(get_current_user),
) -> ConfigurationValidateResponse:
    return await validate_configuration_payload(payload)


@router.post("/configurations/import", response_model=ConfigurationImportResponse)
async def import_all_configurations(
    payload: ConfigurationImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ConfigurationImportResponse:
    return await import_configurations(db, payload, created_by=current_user.email)


@router.get("/configurations/{configuration_id}", response_model=ConfigurationRead)
async def read_configuration(
    configuration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ConfigurationRead:
    return await get_configuration(db, configuration_id)


@router.patch("/configurations/{configuration_id}", response_model=ConfigurationRead)
async def update_configuration(
    configuration_id: uuid.UUID,
    payload: ConfigurationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ConfigurationRead:
    return await create_successor_version(db, configuration_id, payload, created_by=current_user.email)


@router.delete("/configurations/{configuration_id}", response_model=Message)
async def soft_delete_configuration(
    configuration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> Message:
    await delete_configuration(db, configuration_id)
    return Message(detail="Configuration deleted")


@router.get(
    "/configurations/{configuration_id}/history", response_model=list[ConfigurationRead]
)
async def read_configuration_history(
    configuration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[ConfigurationRead]:
    return await get_configuration_history(db, configuration_id)


@router.post("/configurations/{configuration_id}/rollback", response_model=ConfigurationRead)
async def rollback_to_configuration(
    configuration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ConfigurationRead:
    return await rollback_configuration(db, configuration_id, actor=current_user.email)


@router.post("/configurations/{configuration_id}/activate", response_model=ConfigurationRead)
async def activate_configuration_version(
    configuration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ConfigurationRead:
    return await activate_configuration(db, configuration_id, actor=current_user.email)


@router.post("/configurations/{configuration_id}/archive", response_model=ConfigurationRead)
async def archive_configuration_version(
    configuration_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ConfigurationRead:
    return await archive_configuration(db, configuration_id, actor=current_user.email)


@router.get(
    "/configurations/{configuration_id}/compare/{version}",
    response_model=ConfigurationCompareResponse,
)
async def compare_configuration_versions(
    configuration_id: uuid.UUID,
    version: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ConfigurationCompareResponse:
    return await compare_configurations(db, configuration_id, version)
