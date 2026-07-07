import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_admin
from app.models.user import User
from app.schemas.rbac import (
    PermissionRead,
    RbacUserCreate,
    RbacUserRead,
    RbacUserUpdate,
    RoleAssignmentResult,
    RoleCreate,
    RoleRead,
    RoleUpdate,
)
from app.services.rbac_service import (
    assign_role,
    create_role,
    create_user,
    get_user,
    list_permissions,
    list_roles,
    list_users,
    remove_role,
    set_user_active,
    update_role,
    update_user,
)

# The whole administration surface is privileged: it manages accounts, roles
# and grants, so every route requires an administrator.
router = APIRouter(dependencies=[Depends(require_admin)])


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #


@router.get("/users", response_model=list[RbacUserRead])
async def read_users(
    db: AsyncSession = Depends(get_db),
    is_active: bool | None = None,
    search: str | None = Query(default=None),
) -> list[RbacUserRead]:
    return await list_users(db, is_active=is_active, search=search)


@router.post("/users", response_model=RbacUserRead, status_code=201)
async def create_new_user(
    payload: RbacUserCreate,
    db: AsyncSession = Depends(get_db),
) -> RbacUserRead:
    return await create_user(db, payload)


@router.get("/users/{user_id}", response_model=RbacUserRead)
async def read_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> RbacUserRead:
    return await get_user(db, user_id)


@router.patch("/users/{user_id}", response_model=RbacUserRead)
async def patch_user(
    user_id: uuid.UUID,
    payload: RbacUserUpdate,
    db: AsyncSession = Depends(get_db),
) -> RbacUserRead:
    return await update_user(db, user_id, payload)


@router.post("/users/{user_id}/activate", response_model=RbacUserRead)
async def activate_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> RbacUserRead:
    return await set_user_active(db, user_id, is_active=True)


@router.post("/users/{user_id}/deactivate", response_model=RbacUserRead)
async def deactivate_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> RbacUserRead:
    return await set_user_active(db, user_id, is_active=False)


# --------------------------------------------------------------------------- #
# Roles & permissions
# --------------------------------------------------------------------------- #


@router.get("/roles", response_model=list[RoleRead])
async def read_roles(db: AsyncSession = Depends(get_db)) -> list[RoleRead]:
    return await list_roles(db)


@router.post("/roles", response_model=RoleRead, status_code=201)
async def create_new_role(
    payload: RoleCreate,
    db: AsyncSession = Depends(get_db),
) -> RoleRead:
    return await create_role(db, payload)


@router.patch("/roles/{role_id}", response_model=RoleRead)
async def patch_role(
    role_id: uuid.UUID,
    payload: RoleUpdate,
    db: AsyncSession = Depends(get_db),
) -> RoleRead:
    return await update_role(db, role_id, payload)


@router.get("/permissions", response_model=list[PermissionRead])
async def read_permissions(
    db: AsyncSession = Depends(get_db),
    resource: str | None = Query(default=None),
) -> list[PermissionRead]:
    return await list_permissions(db, resource=resource)


# --------------------------------------------------------------------------- #
# Role assignment
# --------------------------------------------------------------------------- #


@router.post("/users/{user_id}/roles/{role_id}", response_model=RoleAssignmentResult)
async def assign_role_to_user(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> RoleAssignmentResult:
    return await assign_role(db, user_id, role_id, assigned_by=current_user.email)


@router.delete("/users/{user_id}/roles/{role_id}", response_model=RoleAssignmentResult)
async def remove_role_from_user(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> RoleAssignmentResult:
    return await remove_role(db, user_id, role_id)
