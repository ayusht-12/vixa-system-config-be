import uuid
from collections import defaultdict

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.models.user import User
from app.schemas.rbac import (
    PermissionCreate,
    PermissionRead,
    RbacUserCreate,
    RbacUserRead,
    RbacUserUpdate,
    RoleAssignmentResult,
    RoleCreate,
    RoleRead,
    RoleSummary,
    RoleUpdate,
)


# --------------------------------------------------------------------------- #
# Internal loaders
# --------------------------------------------------------------------------- #


async def _roles_by_user(
    db: AsyncSession, user_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[Role]]:
    if not user_ids:
        return {}
    rows = (
        await db.execute(
            select(UserRole.user_id, Role)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id.in_(user_ids))
            .order_by(Role.name)
        )
    ).all()
    grouped: dict[uuid.UUID, list[Role]] = defaultdict(list)
    for user_id, role in rows:
        grouped[user_id].append(role)
    return grouped


async def _permissions_by_role(
    db: AsyncSession, role_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[Permission]]:
    if not role_ids:
        return {}
    rows = (
        await db.execute(
            select(RolePermission.role_id, Permission)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id.in_(role_ids))
            .order_by(Permission.name)
        )
    ).all()
    grouped: dict[uuid.UUID, list[Permission]] = defaultdict(list)
    for role_id, permission in rows:
        grouped[role_id].append(permission)
    return grouped


async def _user_counts_by_role(db: AsyncSession) -> dict[uuid.UUID, int]:
    rows = (
        await db.execute(select(UserRole.role_id, func.count()).group_by(UserRole.role_id))
    ).all()
    return dict(rows)


def _user_to_read(user: User, roles: list[Role]) -> RbacUserRead:
    return RbacUserRead(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        is_active=user.is_active,
        is_admin=user.is_admin,
        created_at=user.created_at,
        roles=[RoleSummary(id=r.id, name=r.name) for r in roles],
    )


def _role_to_read(role: Role, permissions: list[Permission], user_count: int) -> RoleRead:
    return RoleRead(
        id=role.id,
        name=role.name,
        description=role.description,
        is_active=role.is_active,
        permission_count=len(permissions),
        user_count=user_count,
        permissions=[PermissionRead.model_validate(p) for p in permissions],
        created_at=role.created_at,
    )


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #


async def list_users(
    db: AsyncSession, *, is_active: bool | None = None, search: str | None = None
) -> list[RbacUserRead]:
    query = select(User).order_by(User.display_name)
    if is_active is not None:
        query = query.where(User.is_active == is_active)
    if search:
        pattern = f"%{search}%"
        query = query.where(User.display_name.ilike(pattern) | User.email.ilike(pattern))
    users = (await db.execute(query)).scalars().all()
    roles_by_user = await _roles_by_user(db, [u.id for u in users])
    return [_user_to_read(u, roles_by_user.get(u.id, [])) for u in users]


async def _get_user_orm(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


async def get_user(db: AsyncSession, user_id: uuid.UUID) -> RbacUserRead:
    user = await _get_user_orm(db, user_id)
    roles_by_user = await _roles_by_user(db, [user.id])
    return _user_to_read(user, roles_by_user.get(user.id, []))


async def create_user(db: AsyncSession, payload: RbacUserCreate) -> RbacUserRead:
    existing = (
        await db.execute(select(User).where(User.email == payload.email))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists"
        )

    user = User(
        id=uuid.uuid4(),
        email=payload.email,
        display_name=payload.display_name,
        hashed_password=hash_password(payload.password),
        is_active=True,
        is_admin=payload.is_admin,
    )
    db.add(user)
    await db.flush()

    if payload.role_ids:
        roles = (
            await db.execute(select(Role).where(Role.id.in_(payload.role_ids)))
        ).scalars().all()
        found = {r.id for r in roles}
        missing = [str(rid) for rid in payload.role_ids if rid not in found]
        if missing:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown role id(s): {', '.join(missing)}",
            )
        for role in roles:
            db.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=None))

    await db.commit()
    return await get_user(db, user.id)


async def update_user(
    db: AsyncSession, user_id: uuid.UUID, payload: RbacUserUpdate
) -> RbacUserRead:
    user = await _get_user_orm(db, user_id)
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.is_admin is not None:
        user.is_admin = payload.is_admin
    await db.commit()
    return await get_user(db, user.id)


async def set_user_active(
    db: AsyncSession, user_id: uuid.UUID, *, is_active: bool
) -> RbacUserRead:
    user = await _get_user_orm(db, user_id)
    user.is_active = is_active
    await db.commit()
    return await get_user(db, user.id)


# --------------------------------------------------------------------------- #
# Roles
# --------------------------------------------------------------------------- #


async def list_roles(db: AsyncSession) -> list[RoleRead]:
    roles = (await db.execute(select(Role).order_by(Role.name))).scalars().all()
    perms_by_role = await _permissions_by_role(db, [r.id for r in roles])
    counts = await _user_counts_by_role(db)
    return [
        _role_to_read(r, perms_by_role.get(r.id, []), counts.get(r.id, 0)) for r in roles
    ]


async def _get_role_orm(db: AsyncSession, role_id: uuid.UUID) -> Role:
    role = await db.get(Role, role_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return role


async def _role_read_for(db: AsyncSession, role: Role) -> RoleRead:
    perms_by_role = await _permissions_by_role(db, [role.id])
    counts = await _user_counts_by_role(db)
    return _role_to_read(role, perms_by_role.get(role.id, []), counts.get(role.id, 0))


async def _validate_permission_ids(
    db: AsyncSession, permission_ids: list[uuid.UUID]
) -> list[Permission]:
    if not permission_ids:
        return []
    permissions = (
        await db.execute(select(Permission).where(Permission.id.in_(permission_ids)))
    ).scalars().all()
    found = {p.id for p in permissions}
    missing = [str(pid) for pid in permission_ids if pid not in found]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown permission id(s): {', '.join(missing)}",
        )
    return list(permissions)


async def create_role(db: AsyncSession, payload: RoleCreate) -> RoleRead:
    existing = (
        await db.execute(select(Role).where(Role.name == payload.name))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="A role with this name already exists"
        )
    await _validate_permission_ids(db, payload.permission_ids)

    role = Role(id=uuid.uuid4(), name=payload.name, description=payload.description, is_active=True)
    db.add(role)
    await db.flush()
    for permission_id in dict.fromkeys(payload.permission_ids):
        db.add(RolePermission(role_id=role.id, permission_id=permission_id))
    await db.commit()
    return await _role_read_for(db, role)


async def update_role(db: AsyncSession, role_id: uuid.UUID, payload: RoleUpdate) -> RoleRead:
    role = await _get_role_orm(db, role_id)

    if payload.name is not None and payload.name != role.name:
        clash = (
            await db.execute(select(Role).where(Role.name == payload.name, Role.id != role.id))
        ).scalar_one_or_none()
        if clash is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A role with this name already exists",
            )
        role.name = payload.name
    if payload.description is not None:
        role.description = payload.description
    if payload.is_active is not None:
        role.is_active = payload.is_active

    if payload.permission_ids is not None:
        await _validate_permission_ids(db, payload.permission_ids)
        existing_links = (
            await db.execute(select(RolePermission).where(RolePermission.role_id == role.id))
        ).scalars().all()
        for link in existing_links:
            await db.delete(link)
        await db.flush()
        for permission_id in dict.fromkeys(payload.permission_ids):
            db.add(RolePermission(role_id=role.id, permission_id=permission_id))

    await db.commit()
    return await _role_read_for(db, role)


# --------------------------------------------------------------------------- #
# Permissions
# --------------------------------------------------------------------------- #


async def list_permissions(
    db: AsyncSession, *, resource: str | None = None
) -> list[PermissionRead]:
    query = select(Permission).order_by(Permission.resource, Permission.action)
    if resource:
        query = query.where(Permission.resource == resource)
    permissions = (await db.execute(query)).scalars().all()
    return [PermissionRead.model_validate(p) for p in permissions]


async def create_permission(db: AsyncSession, payload: PermissionCreate) -> PermissionRead:
    existing = (
        await db.execute(select(Permission).where(Permission.name == payload.name))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A permission with this name already exists",
        )
    permission = Permission(
        id=uuid.uuid4(),
        name=payload.name,
        resource=payload.resource,
        action=payload.action,
        description=payload.description,
    )
    db.add(permission)
    await db.commit()
    await db.refresh(permission)
    return PermissionRead.model_validate(permission)


# --------------------------------------------------------------------------- #
# Role assignment
# --------------------------------------------------------------------------- #


async def _role_summaries_for_user(db: AsyncSession, user_id: uuid.UUID) -> list[RoleSummary]:
    roles = (await _roles_by_user(db, [user_id])).get(user_id, [])
    return [RoleSummary(id=r.id, name=r.name) for r in roles]


async def assign_role(
    db: AsyncSession, user_id: uuid.UUID, role_id: uuid.UUID, *, assigned_by: str
) -> RoleAssignmentResult:
    await _get_user_orm(db, user_id)
    await _get_role_orm(db, role_id)

    existing = (
        await db.execute(
            select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
        )
    ).scalar_one_or_none()
    if existing is None:
        db.add(UserRole(user_id=user_id, role_id=role_id, assigned_by=assigned_by))
        await db.commit()
        detail = "Role assigned"
    else:
        detail = "Role already assigned"

    return RoleAssignmentResult(
        detail=detail,
        user_id=user_id,
        role_id=role_id,
        roles=await _role_summaries_for_user(db, user_id),
    )


async def remove_role(
    db: AsyncSession, user_id: uuid.UUID, role_id: uuid.UUID
) -> RoleAssignmentResult:
    await _get_user_orm(db, user_id)
    await _get_role_orm(db, role_id)

    existing = (
        await db.execute(
            select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id)
        )
    ).scalar_one_or_none()
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This role is not assigned to the user",
        )
    await db.delete(existing)
    await db.commit()

    return RoleAssignmentResult(
        detail="Role removed",
        user_id=user_id,
        role_id=role_id,
        roles=await _role_summaries_for_user(db, user_id),
    )
