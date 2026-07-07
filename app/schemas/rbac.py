import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


# --------------------------------------------------------------------------- #
# Permissions
# --------------------------------------------------------------------------- #


class PermissionRead(ORMModel):
    id: uuid.UUID
    name: str
    description: str | None
    resource: str
    action: str


class PermissionCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    resource: str = Field(min_length=1, max_length=60)
    action: str = Field(min_length=1, max_length=60)
    description: str | None = Field(default=None, max_length=500)


# --------------------------------------------------------------------------- #
# Roles
# --------------------------------------------------------------------------- #


class RoleRead(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    is_active: bool
    permission_count: int
    user_count: int
    permissions: list[PermissionRead]
    created_at: datetime


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    permission_ids: list[uuid.UUID] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    is_active: bool | None = None
    # When provided, replaces the role's permission set wholesale.
    permission_ids: list[uuid.UUID] | None = None


# --------------------------------------------------------------------------- #
# Users (administration view — never exposes password material)
# --------------------------------------------------------------------------- #


class RoleSummary(BaseModel):
    id: uuid.UUID
    name: str


class RbacUserRead(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    is_active: bool
    is_admin: bool
    created_at: datetime
    roles: list[RoleSummary]


class RbacUserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=128)
    is_admin: bool = False
    role_ids: list[uuid.UUID] = Field(default_factory=list)


class RbacUserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    is_admin: bool | None = None


class RoleAssignmentResult(BaseModel):
    detail: str
    user_id: uuid.UUID
    role_id: uuid.UUID
    roles: list[RoleSummary]
