import uuid

from pydantic import BaseModel

from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    # Plain str, not EmailStr: this is a lookup key against User.email (also
    # a plain string column), not a field we need RFC-validated — seeded
    # demo accounts like "admin@nexus" have no TLD and would otherwise be
    # rejected before ever reaching the password check.
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class UserRead(ORMModel):
    id: uuid.UUID
    email: str
    display_name: str
    is_admin: bool
