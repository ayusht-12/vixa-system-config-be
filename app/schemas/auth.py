import uuid
from datetime import datetime

from pydantic import BaseModel, Field

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


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3)


class ForgotPasswordResponse(BaseModel):
    detail: str
    # The raw reset token is surfaced only in non-production environments so the
    # flow is testable without an email transport. It is never returned in
    # production, where the token is expected to be delivered out-of-band.
    reset_token: str | None = None


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=128)


class SessionRead(ORMModel):
    id: uuid.UUID
    created_at: datetime
    expires_at: datetime
