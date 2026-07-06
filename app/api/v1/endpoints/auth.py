from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.core.security import create_access_token
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    RefreshRequest,
    ResetPasswordRequest,
    SessionRead,
    TokenResponse,
    UserRead,
)
from app.schemas.common import Message
from app.services.auth_service import (
    authenticate_user,
    change_password,
    create_password_reset_token,
    issue_refresh_token,
    list_active_sessions,
    redeem_refresh_token,
    reset_password,
    revoke_refresh_token,
)

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    user = await authenticate_user(db, credentials.email, credentials.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(subject=str(user.id), extra_claims={"email": user.email})
    refresh_token = await issue_refresh_token(db, user)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    user = await redeem_refresh_token(db, payload.refresh_token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is invalid, expired, or already used",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(subject=str(user.id), extra_claims={"email": user.email})
    refresh_token = await issue_refresh_token(db, user)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", response_model=Message)
async def logout(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> Message:
    await revoke_refresh_token(db, payload.refresh_token)
    return Message(detail="Logged out")


@router.get("/me", response_model=UserRead)
async def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.post("/change-password", response_model=Message)
async def change_own_password(
    payload: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Message:
    await change_password(db, current_user, payload.current_password, payload.new_password)
    return Message(detail="Password changed successfully")


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> ForgotPasswordResponse:
    raw_token = await create_password_reset_token(db, payload.email)
    # Always return the same generic message regardless of whether the email
    # matched an account, to avoid leaking which addresses are registered.
    response = ForgotPasswordResponse(
        detail="If an account exists for that email, a password reset token has been issued."
    )
    # Fail closed: echo the raw token only in explicitly recognised non-prod
    # environments, so an unset, mistyped, or mis-cased ENVIRONMENT never leaks
    # it. The token lets the reset flow be exercised without an email transport.
    if raw_token is not None and settings.ENVIRONMENT.lower() in {"development", "local", "test"}:
        response.reset_token = raw_token
    return response


@router.post("/reset-password", response_model=Message)
async def reset_own_password(
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> Message:
    ok = await reset_password(db, payload.token, payload.new_password)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid, expired, or already used",
        )
    return Message(detail="Password reset successfully")


@router.get("/sessions", response_model=list[SessionRead])
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SessionRead]:
    sessions = await list_active_sessions(db, current_user)
    return [SessionRead.model_validate(session) for session in sessions]
