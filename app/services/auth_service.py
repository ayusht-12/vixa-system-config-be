import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.models.user import PasswordResetToken, RefreshToken, User

# Password reset tokens are short-lived by design; the raw token grants a
# password change, so its usable window is kept small.
PASSWORD_RESET_EXPIRE_MINUTES = 60


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email.lower()))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def issue_refresh_token(db: AsyncSession, user: User) -> str:
    raw_token = generate_refresh_token()
    db.add(
        RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=hash_refresh_token(raw_token),
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
    )
    await db.commit()
    return raw_token


async def redeem_refresh_token(db: AsyncSession, raw_token: str) -> User | None:
    """Validate a refresh token and rotate it: the presented token is revoked
    (single use) and, if it was valid, a fresh one takes its place. Rotation
    means a stolen-and-replayed token is only ever usable once before the
    legitimate holder's next refresh silently invalidates it.
    """
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw_token))
    )
    token = result.scalar_one_or_none()
    if token is None or token.revoked_at is not None:
        return None
    if _as_aware_utc(token.expires_at) < datetime.now(timezone.utc):
        return None

    token.revoked_at = datetime.now(timezone.utc)
    user = await db.get(User, token.user_id)
    await db.commit()

    if user is None or not user.is_active:
        return None
    return user


async def revoke_refresh_token(db: AsyncSession, raw_token: str) -> None:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw_token))
    )
    token = result.scalar_one_or_none()
    if token is not None and token.revoked_at is None:
        token.revoked_at = datetime.now(timezone.utc)
        await db.commit()


async def _revoke_all_user_refresh_tokens(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Revoke every still-active refresh token for a user. Used on password
    change / reset so credentials that may be compromised can no longer mint
    new access tokens — the user must re-authenticate everywhere. Does not
    commit; the caller commits as part of the surrounding transaction."""
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
        )
    )
    now = datetime.now(timezone.utc)
    for token in result.scalars().all():
        token.revoked_at = now


async def change_password(
    db: AsyncSession, user: User, current_password: str, new_password: str
) -> None:
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    user.hashed_password = hash_password(new_password)
    await _revoke_all_user_refresh_tokens(db, user.id)
    await db.commit()


async def create_password_reset_token(db: AsyncSession, email: str) -> str | None:
    """Issue a single-use password reset token. Returns the raw token when a
    matching active user exists, otherwise None. Callers must not reveal which
    case occurred to unauthenticated clients (avoid account enumeration)."""
    result = await db.execute(select(User).where(User.email == email.lower()))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        return None
    raw_token = generate_refresh_token()
    db.add(
        PasswordResetToken(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=hash_refresh_token(raw_token),
            expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=PASSWORD_RESET_EXPIRE_MINUTES),
        )
    )
    await db.commit()
    return raw_token


async def reset_password(db: AsyncSession, raw_token: str, new_password: str) -> bool:
    """Consume a reset token and set a new password. Returns False when the
    token is unknown, already used, expired, or the user is inactive."""
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == hash_refresh_token(raw_token)
        )
    )
    token = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if token is None or token.used_at is not None or token.expires_at < now:
        return False
    user = await db.get(User, token.user_id)
    if user is None or not user.is_active:
        return False
    user.hashed_password = hash_password(new_password)
    token.used_at = now
    await _revoke_all_user_refresh_tokens(db, user.id)
    await db.commit()
    return True


async def list_active_sessions(db: AsyncSession, user: User) -> list[RefreshToken]:
    """Active sessions are the user's refresh tokens that are neither revoked
    nor expired. Only non-sensitive metadata is exposed to callers — never the
    token hash."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(RefreshToken)
        .where(
            RefreshToken.user_id == user.id,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > now,
        )
        .order_by(RefreshToken.created_at.desc())
    )
    return list(result.scalars().all())
