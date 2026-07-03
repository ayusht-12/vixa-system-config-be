import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import generate_refresh_token, hash_refresh_token, verify_password
from app.models.user import RefreshToken, User


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
