import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import hash_refresh_token
from app.models.user import RefreshToken
from app.models.user import User
from app.services.auth_service import issue_refresh_token, redeem_refresh_token


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, test_user: User) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@nexus.local", "password": "TestPassword!123"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    assert len(body["access_token"]) > 20


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, test_user: User) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@nexus.local", "password": "wrong-password"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@nexus.local", "password": "whatever"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_requires_token(client: AsyncClient) -> None:
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_returns_current_user(client: AsyncClient, test_user: User) -> None:
    login_response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@nexus.local", "password": "TestPassword!123"},
    )
    token = login_response.json()["access_token"]

    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "test@nexus.local"
    assert body["is_admin"] is True


@pytest.mark.asyncio
async def test_me_rejects_garbage_token(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_production_rejects_insecure_settings() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(ENVIRONMENT="production", DEBUG=False)

    with pytest.raises(ValidationError, match="DEBUG"):
        Settings(ENVIRONMENT="production", DEBUG=True, SECRET_KEY="a-secure-production-secret")


@pytest.mark.asyncio
async def test_jwt_algorithm_is_normalized_and_restricted() -> None:
    assert Settings(JWT_ALGORITHM="hs512").JWT_ALGORITHM == "HS512"

    with pytest.raises(ValidationError, match="JWT_ALGORITHM"):
        Settings(JWT_ALGORITHM="none")


@pytest.mark.asyncio
async def test_refresh_token_is_stored_hashed_and_rotates(
    db_session: AsyncSession, test_user: User
) -> None:
    raw_token = await issue_refresh_token(db_session, test_user)

    result = await db_session.execute(select(RefreshToken))
    stored_token = result.scalar_one()

    assert stored_token.token_hash == hash_refresh_token(raw_token)
    assert stored_token.token_hash != raw_token

    user = await redeem_refresh_token(db_session, raw_token)
    assert user is not None
    assert user.id == test_user.id

    await db_session.refresh(stored_token)
    assert stored_token.revoked_at is not None


@pytest.mark.asyncio
async def test_refresh_token_accepts_naive_database_expiry(
    db_session: AsyncSession, test_user: User
) -> None:
    raw_token = "refresh-token-with-naive-expiry"
    db_session.add(
        RefreshToken(
            id=uuid.uuid4(),
            user_id=test_user.id,
            token_hash=hash_refresh_token(raw_token),
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1),
        )
    )
    await db_session.commit()

    user = await redeem_refresh_token(db_session, raw_token)

    assert user is not None
    assert user.id == test_user.id
