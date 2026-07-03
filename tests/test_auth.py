import pytest
from httpx import AsyncClient

from app.models.user import User


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
