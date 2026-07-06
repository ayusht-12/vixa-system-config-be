"""Integration tests for the newly added system / auth / tenancy endpoints.

These run against the same Postgres-backed fixtures as the rest of the suite
(see conftest.py) and exercise the endpoints end-to-end through the ASGI app,
covering happy paths and the important authorization / error branches.
"""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.tenancy import Tenant, TenantTier
from app.models.user import User

TEST_EMAIL = "test@nexus.local"
TEST_PASSWORD = "TestPassword!123"


async def _login(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def second_user(db_session: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(),
        email="member@nexus.local",
        display_name="Member User",
        hashed_password=hash_password("MemberPass!123"),
        is_active=True,
        is_admin=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def tenant(db_session: AsyncSession) -> Tenant:
    t = Tenant(
        id=uuid.uuid4(),
        slug="acme",
        org_id="ORG-ACME-01",
        display_name="Acme Corp",
        tier=TenantTier.STANDARD,
        region="us-east-1",
        db_schema_name="tenant_acme",
    )
    db_session.add(t)
    await db_session.commit()
    await db_session.refresh(t)
    return t


# --------------------------------------------------------------------------- #
# System
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_liveness_is_public(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/system/live")
    assert resp.status_code == 200
    assert resp.json()["status"] == "alive"


@pytest.mark.asyncio
async def test_readiness_reports_database_up(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/system/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert any(d["name"] == "database" and d["status"] == "up" for d in body["dependencies"])


@pytest.mark.asyncio
async def test_version_requires_auth(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/system/version")).status_code == 401


@pytest.mark.asyncio
async def test_version_with_auth(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/system/version", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["api_prefix"] == "/api/v1"
    assert body["version"]


@pytest.mark.asyncio
async def test_dependencies_requires_admin(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/system/dependencies")).status_code == 401


@pytest.mark.asyncio
async def test_dependencies_reports_database(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/system/dependencies", headers=_auth(token))
    # 200 when everything is up, 503 if a dependency (e.g. audit key file) is down.
    assert resp.status_code in (200, 503)
    body = resp.json()
    assert any(d["name"] == "database" and d["status"] == "up" for d in body["dependencies"])


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_change_password_flow(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=_auth(token),
        json={"current_password": TEST_PASSWORD, "new_password": "BrandNewPass!1"},
    )
    assert resp.status_code == 200, resp.text
    # Old password no longer works; new one does.
    assert (
        await client.post(
            "/api/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
        )
    ).status_code == 401
    assert (
        await client.post(
            "/api/v1/auth/login",
            json={"email": TEST_EMAIL, "password": "BrandNewPass!1"},
        )
    ).status_code == 200


@pytest.mark.asyncio
async def test_change_password_wrong_current(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/auth/change-password",
        headers=_auth(token),
        json={"current_password": "wrong-one", "new_password": "BrandNewPass!1"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_change_password_requires_auth(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "x", "new_password": "BrandNewPass!1"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_forgot_and_reset_password_flow(client: AsyncClient, test_user: User) -> None:
    forgot = await client.post(
        "/api/v1/auth/forgot-password", json={"email": TEST_EMAIL}
    )
    assert forgot.status_code == 200
    reset_token = forgot.json()["reset_token"]  # surfaced in non-production
    assert reset_token

    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": "ResetPass!123"},
    )
    assert reset.status_code == 200, reset.text
    assert (
        await client.post(
            "/api/v1/auth/login",
            json={"email": TEST_EMAIL, "password": "ResetPass!123"},
        )
    ).status_code == 200
    # Single-use: replaying the same token fails.
    replay = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": "Another!123"},
    )
    assert replay.status_code == 400


@pytest.mark.asyncio
async def test_forgot_password_unknown_email_is_generic(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/forgot-password", json={"email": "nobody@nexus.local"}
    )
    assert resp.status_code == 200
    # No token issued for a non-existent account, but the message is identical.
    assert resp.json()["reset_token"] is None


@pytest.mark.asyncio
async def test_reset_password_invalid_token(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": "not-a-real-token", "new_password": "Whatever!123"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_sessions_lists_active_without_leaking_secrets(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/auth/sessions", headers=_auth(token))
    assert resp.status_code == 200
    sessions = resp.json()
    assert len(sessions) >= 1
    for s in sessions:
        assert set(s.keys()) == {"id", "created_at", "expires_at"}
        assert "token_hash" not in s


@pytest.mark.asyncio
async def test_sessions_requires_auth(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/auth/sessions")).status_code == 401


# --------------------------------------------------------------------------- #
# Tenancy members / usage
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_member_add_list_remove(
    client: AsyncClient, test_user: User, tenant: Tenant, second_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    base = f"/api/v1/tenancy/tenants/{tenant.id}/members"

    add = await client.post(
        base, headers=_auth(token), json={"user_id": str(second_user.id), "role": "analyst"}
    )
    assert add.status_code == 201, add.text
    body = add.json()
    assert body["email"] == "member@nexus.local"
    assert body["role"] == "analyst"

    listed = await client.get(base, headers=_auth(token))
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    removed = await client.delete(
        f"{base}/{second_user.id}", headers=_auth(token)
    )
    assert removed.status_code == 200
    assert (await client.get(base, headers=_auth(token))).json() == []


@pytest.mark.asyncio
async def test_member_add_duplicate_conflicts(
    client: AsyncClient, test_user: User, tenant: Tenant, second_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    base = f"/api/v1/tenancy/tenants/{tenant.id}/members"
    payload = {"user_id": str(second_user.id), "role": "viewer"}
    assert (await client.post(base, headers=_auth(token), json=payload)).status_code == 201
    dup = await client.post(base, headers=_auth(token), json=payload)
    assert dup.status_code == 409


@pytest.mark.asyncio
async def test_member_add_unknown_user_404(
    client: AsyncClient, test_user: User, tenant: Tenant
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    base = f"/api/v1/tenancy/tenants/{tenant.id}/members"
    resp = await client.post(
        base, headers=_auth(token), json={"user_id": str(uuid.uuid4()), "role": "viewer"}
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_member_list_unknown_tenant_404(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get(
        f"/api/v1/tenancy/tenants/{uuid.uuid4()}/members", headers=_auth(token)
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_members_require_auth(client: AsyncClient, tenant: Tenant) -> None:
    assert (
        await client.get(f"/api/v1/tenancy/tenants/{tenant.id}/members")
    ).status_code == 401


@pytest.mark.asyncio
async def test_tenant_usage_summary(
    client: AsyncClient, test_user: User, tenant: Tenant, second_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    base = f"/api/v1/tenancy/tenants/{tenant.id}/members"
    await client.post(
        base, headers=_auth(token), json={"user_id": str(second_user.id), "role": "owner"}
    )

    usage = await client.get(
        f"/api/v1/tenancy/tenants/{tenant.id}/usage", headers=_auth(token)
    )
    assert usage.status_code == 200
    body = usage.json()
    assert body["slug"] == "acme"
    assert body["member_count"] == 1
    assert "isolation_score" in body


# --------------------------------------------------------------------------- #
# Authorization: admin-gated endpoints reject authenticated non-admins (403)
# --------------------------------------------------------------------------- #

MEMBER_EMAIL = "member@nexus.local"
MEMBER_PASSWORD = "MemberPass!123"


@pytest.mark.asyncio
async def test_members_forbidden_for_non_admin(
    client: AsyncClient, tenant: Tenant, second_user: User
) -> None:
    token = await _login(client, MEMBER_EMAIL, MEMBER_PASSWORD)
    base = f"/api/v1/tenancy/tenants/{tenant.id}/members"
    assert (await client.get(base, headers=_auth(token))).status_code == 403
    assert (
        await client.post(
            base, headers=_auth(token), json={"user_id": str(second_user.id), "role": "viewer"}
        )
    ).status_code == 403
    assert (
        await client.delete(f"{base}/{second_user.id}", headers=_auth(token))
    ).status_code == 403


@pytest.mark.asyncio
async def test_dependencies_forbidden_for_non_admin(
    client: AsyncClient, second_user: User
) -> None:
    token = await _login(client, MEMBER_EMAIL, MEMBER_PASSWORD)
    assert (
        await client.get("/api/v1/system/dependencies", headers=_auth(token))
    ).status_code == 403


# --------------------------------------------------------------------------- #
# Auth: password change / reset revoke all refresh tokens (session invalidation)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_change_password_revokes_sessions(client: AsyncClient, test_user: User) -> None:
    login = await client.post(
        "/api/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    access = login.json()["access_token"]
    refresh = login.json()["refresh_token"]

    changed = await client.post(
        "/api/v1/auth/change-password",
        headers=_auth(access),
        json={"current_password": TEST_PASSWORD, "new_password": "BrandNewPass!1"},
    )
    assert changed.status_code == 200

    # The pre-change refresh token can no longer mint access tokens...
    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert replay.status_code == 401
    # ...and it no longer appears among active sessions.
    sessions = await client.get("/api/v1/auth/sessions", headers=_auth(access))
    assert sessions.status_code == 200
    assert sessions.json() == []


@pytest.mark.asyncio
async def test_reset_password_revokes_sessions(client: AsyncClient, test_user: User) -> None:
    login = await client.post(
        "/api/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    refresh = login.json()["refresh_token"]

    forgot = await client.post("/api/v1/auth/forgot-password", json={"email": TEST_EMAIL})
    reset_token = forgot.json()["reset_token"]
    assert reset_token

    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": "ResetPass!123"},
    )
    assert reset.status_code == 200

    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert replay.status_code == 401


# --------------------------------------------------------------------------- #
# Auth: /sessions is scoped per user and excludes revoked tokens
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_sessions_are_scoped_per_user(
    client: AsyncClient, test_user: User, second_user: User
) -> None:
    admin_token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    member_token = await _login(client, MEMBER_EMAIL, MEMBER_PASSWORD)

    admin_sessions = (
        await client.get("/api/v1/auth/sessions", headers=_auth(admin_token))
    ).json()
    member_sessions = (
        await client.get("/api/v1/auth/sessions", headers=_auth(member_token))
    ).json()

    # Each user logged in exactly once and sees only their own single session;
    # dropping the user_id filter would return both tokens to each caller.
    assert len(admin_sessions) == 1
    assert len(member_sessions) == 1
    assert {s["id"] for s in admin_sessions}.isdisjoint({s["id"] for s in member_sessions})


@pytest.mark.asyncio
async def test_sessions_excludes_revoked(client: AsyncClient, test_user: User) -> None:
    first = await client.post(
        "/api/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    first_refresh = first.json()["refresh_token"]
    second = await client.post(
        "/api/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    second_access = second.json()["access_token"]

    before = (await client.get("/api/v1/auth/sessions", headers=_auth(second_access))).json()
    assert len(before) == 2

    # Logging out revokes the first session's refresh token.
    await client.post("/api/v1/auth/logout", json={"refresh_token": first_refresh})

    after = (await client.get("/api/v1/auth/sessions", headers=_auth(second_access))).json()
    assert len(after) == 1


# --------------------------------------------------------------------------- #
# Tenancy members: remaining 404 branches
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_remove_member_not_found(
    client: AsyncClient, test_user: User, tenant: Tenant, second_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    # second_user was never added to this tenant.
    resp = await client.delete(
        f"/api/v1/tenancy/tenants/{tenant.id}/members/{second_user.id}", headers=_auth(token)
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_add_member_unknown_tenant_404(
    client: AsyncClient, test_user: User, second_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        f"/api/v1/tenancy/tenants/{uuid.uuid4()}/members",
        headers=_auth(token),
        json={"user_id": str(second_user.id), "role": "viewer"},
    )
    assert resp.status_code == 404
