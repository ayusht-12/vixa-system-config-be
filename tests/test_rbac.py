"""Integration tests for the RBAC administration endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.rbac import Permission
from app.models.user import User

TEST_EMAIL = "test@nexus.local"
TEST_PASSWORD = "TestPassword!123"


async def _login(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def non_admin(db_session: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(),
        email="viewer@nexus.local",
        display_name="Viewer",
        hashed_password=hash_password("ViewerPass!123"),
        is_active=True,
        is_admin=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def permissions(db_session: AsyncSession) -> list[Permission]:
    rows = [
        Permission(id=uuid.uuid4(), name="tenants:read", resource="tenants", action="read"),
        Permission(id=uuid.uuid4(), name="tenants:create", resource="tenants", action="create"),
        Permission(id=uuid.uuid4(), name="config:read", resource="config", action="read"),
    ]
    db_session.add_all(rows)
    await db_session.commit()
    for row in rows:
        await db_session.refresh(row)
    return rows


@pytest.mark.asyncio
async def test_rbac_requires_admin(client: AsyncClient, non_admin: User) -> None:
    token = await _login(client, non_admin.email, "ViewerPass!123")
    resp = await client.get("/api/v1/rbac/users", headers=_auth(token))
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_create_user_hides_password_and_lists(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/rbac/users",
        headers=_auth(token),
        json={
            "email": "newby@nexus.local",
            "display_name": "New Person",
            "password": "SuperSecret!99",
            "is_admin": False,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == "newby@nexus.local"
    assert body["is_active"] is True
    assert body["roles"] == []
    # No password material may ever be surfaced.
    assert "password" not in body
    assert "hashed_password" not in body

    listing = await client.get("/api/v1/rbac/users", headers=_auth(token))
    assert listing.status_code == 200
    emails = {u["email"] for u in listing.json()}
    assert {"test@nexus.local", "newby@nexus.local"} <= emails


@pytest.mark.asyncio
async def test_create_user_duplicate_email_conflict(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/rbac/users",
        headers=_auth(token),
        json={"email": TEST_EMAIL, "display_name": "Clash", "password": "Whatever!123"},
    )
    assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
async def test_update_activate_deactivate_user(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    created = await client.post(
        "/api/v1/rbac/users",
        headers=_auth(token),
        json={"email": "flip@nexus.local", "display_name": "Flip", "password": "FlipPass!123"},
    )
    user_id = created.json()["id"]

    patched = await client.patch(
        f"/api/v1/rbac/users/{user_id}",
        headers=_auth(token),
        json={"display_name": "Flipper", "is_admin": True},
    )
    assert patched.status_code == 200
    assert patched.json()["display_name"] == "Flipper"
    assert patched.json()["is_admin"] is True

    deactivated = await client.post(
        f"/api/v1/rbac/users/{user_id}/deactivate", headers=_auth(token)
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["is_active"] is False

    activated = await client.post(
        f"/api/v1/rbac/users/{user_id}/activate", headers=_auth(token)
    )
    assert activated.status_code == 200
    assert activated.json()["is_active"] is True


@pytest.mark.asyncio
async def test_get_unknown_user_404(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get(f"/api/v1/rbac/users/{uuid.uuid4()}", headers=_auth(token))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_role_with_permissions_and_update(
    client: AsyncClient, test_user: User, permissions: list[Permission]
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    perm_ids = [str(permissions[0].id), str(permissions[2].id)]
    created = await client.post(
        "/api/v1/rbac/roles",
        headers=_auth(token),
        json={"name": "Operator", "description": "Ops", "permission_ids": perm_ids},
    )
    assert created.status_code == 201, created.text
    role = created.json()
    assert role["permission_count"] == 2
    assert role["user_count"] == 0
    assert {p["name"] for p in role["permissions"]} == {"tenants:read", "config:read"}

    # Replace the permission set wholesale.
    updated = await client.patch(
        f"/api/v1/rbac/roles/{role['id']}",
        headers=_auth(token),
        json={"permission_ids": [str(permissions[1].id)]},
    )
    assert updated.status_code == 200
    assert updated.json()["permission_count"] == 1
    assert updated.json()["permissions"][0]["name"] == "tenants:create"


@pytest.mark.asyncio
async def test_create_role_duplicate_name_conflict(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    first = await client.post(
        "/api/v1/rbac/roles", headers=_auth(token), json={"name": "Auditor"}
    )
    assert first.status_code == 201
    dup = await client.post(
        "/api/v1/rbac/roles", headers=_auth(token), json={"name": "Auditor"}
    )
    assert dup.status_code == 409


@pytest.mark.asyncio
async def test_list_permissions(
    client: AsyncClient, test_user: User, permissions: list[Permission]
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/rbac/permissions", headers=_auth(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 3
    filtered = await client.get(
        "/api/v1/rbac/permissions?resource=tenants", headers=_auth(token)
    )
    assert {p["name"] for p in filtered.json()} == {"tenants:read", "tenants:create"}


@pytest.mark.asyncio
async def test_assign_and_remove_role(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    user = await client.post(
        "/api/v1/rbac/users",
        headers=_auth(token),
        json={"email": "assignee@nexus.local", "display_name": "Assignee", "password": "AssignPass!1"},
    )
    user_id = user.json()["id"]
    role = await client.post(
        "/api/v1/rbac/roles", headers=_auth(token), json={"name": "Analyst"}
    )
    role_id = role.json()["id"]

    assigned = await client.post(
        f"/api/v1/rbac/users/{user_id}/roles/{role_id}", headers=_auth(token)
    )
    assert assigned.status_code == 200
    assert assigned.json()["detail"] == "Role assigned"
    assert {r["name"] for r in assigned.json()["roles"]} == {"Analyst"}

    # Idempotent re-assign.
    again = await client.post(
        f"/api/v1/rbac/users/{user_id}/roles/{role_id}", headers=_auth(token)
    )
    assert again.status_code == 200
    assert again.json()["detail"] == "Role already assigned"

    # Role now reports one user.
    roles = await client.get("/api/v1/rbac/roles", headers=_auth(token))
    analyst = next(r for r in roles.json() if r["name"] == "Analyst")
    assert analyst["user_count"] == 1

    removed = await client.delete(
        f"/api/v1/rbac/users/{user_id}/roles/{role_id}", headers=_auth(token)
    )
    assert removed.status_code == 200
    assert removed.json()["roles"] == []

    # Removing a non-assigned role is a 404.
    removed_again = await client.delete(
        f"/api/v1/rbac/users/{user_id}/roles/{role_id}", headers=_auth(token)
    )
    assert removed_again.status_code == 404
