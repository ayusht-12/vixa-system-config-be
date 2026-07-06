"""Integration tests for the versioned Configuration document endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
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


async def _create(client: AsyncClient, token: str, name: str, payload: dict, **extra) -> dict:
    resp = await client.post(
        "/api/v1/config/configurations",
        headers=_auth(token),
        json={"name": name, "payload": payload, **extra},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


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


# --------------------------------------------------------------------------- #
# Create / list / get
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_create_configuration(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    body = await _create(client, token, "engine-runtime", {"workers": 8})
    assert body["version"] == 1
    assert body["status"] == "draft"
    assert body["name"] == "engine-runtime"
    assert body["payload"] == {"workers": 8}
    assert len(body["checksum"]) == 64
    assert body["is_deleted"] is False


@pytest.mark.asyncio
async def test_create_duplicate_name_conflicts(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    await _create(client, token, "cfg-dup", {"a": 1})
    resp = await client.post(
        "/api/v1/config/configurations",
        headers=_auth(token),
        json={"name": "cfg-dup", "payload": {"a": 2}},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_create_empty_payload_422(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/config/configurations",
        headers=_auth(token),
        json={"name": "cfg-empty", "payload": {}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_requires_admin(client: AsyncClient, non_admin: User) -> None:
    token = await _login(client, "viewer@nexus.local", "ViewerPass!123")
    resp = await client.post(
        "/api/v1/config/configurations",
        headers=_auth(token),
        json={"name": "cfg-viewer", "payload": {"a": 1}},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_and_status_filter(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    a = await _create(client, token, "cfg-a", {"a": 1})
    await _create(client, token, "cfg-b", {"b": 1})
    await client.post(
        f"/api/v1/config/configurations/{a['id']}/activate", headers=_auth(token)
    )

    all_list = await client.get("/api/v1/config/configurations", headers=_auth(token))
    assert all_list.status_code == 200
    assert len(all_list.json()) == 2

    active = await client.get(
        "/api/v1/config/configurations?status=active", headers=_auth(token)
    )
    assert [c["name"] for c in active.json()] == ["cfg-a"]

    by_name = await client.get(
        "/api/v1/config/configurations?name=cfg-b", headers=_auth(token)
    )
    assert len(by_name.json()) == 1


@pytest.mark.asyncio
async def test_get_and_404(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    body = await _create(client, token, "cfg-get", {"a": 1})
    ok = await client.get(
        f"/api/v1/config/configurations/{body['id']}", headers=_auth(token)
    )
    assert ok.status_code == 200
    missing = await client.get(
        f"/api/v1/config/configurations/{uuid.uuid4()}", headers=_auth(token)
    )
    assert missing.status_code == 404


# --------------------------------------------------------------------------- #
# Versioning: patch (successor) / history / latest
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_patch_creates_successor_and_history(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-ver", {"a": 1})

    v2 = await client.patch(
        f"/api/v1/config/configurations/{v1['id']}",
        headers=_auth(token),
        json={"payload": {"a": 2}},
    )
    assert v2.status_code == 200, v2.text
    assert v2.json()["version"] == 2
    assert v2.json()["status"] == "draft"

    v3 = await client.patch(
        f"/api/v1/config/configurations/{v2.json()['id']}",
        headers=_auth(token),
        json={"payload": {"a": 3}},
    )
    assert v3.json()["version"] == 3

    history = await client.get(
        f"/api/v1/config/configurations/{v1['id']}/history", headers=_auth(token)
    )
    assert history.status_code == 200
    versions = [c["version"] for c in history.json()]
    assert versions == [3, 2, 1]


@pytest.mark.asyncio
async def test_latest_and_latest_active(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-latest", {"a": 1})
    v2 = await client.patch(
        f"/api/v1/config/configurations/{v1['id']}",
        headers=_auth(token),
        json={"payload": {"a": 2}},
    )

    latest = await client.get(
        "/api/v1/config/configurations/latest?name=cfg-latest", headers=_auth(token)
    )
    assert latest.status_code == 200
    assert latest.json()["version"] == 2

    # No active version yet.
    none_active = await client.get(
        "/api/v1/config/configurations/latest-active?name=cfg-latest", headers=_auth(token)
    )
    assert none_active.status_code == 404

    await client.post(
        f"/api/v1/config/configurations/{v1['id']}/activate", headers=_auth(token)
    )
    active = await client.get(
        "/api/v1/config/configurations/latest-active?name=cfg-latest", headers=_auth(token)
    )
    assert active.status_code == 200
    assert active.json()["version"] == 1


@pytest.mark.asyncio
async def test_latest_unknown_name_404(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get(
        "/api/v1/config/configurations/latest?name=does-not-exist", headers=_auth(token)
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Lifecycle: activate / archive / rollback
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_activate_archives_previous(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-life", {"a": 1})
    await client.post(
        f"/api/v1/config/configurations/{v1['id']}/activate", headers=_auth(token)
    )
    v2 = await client.patch(
        f"/api/v1/config/configurations/{v1['id']}",
        headers=_auth(token),
        json={"payload": {"a": 2}},
    )
    v2_id = v2.json()["id"]
    activated = await client.post(
        f"/api/v1/config/configurations/{v2_id}/activate", headers=_auth(token)
    )
    assert activated.status_code == 200
    assert activated.json()["status"] == "active"

    # v1 is now archived.
    old = await client.get(
        f"/api/v1/config/configurations/{v1['id']}", headers=_auth(token)
    )
    assert old.json()["status"] == "archived"


@pytest.mark.asyncio
async def test_activate_already_active_conflicts(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-act2", {"a": 1})
    await client.post(
        f"/api/v1/config/configurations/{v1['id']}/activate", headers=_auth(token)
    )
    again = await client.post(
        f"/api/v1/config/configurations/{v1['id']}/activate", headers=_auth(token)
    )
    assert again.status_code == 409


@pytest.mark.asyncio
async def test_archive(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-arch", {"a": 1})
    archived = await client.post(
        f"/api/v1/config/configurations/{v1['id']}/archive", headers=_auth(token)
    )
    assert archived.status_code == 200
    assert archived.json()["status"] == "archived"
    again = await client.post(
        f"/api/v1/config/configurations/{v1['id']}/archive", headers=_auth(token)
    )
    assert again.status_code == 409


@pytest.mark.asyncio
async def test_rollback_creates_and_activates_new_version(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-roll", {"setting": "original"})
    await client.post(
        f"/api/v1/config/configurations/{v1['id']}/activate", headers=_auth(token)
    )
    v2 = await client.patch(
        f"/api/v1/config/configurations/{v1['id']}",
        headers=_auth(token),
        json={"payload": {"setting": "changed"}},
    )
    await client.post(
        f"/api/v1/config/configurations/{v2.json()['id']}/activate", headers=_auth(token)
    )

    rolled = await client.post(
        f"/api/v1/config/configurations/{v1['id']}/rollback", headers=_auth(token)
    )
    assert rolled.status_code == 200, rolled.text
    body = rolled.json()
    assert body["version"] == 3
    assert body["status"] == "active"
    assert body["payload"] == {"setting": "original"}

    # The previously-active v2 is archived.
    v2_now = await client.get(
        f"/api/v1/config/configurations/{v2.json()['id']}", headers=_auth(token)
    )
    assert v2_now.json()["status"] == "archived"


# --------------------------------------------------------------------------- #
# Delete (soft)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_soft_delete(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-del", {"a": 1})

    deleted = await client.delete(
        f"/api/v1/config/configurations/{v1['id']}", headers=_auth(token)
    )
    assert deleted.status_code == 200

    gone = await client.get(
        f"/api/v1/config/configurations/{v1['id']}", headers=_auth(token)
    )
    assert gone.status_code == 404

    listed = await client.get("/api/v1/config/configurations", headers=_auth(token))
    assert listed.json() == []

    with_deleted = await client.get(
        "/api/v1/config/configurations?include_deleted=true", headers=_auth(token)
    )
    assert len(with_deleted.json()) == 1
    assert with_deleted.json()[0]["is_deleted"] is True


@pytest.mark.asyncio
async def test_delete_active_conflicts(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-del2", {"a": 1})
    await client.post(
        f"/api/v1/config/configurations/{v1['id']}/activate", headers=_auth(token)
    )
    resp = await client.delete(
        f"/api/v1/config/configurations/{v1['id']}", headers=_auth(token)
    )
    assert resp.status_code == 409


# --------------------------------------------------------------------------- #
# Compare
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_compare_versions(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-cmp", {"a": 1, "b": 2})
    v2 = await client.patch(
        f"/api/v1/config/configurations/{v1['id']}",
        headers=_auth(token),
        json={"payload": {"a": 1, "b": 3, "c": 4}},
    )
    cmp = await client.get(
        f"/api/v1/config/configurations/{v2.json()['id']}/compare/1", headers=_auth(token)
    )
    assert cmp.status_code == 200, cmp.text
    body = cmp.json()
    assert body["base_version"] == 2
    assert body["other_version"] == 1
    assert body["added"] == {}
    assert body["removed"] == {"c": 4}
    assert body["changed"] == {"b": {"from": 3, "to": 2}}
    assert body["unchanged_count"] == 1


@pytest.mark.asyncio
async def test_compare_unknown_version_404(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    v1 = await _create(client, token, "cfg-cmp2", {"a": 1})
    resp = await client.get(
        f"/api/v1/config/configurations/{v1['id']}/compare/99", headers=_auth(token)
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Validate / export / import
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_validate_ok_and_errors(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    ok = await client.post(
        "/api/v1/config/configurations/validate",
        headers=_auth(token),
        json={"payload": {"a": 1}},
    )
    assert ok.status_code == 200
    assert ok.json()["valid"] is True
    assert ok.json()["checksum"] is not None

    bad = await client.post(
        "/api/v1/config/configurations/validate",
        headers=_auth(token),
        json={"payload": {}, "sensitive_keys": ["missing"]},
    )
    assert bad.status_code == 200
    assert bad.json()["valid"] is False
    assert bad.json()["errors"]
    assert bad.json()["checksum"] is None


@pytest.mark.asyncio
async def test_export_metadata_only(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    await _create(client, token, "cfg-exp", {"secret_value": "xyz"})
    resp = await client.get("/api/v1/config/configurations/export", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    item = body["items"][0]
    assert item["name"] == "cfg-exp"
    # Export must not carry the payload (which may hold secrets).
    assert "payload" not in item


@pytest.mark.asyncio
async def test_import_bulk(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/config/configurations/import",
        headers=_auth(token),
        json={
            "items": [
                {"name": "imp-a", "payload": {"x": 1}},
                {"name": "imp-a", "payload": {"x": 2}},
                {"name": "imp-bad", "payload": {}},
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["imported"] == 2
    assert body["skipped"] == 1
    # Two rows for imp-a get versions 1 and 2.
    imp_a_versions = sorted(r["version"] for r in body["rows"] if r["name"] == "imp-a")
    assert imp_a_versions == [1, 2]


@pytest.mark.asyncio
async def test_import_requires_admin(client: AsyncClient, non_admin: User) -> None:
    token = await _login(client, "viewer@nexus.local", "ViewerPass!123")
    resp = await client.post(
        "/api/v1/config/configurations/import",
        headers=_auth(token),
        json={"items": [{"name": "imp-x", "payload": {"a": 1}}]},
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Sensitive masking & auth
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_sensitive_values_are_masked(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    body = await _create(
        client,
        token,
        "cfg-secret",
        {"client_secret": "topsecret", "host": "engine.internal"},
        sensitive_keys=["client_secret"],
    )
    assert body["payload"]["client_secret"] != "topsecret"
    assert body["payload"]["host"] == "engine.internal"
    assert body["sensitive_keys"] == ["client_secret"]


@pytest.mark.asyncio
async def test_configurations_require_auth(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/config/configurations")).status_code == 401
    assert (await client.get("/api/v1/config/configurations/export")).status_code == 401
