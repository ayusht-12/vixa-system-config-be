"""Integration tests for notifications and alert-rule endpoints."""

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.notification import AlertChannel, Notification, NotificationSeverity
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
async def notifications(db_session: AsyncSession, test_user: User) -> list[Notification]:
    rows = [
        Notification(
            id=uuid.uuid4(), user_id=test_user.id, severity=NotificationSeverity.CRITICAL,
            category="anomaly", title="Critical anomaly", body="body", source="anomaly",
            link="/anomalies", is_read=False,
        ),
        Notification(
            id=uuid.uuid4(), user_id=test_user.id, severity=NotificationSeverity.INFO,
            category="config", title="Config staged", body="body", source="config",
            link=None, is_read=True,
        ),
    ]
    db_session.add_all(rows)
    await db_session.commit()
    for row in rows:
        await db_session.refresh(row)
    return rows


@pytest.mark.asyncio
async def test_list_and_unread_count(
    client: AsyncClient, test_user: User, notifications: list[Notification]
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    listing = await client.get("/api/v1/notifications", headers=_auth(token))
    assert listing.status_code == 200
    assert len(listing.json()) == 2

    unread = await client.get(
        "/api/v1/notifications", headers=_auth(token), params={"unread_only": True}
    )
    assert unread.status_code == 200
    assert len(unread.json()) == 1
    assert unread.json()[0]["is_read"] is False

    count = await client.get("/api/v1/notifications/unread-count", headers=_auth(token))
    assert count.status_code == 200
    assert count.json() == {"unread": 1, "total": 2}


@pytest.mark.asyncio
async def test_mark_read_and_read_all(
    client: AsyncClient, test_user: User, notifications: list[Notification]
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    unread_id = next(n.id for n in notifications if not n.is_read)

    read = await client.post(
        f"/api/v1/notifications/{unread_id}/read", headers=_auth(token)
    )
    assert read.status_code == 200
    assert read.json()["is_read"] is True
    assert read.json()["read_at"] is not None

    count = await client.get("/api/v1/notifications/unread-count", headers=_auth(token))
    assert count.json()["unread"] == 0

    all_read = await client.post("/api/v1/notifications/read-all", headers=_auth(token))
    assert all_read.status_code == 200
    assert all_read.json()["marked_read"] == 0  # nothing left unread


@pytest.mark.asyncio
async def test_mark_read_unknown_is_404(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        f"/api/v1/notifications/{uuid.uuid4()}/read", headers=_auth(token)
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_alert_rule_lifecycle(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    payload = {
        "name": "Critical anomaly page",
        "description": "Page on critical anomaly",
        "source": "anomaly",
        "condition": "anomaly.severity == critical",
        "threshold_severity": "critical",
        "channel": "slack",
        "target": "#sec-oncall",
        "is_enabled": True,
    }
    created = await client.post("/api/v1/alert-rules", headers=_auth(token), json=payload)
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["created_by"] == TEST_EMAIL
    assert rule["trigger_count"] == 0
    rule_id = rule["id"]

    listing = await client.get("/api/v1/alert-rules", headers=_auth(token))
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    patched = await client.patch(
        f"/api/v1/alert-rules/{rule_id}",
        headers=_auth(token),
        json={"is_enabled": False, "channel": "email", "target": "sec@nexus"},
    )
    assert patched.status_code == 200
    assert patched.json()["is_enabled"] is False
    assert patched.json()["channel"] == "email"

    deleted = await client.delete(f"/api/v1/alert-rules/{rule_id}", headers=_auth(token))
    assert deleted.status_code == 204

    gone = await client.patch(
        f"/api/v1/alert-rules/{rule_id}", headers=_auth(token), json={"is_enabled": True}
    )
    assert gone.status_code == 404


@pytest.mark.asyncio
async def test_alert_rules_require_admin(client: AsyncClient, non_admin: User) -> None:
    token = await _login(client, non_admin.email, "ViewerPass!123")
    resp = await client.get("/api/v1/alert-rules", headers=_auth(token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_alert_rule_duplicate_name_conflict(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    payload = {
        "name": "Dupe rule",
        "source": "audit",
        "condition": "x",
        "threshold_severity": "warning",
        "channel": "in_app",
        "target": "team",
    }
    first = await client.post("/api/v1/alert-rules", headers=_auth(token), json=payload)
    assert first.status_code == 201
    dup = await client.post("/api/v1/alert-rules", headers=_auth(token), json=payload)
    assert dup.status_code == 409
