"""Integration tests for the gap endpoints added to existing modules:
dashboard KPI overviews, anomaly history/bulk/trends/types, and audit
entry/export/integrity-status.
"""

import pytest
from httpx import AsyncClient

from app.models.user import User

TEST_EMAIL = "test@nexus.local"
TEST_PASSWORD = "TestPassword!123"


async def _login(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _create_anomaly(client: AsyncClient, token: str, **overrides) -> dict:
    payload = {
        "category": "PRIV_ESCALATION",
        "score": 0.95,
        "title": "Priv escalation",
        "description": "svc assumed admin role",
    }
    payload.update(overrides)
    resp = await client.post("/api/v1/anomalies/events", headers=_auth(token), json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# --------------------------------------------------------------------------- #
# Dashboard KPI overviews
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_dashboard_overviews(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)

    anomaly = await client.get("/api/v1/dashboard/anomaly-overview", headers=_auth(token))
    assert anomaly.status_code == 200
    for key in ("open_count", "critical_open", "events_last_24h", "open_by_severity"):
        assert key in anomaly.json()

    compliance = await client.get("/api/v1/dashboard/compliance-overview", headers=_auth(token))
    assert compliance.status_code == 200
    assert "overall_score" in compliance.json()

    security = await client.get("/api/v1/dashboard/security-overview", headers=_auth(token))
    assert security.status_code == 200
    assert security.json()["total_keys"] == 0  # empty test DB


@pytest.mark.asyncio
async def test_anomaly_overview_counts_open(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    await _create_anomaly(client, token)
    overview = await client.get("/api/v1/dashboard/anomaly-overview", headers=_auth(token))
    body = overview.json()
    assert body["open_count"] == 1
    assert body["critical_open"] == 1
    assert body["events_last_24h"] == 1


# --------------------------------------------------------------------------- #
# Anomaly history / bulk / trends / types
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_anomaly_history_tracks_lifecycle(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    event = await _create_anomaly(client, token)
    event_id = event["id"]

    # Creation writes one audit entry.
    history = await client.get(
        f"/api/v1/anomalies/events/{event_id}/history", headers=_auth(token)
    )
    assert history.status_code == 200
    assert len(history.json()) == 1
    assert history.json()[0]["subtype"] == "ANOMALY_CREATED"

    # A status transition adds another.
    await client.post(f"/api/v1/anomalies/events/{event_id}/resolve", headers=_auth(token))
    history2 = await client.get(
        f"/api/v1/anomalies/events/{event_id}/history", headers=_auth(token)
    )
    assert len(history2.json()) == 2
    assert history2.json()[-1]["new_status"] == "resolved"


@pytest.mark.asyncio
async def test_anomaly_history_unknown_404(client: AsyncClient, test_user: User) -> None:
    import uuid

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get(
        f"/api/v1/anomalies/events/{uuid.uuid4()}/history", headers=_auth(token)
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_bulk_acknowledge_and_resolve(client: AsyncClient, test_user: User) -> None:
    import uuid

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    a = await _create_anomaly(client, token, title="a")
    b = await _create_anomaly(client, token, title="b")
    missing = str(uuid.uuid4())

    ack = await client.post(
        "/api/v1/anomalies/bulk-acknowledge",
        headers=_auth(token),
        json={"event_ids": [a["id"], b["id"], missing]},
    )
    assert ack.status_code == 200, ack.text
    assert ack.json()["new_status"] == "investigating"
    assert ack.json()["updated"] == 2
    assert ack.json()["not_found_ids"] == [missing]

    resolve = await client.post(
        "/api/v1/anomalies/bulk-resolve",
        headers=_auth(token),
        json={"event_ids": [a["id"], b["id"]]},
    )
    assert resolve.status_code == 200
    assert resolve.json()["updated"] == 2

    got = await client.get(f"/api/v1/anomalies/events/{a['id']}", headers=_auth(token))
    assert got.json()["status"] == "resolved"


@pytest.mark.asyncio
async def test_bulk_requires_at_least_one_id(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/anomalies/bulk-acknowledge", headers=_auth(token), json={"event_ids": []}
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_anomaly_trends_and_types(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    await _create_anomaly(client, token, category="RATE_ANOMALY", score=0.8)

    trends = await client.get("/api/v1/anomalies/trends", headers=_auth(token))
    assert trends.status_code == 200
    assert trends.json()["interval"] == "day"
    assert len(trends.json()["buckets"]) >= 1

    types = await client.get("/api/v1/anomalies/types", headers=_auth(token))
    assert types.status_code == 200
    categories = {c["category"] for c in types.json()["categories"]}
    assert "RATE_ANOMALY" in categories
    assert "critical" in types.json()["severities"]
    assert "open" in types.json()["statuses"]


# --------------------------------------------------------------------------- #
# Audit entry / export / integrity-status
# --------------------------------------------------------------------------- #


async def _create_audit_entry(client: AsyncClient, token: str) -> dict:
    resp = await client.post(
        "/api/v1/audit-log/entries",
        headers=_auth(token),
        json={
            "severity": "info",
            "event_type": "config_change",
            "event_subtype": "RETENTION_MOD",
            "actor": "admin@nexus",
            "description": "retention 5y -> 7y",
            "metadata_json": {},
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_get_audit_entry_by_id(client: AsyncClient, test_user: User) -> None:
    import uuid

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    created = await _create_audit_entry(client, token)
    got = await client.get(
        f"/api/v1/audit-log/entries/{created['id']}", headers=_auth(token)
    )
    assert got.status_code == 200
    assert got.json()["id"] == created["id"]
    assert got.json()["entry_hash"] == created["entry_hash"]

    missing = await client.get(
        f"/api/v1/audit-log/entries/{uuid.uuid4()}", headers=_auth(token)
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_audit_export_and_integrity(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    await _create_audit_entry(client, token)
    await _create_audit_entry(client, token)

    export = await client.get("/api/v1/audit-log/export", headers=_auth(token))
    assert export.status_code == 200
    assert export.json()["total"] == 2
    assert export.json()["returned"] == 2
    assert export.json()["truncated"] is False
    assert len(export.json()["entries"]) == 2

    integrity = await client.get("/api/v1/audit-log/integrity-status", headers=_auth(token))
    assert integrity.status_code == 200
    assert integrity.json()["is_valid"] is True
    assert integrity.json()["total_entries"] == 2
    assert integrity.json()["failed_count"] == 0
