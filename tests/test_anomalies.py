import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import AnomalyEvent
from app.models.user import User


async def _auth_headers(client: AsyncClient) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@nexus.local", "password": "TestPassword!123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.mark.asyncio
async def test_anomaly_metadata_is_redacted_without_mutating_storage(
    client: AsyncClient,
    db_session: AsyncSession,
    test_user: User,
) -> None:
    headers = await _auth_headers(client)
    metadata = {
        "password": "top-level-password",
        "safe_value": "visible",
        "nested": {
            "Secret_Key": "deep-secret",
            "safe_nested": {"count": 3},
            "deeper": {"credentials": "deep-credentials"},
        },
        "events": [
            {"api_key": "list-api-key", "label": "first"},
            {"Authorization": "Bearer secret-token", "token": "list-token"},
            "plain-list-value",
        ],
        "note": "secret words in values are preserved",
    }

    create_response = await client.post(
        "/api/v1/anomalies/events",
        headers=headers,
        json={
            "category": "auth",
            "score": 0.92,
            "title": "Suspicious login burst",
            "description": "Multiple failed logins",
            "actor": "service-account",
            "source_ip": "198.51.100.8",
            "metadata_json": metadata,
        },
    )

    assert create_response.status_code == 201
    created = create_response.json()
    redacted = created["metadata_json"]
    assert redacted["password"] == "[REDACTED]"
    assert redacted["nested"]["Secret_Key"] == "[REDACTED]"
    assert redacted["nested"]["deeper"]["credentials"] == "[REDACTED]"
    assert redacted["events"][0]["api_key"] == "[REDACTED]"
    assert redacted["events"][1]["Authorization"] == "[REDACTED]"
    assert redacted["events"][1]["token"] == "[REDACTED]"
    assert redacted["safe_value"] == "visible"
    assert redacted["nested"]["safe_nested"]["count"] == 3
    assert redacted["events"][0]["label"] == "first"
    assert redacted["events"][2] == "plain-list-value"
    assert redacted["note"] == "secret words in values are preserved"

    event_id = created["id"]
    stored = await db_session.scalar(select(AnomalyEvent).where(AnomalyEvent.id == event_id))
    assert stored is not None
    assert stored.metadata_json == metadata

    get_response = await client.get(f"/api/v1/anomalies/events/{event_id}", headers=headers)
    assert get_response.status_code == 200
    assert get_response.json()["metadata_json"] == redacted

    list_response = await client.get("/api/v1/anomalies/events", headers=headers)
    assert list_response.status_code == 200
    assert list_response.json()["items"][0]["metadata_json"] == redacted

    overview_response = await client.get("/api/v1/anomalies/overview", headers=headers)
    assert overview_response.status_code == 200
    assert overview_response.json()["recent_events"][0]["metadata_json"] == redacted
