from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import verify_hex_digest
from app.models.audit import AuditLogEntry
from app.models.anomaly import AnomalyEvent, AnomalySeverity, AnomalyStatus
from app.models.user import User
from app.schemas.anomaly import AnomalyEventCreate
from app.services import anomaly_service
from app.services.anomaly_service import create_anomaly_event, update_anomaly_status
from app.services.audit_service import verify_chain


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

    audit = await db_session.scalar(select(AuditLogEntry))
    assert audit is not None
    assert audit.event_type.value == "anomaly_detected"
    assert audit.event_subtype == "ANOMALY_CREATED"
    assert audit.actor == "test@nexus.local"
    assert audit.metadata_json["metadata_json"]["password"] == "[REDACTED]"
    assert audit.metadata_json["metadata_json"]["nested"]["Secret_Key"] == "[REDACTED]"


def _anomaly_payload(**overrides: object) -> AnomalyEventCreate:
    payload = {
        "category": "auth",
        "score": 0.82,
        "title": "Suspicious login burst",
        "description": "Multiple failed logins",
        "actor": "detector",
        "source_ip": "198.51.100.8",
        "metadata_json": {"api_key": "raw-api-key", "safe": "visible"},
    }
    payload.update(overrides)
    return AnomalyEventCreate(**payload)


async def _create_raw_anomaly(db_session: AsyncSession) -> AnomalyEvent:
    event = AnomalyEvent(
        category="auth",
        score=0.82,
        severity=AnomalySeverity.from_score(0.82),
        status=AnomalyStatus.OPEN,
        title="Suspicious login burst",
        description="Multiple failed logins",
        actor="detector",
        source_ip="198.51.100.8",
        metadata_json={"secret": "raw-secret", "safe": "visible"},
        occurred_at=datetime.now(timezone.utc),
    )
    db_session.add(event)
    await db_session.commit()
    return event


async def _audit_count(db_session: AsyncSession) -> int:
    return await db_session.scalar(select(func.count()).select_from(AuditLogEntry)) or 0


@pytest.mark.asyncio
async def test_anomaly_create_and_status_update_append_valid_audit_entries(
    client: AsyncClient,
    db_session: AsyncSession,
    test_user: User,
) -> None:
    headers = await _auth_headers(client)

    create_response = await client.post(
        "/api/v1/anomalies/events",
        headers=headers,
        json=_anomaly_payload().model_dump(),
    )
    assert create_response.status_code == 201
    event_id = create_response.json()["id"]

    status_response = await client.post(
        f"/api/v1/anomalies/events/{event_id}/acknowledge", headers=headers
    )
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "investigating"

    audits = (
        await db_session.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence.asc()))
    ).scalars().all()
    assert [audit.event_subtype for audit in audits] == [
        "ANOMALY_CREATED",
        "ANOMALY_STATUS_UPDATED",
    ]
    assert audits[0].event_type.value == "anomaly_detected"
    assert audits[1].event_type.value == "anomaly_detected"
    assert audits[0].actor == "test@nexus.local"
    assert audits[1].actor == "test@nexus.local"
    assert audits[0].metadata_json["metadata_json"]["api_key"] == "[REDACTED]"
    assert audits[0].metadata_json["metadata_json"]["safe"] == "visible"
    assert audits[1].metadata_json["previous_status"] == "open"
    assert audits[1].metadata_json["status"] == "investigating"
    assert audits[1].prev_hash == audits[0].entry_hash
    assert all(verify_hex_digest(audit.entry_hash, audit.signature) for audit in audits)

    verification = await verify_chain(db_session)
    assert verification.is_valid is True
    assert verification.verified_count == 2
    assert verification.failed_count == 0


@pytest.mark.asyncio
async def test_audit_failure_rolls_back_anomaly_creation(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_audit_append(*_args: object, **_kwargs: object) -> AuditLogEntry:
        raise RuntimeError("audit append failed")

    monkeypatch.setattr(anomaly_service, "append_entry_in_transaction", fail_audit_append)

    with pytest.raises(RuntimeError, match="audit append failed"):
        await create_anomaly_event(
            db_session, _anomaly_payload(), audit_actor="test@nexus.local"
        )

    assert await db_session.scalar(select(func.count()).select_from(AnomalyEvent)) == 0
    assert await _audit_count(db_session) == 0


@pytest.mark.asyncio
async def test_audit_failure_rolls_back_status_update(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = await _create_raw_anomaly(db_session)

    async def fail_audit_append(*_args: object, **_kwargs: object) -> AuditLogEntry:
        raise RuntimeError("audit append failed")

    monkeypatch.setattr(anomaly_service, "append_entry_in_transaction", fail_audit_append)

    with pytest.raises(RuntimeError, match="audit append failed"):
        await update_anomaly_status(
            db_session,
            event.id,
            AnomalyStatus.RESOLVED,
            audit_actor="test@nexus.local",
        )

    await db_session.refresh(event)
    assert event.status == AnomalyStatus.OPEN
    assert event.resolved_at is None
    assert await _audit_count(db_session) == 0


@pytest.mark.asyncio
async def test_anomaly_mutation_failure_leaves_no_audit_entry(
    db_session: AsyncSession,
) -> None:
    def fail_anomaly_flush(session: object, _flush_context: object, _instances: object) -> None:
        if any(isinstance(item, AnomalyEvent) for item in getattr(session, "new")):
            raise RuntimeError("anomaly flush failed")

    event.listen(db_session.sync_session, "before_flush", fail_anomaly_flush)
    try:
        with pytest.raises(RuntimeError, match="anomaly flush failed"):
            await create_anomaly_event(
                db_session, _anomaly_payload(), audit_actor="test@nexus.local"
            )
    finally:
        event.remove(db_session.sync_session, "before_flush", fail_anomaly_flush)

    assert await db_session.scalar(select(func.count()).select_from(AnomalyEvent)) == 0
    assert await _audit_count(db_session) == 0
