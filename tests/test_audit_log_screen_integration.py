from datetime import datetime, timedelta, timezone
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.audit import AuditLogEntry
from app.models.user import User
from app.schemas.audit import AuditLogEntryCreate
from app.services import audit_service
from app.services.audit_service import append_entry, get_chain_summary, list_entries, verify_chain


TEST_EMAIL = "test@nexus.local"
TEST_PASSWORD = "TestPassword!123"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(client: AsyncClient, email: str = TEST_EMAIL) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _entry(
    *,
    actor: str,
    description: str,
    severity: str = "info",
    event_type: str = "state_change",
    event_subtype: str = "test.event",
    tenant_slug: str | None = None,
    source_ip: str | None = None,
) -> AuditLogEntryCreate:
    return AuditLogEntryCreate(
        severity=severity,
        event_type=event_type,
        event_subtype=event_subtype,
        actor=actor,
        description=description,
        tenant_slug=tenant_slug,
        source_ip=source_ip,
    )


async def _set_occurred_at(
    db_session: AsyncSession, entry: AuditLogEntry, occurred_at: datetime
) -> None:
    await db_session.execute(
        update(AuditLogEntry)
        .where(AuditLogEntry.id == entry.id)
        .values(occurred_at=occurred_at, created_at=occurred_at)
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_list_entries_free_text_search_matches_textual_fields_case_insensitively(
    db_session: AsyncSession,
) -> None:
    await append_entry(
        db_session,
        _entry(actor="Alice.Root", description="Routine rotation", event_subtype="key.rotate"),
    )
    await append_entry(
        db_session,
        _entry(actor="service", description="Escalated Policy Drift", event_subtype="policy.ok"),
    )
    await append_entry(
        db_session,
        _entry(actor="worker", description="background task", event_subtype="AUTH.LOGIN"),
    )

    actor_items, actor_total = await list_entries(db_session, search="alice")
    description_items, description_total = await list_entries(db_session, search="policy drift")
    subtype_items, subtype_total = await list_entries(db_session, search="auth.login")

    assert actor_total == 1
    assert actor_items[0].actor == "Alice.Root"
    assert description_total == 1
    assert description_items[0].description == "Escalated Policy Drift"
    assert subtype_total == 1
    assert subtype_items[0].event_subtype == "AUTH.LOGIN"
    assert actor_items[0].integrity == "unverified"


@pytest.mark.asyncio
async def test_list_entries_time_range_filters_are_inclusive(db_session: AsyncSession) -> None:
    base = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)
    older = await append_entry(db_session, _entry(actor="old", description="old"))
    middle = await append_entry(db_session, _entry(actor="middle", description="middle"))
    newer = await append_entry(db_session, _entry(actor="new", description="new"))
    await _set_occurred_at(db_session, older, base - timedelta(hours=1))
    await _set_occurred_at(db_session, middle, base)
    await _set_occurred_at(db_session, newer, base + timedelta(hours=1))

    from_items, from_total = await list_entries(db_session, from_time=base)
    to_items, to_total = await list_entries(db_session, to_time=base)
    bounded_items, bounded_total = await list_entries(
        db_session,
        from_time=base,
        to_time=base,
    )

    assert from_total == 2
    assert [item.actor for item in from_items] == ["new", "middle"]
    assert to_total == 2
    assert [item.actor for item in to_items] == ["middle", "old"]
    assert bounded_total == 1
    assert bounded_items[0].actor == "middle"


@pytest.mark.asyncio
async def test_list_entries_composes_filters_and_counts_filtered_total(
    db_session: AsyncSession,
) -> None:
    await append_entry(
        db_session,
        _entry(
            actor="alice",
            description="matched config update",
            severity="warning",
            event_type="config_change",
            event_subtype="config.update",
            tenant_slug="acme",
        ),
    )
    await append_entry(
        db_session,
        _entry(
            actor="alice",
            description="wrong severity",
            severity="info",
            event_type="config_change",
            event_subtype="config.update",
            tenant_slug="acme",
        ),
    )
    await append_entry(
        db_session,
        _entry(
            actor="bob",
            description="matched config update",
            severity="warning",
            event_type="config_change",
            event_subtype="config.update",
            tenant_slug="acme",
        ),
    )

    items, total = await list_entries(
        db_session,
        severity="warning",
        event_type="config_change",
        tenant_slug="acme",
        actor_search="ali",
        search="matched",
    )

    assert total == 1
    assert len(items) == 1
    assert items[0].actor == "alice"


@pytest.mark.asyncio
async def test_list_entries_pagination_is_deterministic_and_uses_filtered_total(
    db_session: AsyncSession,
) -> None:
    for index in range(5):
        await append_entry(
            db_session,
            _entry(
                actor=f"actor-{index}",
                description=f"page event {index}",
                severity="info" if index != 0 else "warning",
            ),
        )

    first_page, first_total = await list_entries(
        db_session, severity="info", page=1, page_size=2
    )
    second_page, second_total = await list_entries(
        db_session, severity="info", page=2, page_size=2
    )

    assert first_total == 4
    assert second_total == 4
    assert len(first_page) == 2
    assert len(second_page) == 2
    assert [item.sequence for item in first_page] == sorted(
        [item.sequence for item in first_page], reverse=True
    )
    assert {item.id for item in first_page}.isdisjoint({item.id for item in second_page})


@pytest.mark.asyncio
async def test_summary_does_not_run_full_verification(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = await append_entry(db_session, _entry(actor="tester", description="summary"))

    async def fail_verify(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("summary must not verify the full chain")

    monkeypatch.setattr(audit_service, "verify_chain", fail_verify)

    summary = await get_chain_summary(db_session)

    assert summary.total_entries == 1
    assert summary.root_hash == entry.entry_hash
    assert summary.signing_key_id == entry.signing_key_id
    assert summary.last_verified_at is None
    assert summary.last_verification is None


@pytest.mark.asyncio
async def test_entries_endpoint_rejects_invalid_time_range(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client)
    response = await client.get(
        "/api/v1/audit-log/entries",
        headers=_auth(token),
        params={
            "from_time": "2026-07-06T12:00:00+00:00",
            "to_time": "2026-07-06T11:59:59+00:00",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "from_time must be before or equal to to_time"


@pytest.mark.asyncio
async def test_entries_endpoint_rejects_naive_time(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client)
    response = await client.get(
        "/api/v1/audit-log/entries",
        headers=_auth(token),
        params={"from_time": "2026-07-06T12:00:00"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "from_time must include timezone information"


@pytest.mark.asyncio
async def test_verify_endpoint_remains_admin_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = User(
        id=uuid.uuid4(),
        email="member@nexus.local",
        display_name="Member",
        hashed_password=hash_password(TEST_PASSWORD),
        is_active=True,
        is_admin=False,
    )
    db_session.add(user)
    await db_session.commit()

    token = await _login(client, "member@nexus.local")
    response = await client.post("/api/v1/audit-log/verify", headers=_auth(token))

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_verify_endpoint_returns_valid_chain_result(
    client: AsyncClient, test_user: User, db_session: AsyncSession
) -> None:
    await append_entry(db_session, _entry(actor="tester", description="verify"))
    token = await _login(client)

    response = await client.post("/api/v1/audit-log/verify", headers=_auth(token))

    assert response.status_code == 200
    body = response.json()
    assert body["is_valid"] is True
    assert body["verified_count"] == 1
    assert body["failed_count"] == 0

    service_result = await verify_chain(db_session)
    assert service_result.is_valid is True
