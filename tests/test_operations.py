"""Integration tests for the operations / observability endpoints."""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.operations import ApplicationError, BackgroundJob, ErrorLevel, JobStatus
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
async def ops_data(db_session: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    db_session.add(
        BackgroundJob(
            id=uuid.uuid4(), name="etcd-snapshot", queue="backups",
            status=JobStatus.SUCCEEDED, progress_percent=100.0, duration_ms=1200.0,
            attempts=1, max_attempts=3,
        )
    )
    db_session.add(
        BackgroundJob(
            id=uuid.uuid4(), name="dek-rewrap", queue="security",
            status=JobStatus.FAILED, progress_percent=60.0, attempts=2, max_attempts=3,
            last_error="provider timeout",
        )
    )
    db_session.add(
        ApplicationError(
            id=uuid.uuid4(), occurred_at=now, level=ErrorLevel.ERROR,
            error_type="ProviderTimeoutError", message="slot 2 timeout",
            source="app.services.hsm_service", status_code=504, occurrences=2,
            resolved=False, created_at=now,
        )
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_operations_require_admin(client: AsyncClient, non_admin: User) -> None:
    token = await _login(client, non_admin.email, "ViewerPass!123")
    resp = await client.get("/api/v1/operations/metrics-summary", headers=_auth(token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_metrics_summary_empty(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/operations/metrics-summary", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["gauges"] == []
    assert body["total_requests_per_second"] == 0
    assert body["top_endpoints"] == []


@pytest.mark.asyncio
async def test_jobs_and_errors(client: AsyncClient, test_user: User, ops_data: None) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)

    jobs = await client.get("/api/v1/operations/jobs", headers=_auth(token))
    assert jobs.status_code == 200
    assert len(jobs.json()) == 2

    failed = await client.get("/api/v1/operations/jobs?status=failed", headers=_auth(token))
    assert failed.status_code == 200
    assert len(failed.json()) == 1
    assert failed.json()[0]["name"] == "dek-rewrap"

    errors = await client.get("/api/v1/operations/errors", headers=_auth(token))
    assert errors.status_code == 200
    assert len(errors.json()) == 1
    assert errors.json()[0]["error_type"] == "ProviderTimeoutError"


@pytest.mark.asyncio
async def test_cache_status_not_configured(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/operations/cache-status", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["configured"] is False
    assert resp.json()["status"] == "not_configured"


@pytest.mark.asyncio
async def test_db_status_up(client: AsyncClient, test_user: User) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/operations/db-status", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "up"
    assert resp.json()["reachable"] is True


@pytest.mark.asyncio
async def test_migrations_and_events_and_readiness(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)

    migrations = await client.get("/api/v1/operations/migrations", headers=_auth(token))
    assert migrations.status_code == 200
    assert "head_revision" in migrations.json()

    events = await client.get("/api/v1/operations/events", headers=_auth(token))
    assert events.status_code == 200
    assert events.json()["sink"] == "immutable-audit-log"

    readiness = await client.get("/api/v1/operations/readiness", headers=_auth(token))
    assert readiness.status_code == 200
    assert readiness.json()["status"] == "ready"
    names = {c["name"] for c in readiness.json()["checks"]}
    assert {"database", "migrations", "cache"} <= names
