"""Integration tests for the Compliance module endpoints."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.compliance import (
    ComplianceFramework,
    ComplianceScoreSnapshot,
    ComplianceViolation,
    ControlMapping,
    ControlStatus,
    FrameworkCode,
    ViolationSeverity,
    ViolationStatus,
)
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
async def framework(db_session: AsyncSession) -> ComplianceFramework:
    """A SOC2 framework with three controls (mapped / partial / gap) and one
    open violation, giving deterministic summary and coverage numbers."""
    fw = ComplianceFramework(
        id=uuid.uuid4(),
        code=FrameworkCode.SOC2,
        display_name="SOC 2 Type II",
        subtitle="Trust Services Criteria",
        description="SOC 2 controls",
        auditor="Acme Audit LLP",
        certified=True,
        score=92.0,
    )
    db_session.add(fw)
    await db_session.flush()
    db_session.add_all(
        [
            ControlMapping(
                id=uuid.uuid4(),
                framework_id=fw.id,
                control_domain="Access Control",
                control_description="RBAC enforced",
                control_code="CC6.1",
                status=ControlStatus.MAPPED,
            ),
            ControlMapping(
                id=uuid.uuid4(),
                framework_id=fw.id,
                control_domain="Change Management",
                control_description="Peer review required",
                control_code="CC8.1",
                status=ControlStatus.PARTIAL,
            ),
            ControlMapping(
                id=uuid.uuid4(),
                framework_id=fw.id,
                control_domain="Encryption",
                control_description="At-rest encryption",
                control_code="CC6.7",
                status=ControlStatus.GAP,
            ),
        ]
    )
    db_session.add(
        ComplianceViolation(
            id=uuid.uuid4(),
            framework_id=fw.id,
            severity=ViolationSeverity.VIOLATION,
            status=ViolationStatus.OPEN,
            control_reference="CC6.7",
            title="Unencrypted volume",
            description="Volume X is not encrypted",
            detected_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()
    await db_session.refresh(fw)
    return fw


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
# Frameworks & controls
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_frameworks(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/compliance/frameworks", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["code"] == "soc2"
    assert len(body[0]["control_breakdown"]) == 3
    assert body[0]["open_violation_count"] == 1


@pytest.mark.asyncio
async def test_framework_detail_and_404(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    ok = await client.get(
        f"/api/v1/compliance/frameworks/{framework.id}", headers=_auth(token)
    )
    assert ok.status_code == 200
    assert ok.json()["display_name"] == "SOC 2 Type II"

    missing = await client.get(
        f"/api/v1/compliance/frameworks/{uuid.uuid4()}", headers=_auth(token)
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_list_controls_and_status_filter(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    all_controls = await client.get("/api/v1/compliance/controls", headers=_auth(token))
    assert all_controls.status_code == 200
    assert len(all_controls.json()) == 3

    gaps_only = await client.get(
        "/api/v1/compliance/controls?status=gap", headers=_auth(token)
    )
    assert gaps_only.status_code == 200
    body = gaps_only.json()
    assert len(body) == 1
    assert body[0]["control_domain"] == "Encryption"
    assert body[0]["framework_code"] == "soc2"


@pytest.mark.asyncio
async def test_control_detail_and_404(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    listed = await client.get("/api/v1/compliance/controls", headers=_auth(token))
    control_id = listed.json()[0]["id"]

    ok = await client.get(
        f"/api/v1/compliance/controls/{control_id}", headers=_auth(token)
    )
    assert ok.status_code == 200
    assert ok.json()["id"] == control_id

    missing = await client.get(
        f"/api/v1/compliance/controls/{uuid.uuid4()}", headers=_auth(token)
    )
    assert missing.status_code == 404


# --------------------------------------------------------------------------- #
# Summary & gaps
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_compliance_summary(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/compliance/summary", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["framework_count"] == 1
    assert body["certified_count"] == 1
    assert body["total_controls"] == 3
    assert body["mapped_controls"] == 1
    assert body["partial_controls"] == 1
    assert body["gap_controls"] == 1
    assert body["open_violation_count"] == 1
    assert body["overall_score"] == 92.0


@pytest.mark.asyncio
async def test_compliance_gaps(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/compliance/gaps", headers=_auth(token))
    assert resp.status_code == 200
    statuses = {row["status"] for row in resp.json()}
    # PARTIAL and GAP controls are both surfaced as gaps; MAPPED is not.
    assert statuses == {"partial", "gap"}
    assert len(resp.json()) == 2


# --------------------------------------------------------------------------- #
# Assessments lifecycle & authorization
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_assessment_lifecycle(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)

    started = await client.post(
        "/api/v1/compliance/assessments",
        headers=_auth(token),
        json={"framework_id": str(framework.id)},
    )
    assert started.status_code == 201, started.text
    assessment = started.json()
    assert assessment["status"] == "in_progress"
    assert assessment["framework_code"] == "soc2"
    assessment_id = assessment["id"]

    listed = await client.get("/api/v1/compliance/assessments", headers=_auth(token))
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    detail = await client.get(
        f"/api/v1/compliance/assessments/{assessment_id}", headers=_auth(token)
    )
    assert detail.status_code == 200
    assert detail.json()["status"] == "in_progress"

    completed = await client.post(
        f"/api/v1/compliance/assessments/{assessment_id}/complete", headers=_auth(token)
    )
    assert completed.status_code == 200, completed.text
    body = completed.json()
    assert body["status"] == "completed"
    assert body["total_controls"] == 3
    assert body["mapped_controls"] == 1
    assert body["gap_controls"] == 1
    # 1 mapped (1.0) + 1 partial (0.5) + 1 gap (0) over 3 applicable = 50.0
    assert body["score"] == 50.0
    assert body["completed_at"] is not None


@pytest.mark.asyncio
async def test_complete_twice_conflicts(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    started = await client.post(
        "/api/v1/compliance/assessments",
        headers=_auth(token),
        json={"framework_id": str(framework.id)},
    )
    assessment_id = started.json()["id"]
    first = await client.post(
        f"/api/v1/compliance/assessments/{assessment_id}/complete", headers=_auth(token)
    )
    assert first.status_code == 200
    second = await client.post(
        f"/api/v1/compliance/assessments/{assessment_id}/complete", headers=_auth(token)
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_start_assessment_unknown_framework_404(
    client: AsyncClient, test_user: User
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/compliance/assessments",
        headers=_auth(token),
        json={"framework_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_start_assessment_requires_admin(
    client: AsyncClient, non_admin: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, "viewer@nexus.local", "ViewerPass!123")
    resp = await client.post(
        "/api/v1/compliance/assessments",
        headers=_auth(token),
        json={"framework_id": str(framework.id)},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_complete_assessment_requires_admin(
    client: AsyncClient, test_user: User, non_admin: User, framework: ComplianceFramework
) -> None:
    admin_token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    started = await client.post(
        "/api/v1/compliance/assessments",
        headers=_auth(admin_token),
        json={"framework_id": str(framework.id)},
    )
    assessment_id = started.json()["id"]

    viewer_token = await _login(client, "viewer@nexus.local", "ViewerPass!123")
    resp = await client.post(
        f"/api/v1/compliance/assessments/{assessment_id}/complete",
        headers=_auth(viewer_token),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_frameworks_require_auth(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/compliance/frameworks")).status_code == 401


# --------------------------------------------------------------------------- #
# Score trends
# --------------------------------------------------------------------------- #


@pytest_asyncio.fixture
async def score_history(
    db_session: AsyncSession, framework: ComplianceFramework
) -> ComplianceFramework:
    now = datetime.now(timezone.utc)
    # Five points, oldest 88.0 up to newest 92.0.
    for index in range(5):
        db_session.add(
            ComplianceScoreSnapshot(
                id=uuid.uuid4(),
                framework_id=framework.id,
                score=88.0 + index,
                captured_at=now - timedelta(days=(4 - index) * 5),
            )
        )
    await db_session.commit()
    return framework


@pytest.mark.asyncio
async def test_score_trends(
    client: AsyncClient, test_user: User, score_history: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/compliance/score-trends", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["window_days"] == 30
    assert len(body["series"]) == 1
    series = body["series"][0]
    assert series["code"] == "soc2"
    assert len(series["points"]) == 5
    assert series["current_score"] == 92.0
    assert series["delta"] == 4.0


@pytest.mark.asyncio
async def test_score_trends_empty_when_no_history(
    client: AsyncClient, test_user: User, framework: ComplianceFramework
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/compliance/score-trends", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["series"] == []
