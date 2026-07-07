"""Integration tests for the HSM / Security module endpoints."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.hsm import (
    AttestationRun,
    KeyCeremony,
    KeyCustodianApproval,
    HsmSlot,
    MasterKey,
    MasterKeyStatus,
    SecurityOperation,
    SecurityOperationStatus,
    SecurityOperationType,
    SecurityProvider,
    SecurityProviderType,
    SlotPurpose,
)
from app.models.audit import AuditLogEntry
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
async def hsm_env(db_session: AsyncSession) -> dict:
    """A deterministic HSM environment: one primary slot, an active and an
    expiring master key, one active provider and one passing attestation run.
    """
    now = datetime.now(timezone.utc)
    slot = HsmSlot(
        id=uuid.uuid4(),
        slot_number=0,
        label="nexus-primary",
        purpose=SlotPurpose.PRIMARY,
        is_active=True,
        object_count=100,
        capacity_max_objects=1000,
        ops_per_second=100.0,
        token_flags="RNG,WRITE,LOGIN",
    )
    db_session.add(slot)
    await db_session.flush()

    active_key = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-master-v5",
        slot_id=slot.id,
        algorithm="AES-256",
        status=MasterKeyStatus.ACTIVE,
        rotation_policy_days=180,
        activated_at=now - timedelta(days=10),
        expires_at=now + timedelta(days=180),
        wraps_dek_count=1200,
        throughput_ops=100.0,
    )
    expiring_key = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-signing-v4",
        slot_id=slot.id,
        algorithm="ECDSA-P384",
        status=MasterKeyStatus.EXPIRING,
        rotation_policy_days=365,
        activated_at=now - timedelta(days=350),
        expires_at=now + timedelta(days=14, hours=12),
        wraps_dek_count=0,
        throughput_ops=0.0,
    )
    provider = SecurityProvider(
        id=uuid.uuid4(),
        name="nexus-luna-primary",
        provider_type=SecurityProviderType.PKCS11,
        model="Thales Luna 7",
        manufacturer="Thales Group",
        library_path="/usr/lib/libCryptoki2_64.so",
        firmware_version="7.4.2-build.47",
        serial_number="TL7-US-E1-0042",
        fips_level="FIPS 140-3 Level 3",
        is_active=True,
        pool_active=8,
        pool_max=10,
        avg_latency_ms=0.4,
        session_count=8,
        rw_session_count=3,
        error_count_24h=0,
        supported_mechanisms=["CKM_AES_GCM", "CKM_ECDSA"],
        last_health_check_at=now - timedelta(minutes=1),
    )
    run = AttestationRun(
        ran_at=now - timedelta(hours=1),
        checks=[{"key": "fips_mode", "label": "FIPS Mode", "passed": True, "detail": "ok"}],
        all_passed=True,
    )
    db_session.add_all([active_key, expiring_key, provider, run])
    await db_session.commit()
    return {"slot": slot, "active_key": active_key, "expiring_key": expiring_key, "provider": provider}


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
# Summary
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_security_summary(client: AsyncClient, test_user: User, hsm_env: dict) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/hsm/summary", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["overall_status"] == "healthy"
    assert body["total_keys"] == 2
    assert body["active_keys"] == 1
    assert body["expiring_keys"] == 1
    assert body["disabled_keys"] == 0
    assert body["provider_count"] == 1
    assert body["active_provider_count"] == 1
    assert body["key_ops_per_second"] == 100.0
    assert body["slot_count"] == 1
    assert body["near_capacity_slots"] == 0
    assert body["next_rotation_days"] == 14
    assert body["latest_attestation_passed"] is True
    assert body["attestation_pass_rate"] == 100.0


# --------------------------------------------------------------------------- #
# Keys: list / detail
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_keys_and_status_filter(
    client: AsyncClient, test_user: User, hsm_env: dict
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    all_keys = await client.get("/api/v1/hsm/keys", headers=_auth(token))
    assert all_keys.status_code == 200
    assert len(all_keys.json()) == 2

    expiring = await client.get("/api/v1/hsm/keys?status=expiring", headers=_auth(token))
    assert expiring.status_code == 200
    body = expiring.json()
    assert len(body) == 1
    assert body[0]["key_label"] == "nexus-signing-v4"


@pytest.mark.asyncio
async def test_key_detail_and_404(client: AsyncClient, test_user: User, hsm_env: dict) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    key_id = hsm_env["active_key"].id
    ok = await client.get(f"/api/v1/hsm/keys/{key_id}", headers=_auth(token))
    assert ok.status_code == 200
    assert ok.json()["key_label"] == "nexus-master-v5"
    assert ok.json()["slot_label"] == "nexus-primary"

    missing = await client.get(f"/api/v1/hsm/keys/{uuid.uuid4()}", headers=_auth(token))
    assert missing.status_code == 404


# --------------------------------------------------------------------------- #
# Keys: create
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_register_key(client: AsyncClient, test_user: User, hsm_env: dict) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/keys",
        headers=_auth(token),
        json={"key_label": "nexus-archive-v1", "algorithm": "AES-256", "rotation_policy_days": 90},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["key_label"] == "nexus-archive-v1"
    assert body["status"] == "pending"
    assert body["effective_status"] == "pending"
    assert body["activated_at"] is None

    # The create is recorded in the operations history.
    ops = await client.get("/api/v1/hsm/operations?type=key_create", headers=_auth(token))
    assert ops.status_code == 200
    assert any(o["key_label"] == "nexus-archive-v1" for o in ops.json())


@pytest.mark.asyncio
async def test_register_key_with_slot(client: AsyncClient, test_user: User, hsm_env: dict) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/keys",
        headers=_auth(token),
        json={
            "key_label": "nexus-slotted-v1",
            "algorithm": "AES-256",
            "slot_id": str(hsm_env["slot"].id),
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["slot_label"] == "nexus-primary"


@pytest.mark.asyncio
async def test_register_key_duplicate_conflict(
    client: AsyncClient, test_user: User, hsm_env: dict
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/keys",
        headers=_auth(token),
        json={"key_label": "nexus-master-v5", "algorithm": "AES-256"},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_register_key_unknown_slot_404(
    client: AsyncClient, test_user: User, hsm_env: dict
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/keys",
        headers=_auth(token),
        json={"key_label": "nexus-orphan-v1", "algorithm": "AES-256", "slot_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_register_key_requires_admin(
    client: AsyncClient, non_admin: User, hsm_env: dict
) -> None:
    token = await _login(client, "viewer@nexus.local", "ViewerPass!123")
    resp = await client.post(
        "/api/v1/hsm/keys",
        headers=_auth(token),
        json={"key_label": "nexus-viewer-v1", "algorithm": "AES-256"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_register_key_rejects_short_label(
    client: AsyncClient, test_user: User, hsm_env: dict
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/keys",
        headers=_auth(token),
        json={"key_label": "ab", "algorithm": "AES-256"},
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Keys: rotate
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_rotate_key(client: AsyncClient, test_user: User, hsm_env: dict) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    old_id = hsm_env["active_key"].id

    resp = await client.post(f"/api/v1/hsm/keys/{old_id}/rotate", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    successor = resp.json()
    assert successor["key_label"] == "nexus-master-v6"
    assert successor["status"] == "active"
    assert successor["wraps_dek_count"] == 1200

    # Predecessor is now retired.
    old = await client.get(f"/api/v1/hsm/keys/{old_id}", headers=_auth(token))
    assert old.json()["status"] == "retired"

    # The rotation is recorded.
    ops = await client.get("/api/v1/hsm/operations?type=key_rotate", headers=_auth(token))
    assert any(o["key_label"] == "nexus-master-v6" for o in ops.json())


@pytest.mark.asyncio
async def test_rotate_key_custom_label(
    client: AsyncClient, test_user: User, hsm_env: dict
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    old_id = hsm_env["active_key"].id
    resp = await client.post(
        f"/api/v1/hsm/keys/{old_id}/rotate",
        headers=_auth(token),
        json={"new_label": "nexus-master-2027"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["key_label"] == "nexus-master-2027"


@pytest.mark.asyncio
async def test_rotate_pending_key_conflicts(
    client: AsyncClient, test_user: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    pending = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-pending-v1",
        slot_id=hsm_env["slot"].id,
        algorithm="AES-256",
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=180,
    )
    db_session.add(pending)
    await db_session.commit()

    resp = await client.post(f"/api/v1/hsm/keys/{pending.id}/rotate", headers=_auth(token))
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_rotate_requires_admin(
    client: AsyncClient, non_admin: User, hsm_env: dict
) -> None:
    token = await _login(client, "viewer@nexus.local", "ViewerPass!123")
    resp = await client.post(
        f"/api/v1/hsm/keys/{hsm_env['active_key'].id}/rotate", headers=_auth(token)
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Keys: disable
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_disable_key(client: AsyncClient, test_user: User, hsm_env: dict) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    key_id = hsm_env["active_key"].id

    resp = await client.post(f"/api/v1/hsm/keys/{key_id}/disable", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "disabled"
    assert resp.json()["effective_status"] == "disabled"

    # Disabling again is a conflict.
    again = await client.post(f"/api/v1/hsm/keys/{key_id}/disable", headers=_auth(token))
    assert again.status_code == 409


@pytest.mark.asyncio
async def test_disable_requires_admin(
    client: AsyncClient, non_admin: User, hsm_env: dict
) -> None:
    token = await _login(client, "viewer@nexus.local", "ViewerPass!123")
    resp = await client.post(
        f"/api/v1/hsm/keys/{hsm_env['active_key'].id}/disable", headers=_auth(token)
    )
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Key ceremonies
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_initiate_key_ceremony(
    client: AsyncClient, test_user: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    pending = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-master-v6",
        slot_id=hsm_env["slot"].id,
        algorithm="AES-256",
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=180,
    )
    db_session.add(pending)
    await db_session.commit()

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/ceremonies",
        headers=_auth(token),
        json={
            "master_key_id": str(pending.id),
            "predecessor_key_id": str(hsm_env["active_key"].id),
            "required_approvals": 2,
            "scheduled_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["master_key_label"] == "nexus-master-v6"
    assert body["predecessor_label"] == "nexus-master-v5"
    assert body["required_approvals"] == 2
    assert body["status"] == "pending"
    assert body["approvals"] == []

    audit = (
        await db_session.execute(
            select(AuditLogEntry).where(
                AuditLogEntry.event_subtype == "KEY_CEREMONY_INITIATED"
            )
        )
    ).scalar_one()
    assert audit.actor == TEST_EMAIL
    assert audit.metadata_json["master_key_label"] == "nexus-master-v6"


@pytest.mark.asyncio
async def test_initiate_key_ceremony_rejects_duplicate_active_ceremony(
    client: AsyncClient, test_user: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    pending = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-pending-ceremony-v1",
        slot_id=hsm_env["slot"].id,
        algorithm="AES-256",
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=180,
    )
    db_session.add(pending)
    await db_session.flush()
    db_session.add(
        KeyCeremony(
            id=uuid.uuid4(),
            ceremony_ref="CER-EXISTING",
            master_key_id=pending.id,
            required_approvals=2,
        )
    )
    await db_session.commit()

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/ceremonies",
        headers=_auth(token),
        json={"master_key_id": str(pending.id), "required_approvals": 2},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_initiate_key_ceremony_requires_pending_key(
    client: AsyncClient, test_user: User, hsm_env: dict
) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/ceremonies",
        headers=_auth(token),
        json={"master_key_id": str(hsm_env["active_key"].id), "required_approvals": 2},
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_initiate_key_ceremony_rejects_naive_schedule(
    client: AsyncClient, test_user: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    pending = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-naive-schedule-v1",
        slot_id=hsm_env["slot"].id,
        algorithm="AES-256",
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=180,
    )
    db_session.add(pending)
    await db_session.commit()

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        "/api/v1/hsm/ceremonies",
        headers=_auth(token),
        json={
            "master_key_id": str(pending.id),
            "required_approvals": 2,
            "scheduled_at": "2026-07-06T09:00:00",
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_initiate_key_ceremony_requires_admin(
    client: AsyncClient, non_admin: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    pending = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-viewer-ceremony-v1",
        slot_id=hsm_env["slot"].id,
        algorithm="AES-256",
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=180,
    )
    db_session.add(pending)
    await db_session.commit()

    token = await _login(client, "viewer@nexus.local", "ViewerPass!123")
    resp = await client.post(
        "/api/v1/hsm/ceremonies",
        headers=_auth(token),
        json={"master_key_id": str(pending.id), "required_approvals": 2},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_approve_ceremony_is_idempotent(
    client: AsyncClient, test_user: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    pending = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-approve-idempotent-v1",
        slot_id=hsm_env["slot"].id,
        algorithm="AES-256",
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=180,
    )
    db_session.add(pending)
    await db_session.flush()
    ceremony = KeyCeremony(
        id=uuid.uuid4(),
        ceremony_ref="CER-IDEMPOTENT",
        master_key_id=pending.id,
        required_approvals=2,
    )
    db_session.add(ceremony)
    await db_session.commit()

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    first = await client.post(
        f"/api/v1/hsm/ceremonies/{ceremony.id}/approve", headers=_auth(token)
    )
    second = await client.post(
        f"/api/v1/hsm/ceremonies/{ceremony.id}/approve", headers=_auth(token)
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert second.json()["approval_count"] == 1
    audits = (
        await db_session.execute(
            select(AuditLogEntry).where(
                AuditLogEntry.event_subtype == "KEY_CEREMONY_APPROVED"
            )
        )
    ).scalars().all()
    assert len(audits) == 1


@pytest.mark.asyncio
async def test_complete_ceremony_requires_quorum(
    client: AsyncClient, test_user: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    pending = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-no-quorum-v1",
        slot_id=hsm_env["slot"].id,
        algorithm="AES-256",
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=180,
    )
    db_session.add(pending)
    await db_session.flush()
    ceremony = KeyCeremony(
        id=uuid.uuid4(),
        ceremony_ref="CER-NO-QUORUM",
        master_key_id=pending.id,
        required_approvals=2,
    )
    db_session.add(ceremony)
    await db_session.commit()

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        f"/api/v1/hsm/ceremonies/{ceremony.id}/complete", headers=_auth(token)
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_complete_ceremony_activates_pending_key_and_audits(
    client: AsyncClient, test_user: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    pending = MasterKey(
        id=uuid.uuid4(),
        key_label="nexus-complete-v1",
        slot_id=hsm_env["slot"].id,
        algorithm="AES-256",
        status=MasterKeyStatus.PENDING,
        rotation_policy_days=180,
    )
    db_session.add(pending)
    await db_session.flush()
    ceremony = KeyCeremony(
        id=uuid.uuid4(),
        ceremony_ref="CER-COMPLETE",
        master_key_id=pending.id,
        predecessor_label=hsm_env["active_key"].key_label,
        required_approvals=1,
    )
    db_session.add(ceremony)
    await db_session.flush()
    db_session.add(
        KeyCustodianApproval(
            ceremony_id=ceremony.id,
            custodian_email=TEST_EMAIL,
            approved_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.post(
        f"/api/v1/hsm/ceremonies/{ceremony.id}/complete", headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "complete"

    pending_detail = await client.get(f"/api/v1/hsm/keys/{pending.id}", headers=_auth(token))
    old_detail = await client.get(
        f"/api/v1/hsm/keys/{hsm_env['active_key'].id}", headers=_auth(token)
    )
    assert pending_detail.json()["status"] == "active"
    assert old_detail.json()["status"] == "retired"

    audit = (
        await db_session.execute(
            select(AuditLogEntry).where(AuditLogEntry.event_subtype == "KEY_ROTATION_COMPLETE")
        )
    ).scalar_one()
    assert audit.actor == TEST_EMAIL


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_operations_and_filter(
    client: AsyncClient, test_user: User, hsm_env: dict, db_session: AsyncSession
) -> None:
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            SecurityOperation(
                id=uuid.uuid4(),
                operation_type=SecurityOperationType.KEY_ROTATE,
                master_key_id=hsm_env["active_key"].id,
                key_label="nexus-master-v5",
                actor="engine-core",
                status=SecurityOperationStatus.SUCCESS,
                detail="rotated",
                occurred_at=now - timedelta(hours=1),
            ),
            SecurityOperation(
                id=uuid.uuid4(),
                operation_type=SecurityOperationType.ATTESTATION_RUN,
                master_key_id=None,
                key_label=None,
                actor="scheduler",
                status=SecurityOperationStatus.SUCCESS,
                detail="attested",
                occurred_at=now - timedelta(hours=2),
            ),
        ]
    )
    await db_session.commit()

    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    all_ops = await client.get("/api/v1/hsm/operations", headers=_auth(token))
    assert all_ops.status_code == 200
    assert len(all_ops.json()) == 2
    # Newest first.
    assert all_ops.json()[0]["operation_type"] == "key_rotate"

    filtered = await client.get(
        "/api/v1/hsm/operations?type=attestation_run", headers=_auth(token)
    )
    assert filtered.status_code == 200
    assert len(filtered.json()) == 1
    assert filtered.json()[0]["actor"] == "scheduler"


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_providers(client: AsyncClient, test_user: User, hsm_env: dict) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/hsm/providers", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    provider = body[0]
    assert provider["name"] == "nexus-luna-primary"
    assert provider["status"] == "online"
    assert provider["pool_utilization_percent"] == 80.0
    assert "CKM_AES_GCM" in provider["supported_mechanisms"]


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_security_health(client: AsyncClient, test_user: User, hsm_env: dict) -> None:
    token = await _login(client, TEST_EMAIL, TEST_PASSWORD)
    resp = await client.get("/api/v1/hsm/health", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["overall_status"] == "healthy"
    assert body["db_reachable"] is True
    assert len(body["providers"]) == 1
    assert body["providers"][0]["status"] == "online"
    check_keys = {c["key"] for c in body["checks"]}
    assert check_keys == {"database", "providers", "attestation", "slot_capacity", "certificates"}
    assert all(c["passed"] for c in body["checks"])


@pytest.mark.asyncio
async def test_hsm_requires_auth(client: AsyncClient) -> None:
    assert (await client.get("/api/v1/hsm/summary")).status_code == 401
    assert (await client.get("/api/v1/hsm/keys")).status_code == 401
    assert (await client.get("/api/v1/hsm/providers")).status_code == 401
    assert (await client.get("/api/v1/hsm/health")).status_code == 401
