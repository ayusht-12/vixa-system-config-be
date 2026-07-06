import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.tenancy import (
    PROVISIONING_STEPS,
    BreachAlert,
    ProvisioningJobStatus,
    SnapshotStatus,
    Tenant,
    TenantBackupSnapshot,
    TenantMember,
    TenantProvisioningJob,
    TenantSchemaValidation,
    TenantStatus,
)
from app.models.user import User
from app.schemas.tenancy import (
    BackupSnapshotRead,
    BreachAlertRead,
    IsolationSummary,
    ProvisioningJobRead,
    ProvisioningStepRead,
    TenancyOverview,
    TenantCreate,
    TenantMemberCreate,
    TenantMemberRead,
    TenantRead,
    TenantSchemaValidationRead,
    TenantUpdate,
    TenantUsageSummary,
)

_STEP_LABELS = {
    "org_namespace_created": "Org namespace created",
    "network_policy_applied": "VPC + network policy applied",
    "schema_migration": "Schema migration running",
    "dek_generation": "DEK generation & HSM binding",
    "isolation_validation": "Isolation boundary validation",
    "initial_snapshot": "Initial backup snapshot",
}

_STALE_SNAPSHOT_AFTER_HOURS = 24


def tenant_to_read(tenant: Tenant) -> TenantRead:
    return TenantRead(
        id=tenant.id,
        slug=tenant.slug,
        org_id=tenant.org_id,
        display_name=tenant.display_name,
        tier=tenant.tier.value,
        isolation_mode=tenant.isolation_mode.value,
        status=tenant.status.value,
        region=tenant.region,
        db_schema_name=tenant.db_schema_name,
        db_schema_valid=tenant.db_schema_valid,
        network_cidr=tenant.network_cidr,
        network_vpc=tenant.network_vpc,
        network_shared=tenant.network_shared,
        dek_label=tenant.dek_label,
        encryption_valid=tenant.encryption_valid,
        events_per_second=tenant.events_per_second,
        isolation_score=tenant.isolation_score,
        isolation_level=tenant.isolation_level,
    )


def _isolation_summary(tenants: list[Tenant]) -> IsolationSummary:
    counts = {"strict": 0, "partial": 0, "breach": 0, "pending": 0}
    for tenant in tenants:
        counts[tenant.isolation_level] = counts.get(tenant.isolation_level, 0) + 1
    return IsolationSummary(
        enforced=counts["strict"],
        partial=counts["partial"],
        breach=counts["breach"],
        pending=counts["pending"],
        total=len(tenants),
    )


def provisioning_job_to_read(job: TenantProvisioningJob, tenant_slug: str) -> ProvisioningJobRead:
    steps = []
    reached_current = False
    for step_key in PROVISIONING_STEPS:
        if step_key in job.completed_steps:
            step_status = "done"
        elif not reached_current and job.current_step == step_key:
            step_status = "in_progress"
            reached_current = True
        elif not reached_current and job.current_step is None:
            step_status = "pending"
        else:
            step_status = "pending"
        steps.append(
            ProvisioningStepRead(key=step_key, label=_STEP_LABELS[step_key], status=step_status)
        )
    return ProvisioningJobRead(
        id=job.id,
        tenant_slug=tenant_slug,
        status=job.status.value,
        percent_complete=job.percent_complete,
        steps=steps,
        eta_seconds=job.eta_seconds,
    )


def _effective_snapshot_status(snapshot: TenantBackupSnapshot, now: datetime) -> str:
    if snapshot.status == SnapshotStatus.PENDING:
        return SnapshotStatus.PENDING.value
    if snapshot.taken_at and (now - snapshot.taken_at).total_seconds() > (
        _STALE_SNAPSHOT_AFTER_HOURS * 3600
    ):
        return SnapshotStatus.STALE.value
    return SnapshotStatus.CURRENT.value


async def get_tenancy_overview(db: AsyncSession) -> TenancyOverview:
    now = datetime.now(timezone.utc)

    tenants_result = await db.execute(select(Tenant).order_by(Tenant.display_name))
    tenants = list(tenants_result.scalars().all())
    tenants_by_id = {t.id: t for t in tenants}

    alerts_result = await db.execute(
        select(BreachAlert)
        .where(BreachAlert.dismissed.is_(False))
        .order_by(BreachAlert.detected_at.desc())
    )
    alerts = alerts_result.scalars().all()

    jobs_result = await db.execute(
        select(TenantProvisioningJob)
        .options(selectinload(TenantProvisioningJob.tenant))
        .order_by(TenantProvisioningJob.created_at.desc())
    )
    jobs = jobs_result.scalars().all()

    validations_result = await db.execute(
        select(TenantSchemaValidation)
        .options(selectinload(TenantSchemaValidation.tenant))
        .order_by(TenantSchemaValidation.validated_at.desc())
        .limit(20)
    )
    validations = validations_result.scalars().all()

    snapshots_result = await db.execute(
        select(TenantBackupSnapshot).options(selectinload(TenantBackupSnapshot.tenant))
    )
    snapshots = snapshots_result.scalars().all()

    return TenancyOverview(
        tenants=[tenant_to_read(t) for t in tenants],
        isolation_summary=_isolation_summary(tenants),
        breach_alerts=[
            BreachAlertRead(
                id=a.id,
                severity=a.severity.value,
                title=a.title,
                description=a.description,
                source_tenant_slug=tenants_by_id.get(a.source_tenant_id).slug
                if a.source_tenant_id in tenants_by_id
                else None,
                target_tenant_slug=tenants_by_id.get(a.target_tenant_id).slug
                if a.target_tenant_id in tenants_by_id
                else None,
                resource=a.resource,
                principal=a.principal,
                action_taken=a.action_taken,
                detected_at=a.detected_at,
                dismissed=a.dismissed,
            )
            for a in alerts
        ],
        active_provisioning=[
            provisioning_job_to_read(j, j.tenant.slug) for j in jobs if j.tenant is not None
        ],
        schema_validations=[
            TenantSchemaValidationRead(
                tenant_slug=v.tenant.slug,
                schema_name=v.schema_name,
                schema_version=v.schema_version,
                table_count=v.table_count,
                status=v.status,
                detail=v.detail,
                validated_at=v.validated_at,
            )
            for v in validations
        ],
        backup_snapshots=[
            BackupSnapshotRead(
                tenant_slug=s.tenant.slug,
                status=_effective_snapshot_status(s, now),
                size_bytes=s.size_bytes,
                taken_at=s.taken_at,
                age_hours=round((now - s.taken_at).total_seconds() / 3600, 1)
                if s.taken_at
                else None,
                retention_days=s.retention_days,
                retained_count=s.retained_count,
                stale_reason=s.stale_reason,
            )
            for s in snapshots
        ],
        total_events_per_second=round(sum(t.events_per_second for t in tenants), 1),
    )


async def dismiss_breach_alert(db: AsyncSession, alert_id: uuid.UUID) -> BreachAlert:
    alert = await db.get(BreachAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.dismissed = True
    alert.dismissed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)
    return alert


async def advance_provisioning_job(db: AsyncSession, job_id: uuid.UUID) -> TenantProvisioningJob:
    """Marks the current step complete and advances to the next one.

    Mirrors what a real orchestration worker would do after each step's
    async task succeeds; exposed as an endpoint here so the flow can be
    driven/demoed without a background worker.
    """
    result = await db.execute(
        select(TenantProvisioningJob)
        .options(selectinload(TenantProvisioningJob.tenant))
        .where(TenantProvisioningJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provisioning job not found")

    remaining = [s for s in PROVISIONING_STEPS if s not in job.completed_steps]
    if not remaining:
        return job

    completed_step = remaining[0]
    job.completed_steps = [*job.completed_steps, completed_step]
    still_remaining = [s for s in PROVISIONING_STEPS if s not in job.completed_steps]
    job.current_step = still_remaining[0] if still_remaining else None

    if not still_remaining:
        job.status = job.status.__class__.COMPLETE
        if job.tenant:
            job.tenant.status = job.tenant.status.__class__.ACTIVE

    await db.commit()
    await db.refresh(job, attribute_names=["tenant"])
    return job


async def list_tenants(
    db: AsyncSession,
    *,
    page: int,
    page_size: int,
    status_filter: TenantStatus | None = None,
    search: str | None = None,
) -> tuple[list[TenantRead], int]:
    query = select(Tenant)
    count_query = select(func.count()).select_from(Tenant)

    if status_filter is not None:
        query = query.where(Tenant.status == status_filter)
        count_query = count_query.where(Tenant.status == status_filter)
    if search:
        pattern = f"%{search}%"
        condition = Tenant.display_name.ilike(pattern) | Tenant.slug.ilike(pattern)
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = (await db.execute(count_query)).scalar_one()

    query = (
        query.order_by(Tenant.display_name).offset((page - 1) * page_size).limit(page_size)
    )
    tenants = (await db.execute(query)).scalars().all()
    return [tenant_to_read(t) for t in tenants], total


async def get_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> Tenant:
    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return tenant


async def create_tenant(db: AsyncSession, payload: TenantCreate) -> Tenant:
    tenant = Tenant(
        id=uuid.uuid4(),
        slug=payload.slug,
        org_id=payload.org_id,
        display_name=payload.display_name,
        tier=payload.tier,
        isolation_mode=payload.isolation_mode,
        status=TenantStatus.PROVISIONING,
        region=payload.region,
        db_schema_name=payload.db_schema_name,
        db_schema_valid=False,
        network_cidr=payload.network_cidr,
        network_vpc=payload.network_vpc,
        network_shared=payload.network_shared,
        dek_label=payload.dek_label,
        encryption_valid=False,
        events_per_second=0.0,
    )
    db.add(tenant)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A tenant with this slug or org_id already exists",
        ) from exc

    db.add(
        TenantProvisioningJob(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            status=ProvisioningJobStatus.RUNNING,
            completed_steps=[],
            current_step=PROVISIONING_STEPS[0],
        )
    )
    await db.commit()
    await db.refresh(tenant)
    return tenant


async def update_tenant(db: AsyncSession, tenant_id: uuid.UUID, payload: TenantUpdate) -> Tenant:
    tenant = await get_tenant(db, tenant_id)
    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(tenant, field, value)
    await db.commit()
    await db.refresh(tenant)
    return tenant


async def set_tenant_status(
    db: AsyncSession, tenant_id: uuid.UUID, new_status: TenantStatus
) -> Tenant:
    tenant = await get_tenant(db, tenant_id)
    tenant.status = new_status
    await db.commit()
    await db.refresh(tenant)
    return tenant


async def delete_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    tenant = await get_tenant(db, tenant_id)
    await db.delete(tenant)
    await db.commit()


def tenant_member_to_read(member: TenantMember) -> TenantMemberRead:
    return TenantMemberRead(
        id=member.id,
        tenant_id=member.tenant_id,
        user_id=member.user_id,
        email=member.user.email,
        display_name=member.user.display_name,
        role=member.role.value,
        created_at=member.created_at,
    )


async def list_tenant_members(
    db: AsyncSession, tenant_id: uuid.UUID
) -> list[TenantMemberRead]:
    await get_tenant(db, tenant_id)  # 404 if the tenant does not exist
    result = await db.execute(
        select(TenantMember)
        .options(selectinload(TenantMember.user))
        .where(TenantMember.tenant_id == tenant_id)
        .order_by(TenantMember.created_at)
    )
    return [tenant_member_to_read(m) for m in result.scalars().all()]


async def add_tenant_member(
    db: AsyncSession, tenant_id: uuid.UUID, payload: TenantMemberCreate
) -> TenantMemberRead:
    await get_tenant(db, tenant_id)
    user = await db.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    member = TenantMember(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        user_id=payload.user_id,
        role=payload.role,
    )
    db.add(member)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a member of this tenant",
        ) from exc
    await db.commit()

    # Re-select with the user eagerly loaded so the response can include the
    # member's email / display name without a lazy load on an expired instance.
    result = await db.execute(
        select(TenantMember)
        .options(selectinload(TenantMember.user))
        .where(TenantMember.id == member.id)
    )
    return tenant_member_to_read(result.scalar_one())


async def remove_tenant_member(
    db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> None:
    result = await db.execute(
        select(TenantMember).where(
            TenantMember.tenant_id == tenant_id, TenantMember.user_id == user_id
        )
    )
    member = result.scalar_one_or_none()
    if member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Tenant membership not found"
        )
    await db.delete(member)
    await db.commit()


async def get_tenant_usage(db: AsyncSession, tenant_id: uuid.UUID) -> TenantUsageSummary:
    tenant = await get_tenant(db, tenant_id)

    async def _count(query) -> int:
        return (await db.execute(query)).scalar_one()

    member_count = await _count(
        select(func.count())
        .select_from(TenantMember)
        .where(TenantMember.tenant_id == tenant_id)
    )
    provisioning_total = await _count(
        select(func.count())
        .select_from(TenantProvisioningJob)
        .where(TenantProvisioningJob.tenant_id == tenant_id)
    )
    provisioning_active = await _count(
        select(func.count())
        .select_from(TenantProvisioningJob)
        .where(
            TenantProvisioningJob.tenant_id == tenant_id,
            TenantProvisioningJob.status == ProvisioningJobStatus.RUNNING,
        )
    )
    schema_total = await _count(
        select(func.count())
        .select_from(TenantSchemaValidation)
        .where(TenantSchemaValidation.tenant_id == tenant_id)
    )
    snapshot_total = await _count(
        select(func.count())
        .select_from(TenantBackupSnapshot)
        .where(TenantBackupSnapshot.tenant_id == tenant_id)
    )
    # "Current" mirrors the tenancy overview's currency rule
    # (_effective_snapshot_status): a snapshot counts only if it is not pending
    # and was taken within the staleness window (or has no timestamp yet). A
    # stored-CURRENT row that has since aged past the window is stale, not
    # current — so the two endpoints never disagree about backup health.
    stale_cutoff = datetime.now(timezone.utc) - timedelta(hours=_STALE_SNAPSHOT_AFTER_HOURS)
    snapshot_current = await _count(
        select(func.count())
        .select_from(TenantBackupSnapshot)
        .where(
            TenantBackupSnapshot.tenant_id == tenant_id,
            TenantBackupSnapshot.status != SnapshotStatus.PENDING,
            or_(
                TenantBackupSnapshot.taken_at.is_(None),
                TenantBackupSnapshot.taken_at >= stale_cutoff,
            ),
        )
    )

    return TenantUsageSummary(
        tenant_id=tenant.id,
        slug=tenant.slug,
        display_name=tenant.display_name,
        status=tenant.status.value,
        member_count=member_count,
        events_per_second=tenant.events_per_second,
        provisioning_jobs_total=provisioning_total,
        active_provisioning_jobs=provisioning_active,
        schema_validations_total=schema_total,
        backup_snapshots_total=snapshot_total,
        current_backup_snapshots=snapshot_current,
        isolation_score=tenant.isolation_score,
        isolation_level=tenant.isolation_level,
    )
