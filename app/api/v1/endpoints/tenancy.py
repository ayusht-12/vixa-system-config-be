import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.core.config import settings
from app.models.tenancy import TenantStatus
from app.models.user import User
from app.schemas.common import Message, Page
from app.schemas.tenancy import (
    ProvisioningJobRead,
    TenancyOverview,
    TenantCreate,
    TenantMemberCreate,
    TenantMemberRead,
    TenantRead,
    TenantUpdate,
    TenantUsageSummary,
)
from app.services.tenancy_service import (
    add_tenant_member,
    advance_provisioning_job,
    create_tenant,
    delete_tenant,
    dismiss_breach_alert,
    get_tenancy_overview,
    get_tenant,
    get_tenant_usage,
    list_tenant_members,
    list_tenants,
    provisioning_job_to_read,
    remove_tenant_member,
    set_tenant_status,
    tenant_to_read,
    update_tenant,
)

router = APIRouter()


@router.get("/overview", response_model=TenancyOverview)
async def read_tenancy_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> TenancyOverview:
    return await get_tenancy_overview(db)


@router.post("/breach-alerts/{alert_id}/dismiss", response_model=Message)
async def dismiss_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> Message:
    await dismiss_breach_alert(db, alert_id)
    return Message(detail="Alert dismissed")


@router.post("/provisioning/{job_id}/advance", response_model=ProvisioningJobRead)
async def advance_provisioning(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> ProvisioningJobRead:
    job = await advance_provisioning_job(db, job_id)
    return provisioning_job_to_read(job, job.tenant.slug if job.tenant else "unknown")


@router.get("/tenants", response_model=Page[TenantRead])
async def read_tenants(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    status_filter: TenantStatus | None = Query(default=None, alias="status"),
    search: str | None = None,
) -> Page[TenantRead]:
    items, total = await list_tenants(
        db, page=page, page_size=page_size, status_filter=status_filter, search=search
    )
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/tenants/{tenant_id}", response_model=TenantRead)
async def read_tenant(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> TenantRead:
    tenant = await get_tenant(db, tenant_id)
    return tenant_to_read(tenant)


@router.post("/tenants", response_model=TenantRead, status_code=201)
async def provision_tenant(
    payload: TenantCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> TenantRead:
    tenant = await create_tenant(db, payload)
    return tenant_to_read(tenant)


@router.patch("/tenants/{tenant_id}", response_model=TenantRead)
async def patch_tenant(
    tenant_id: uuid.UUID,
    payload: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> TenantRead:
    tenant = await update_tenant(db, tenant_id, payload)
    return tenant_to_read(tenant)


@router.post("/tenants/{tenant_id}/activate", response_model=TenantRead)
async def activate_tenant(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> TenantRead:
    tenant = await set_tenant_status(db, tenant_id, TenantStatus.ACTIVE)
    return tenant_to_read(tenant)


@router.post("/tenants/{tenant_id}/deactivate", response_model=TenantRead)
async def deactivate_tenant(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> TenantRead:
    tenant = await set_tenant_status(db, tenant_id, TenantStatus.SUSPENDED)
    return tenant_to_read(tenant)


@router.delete("/tenants/{tenant_id}", response_model=Message)
async def remove_tenant(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> Message:
    await delete_tenant(db, tenant_id)
    return Message(detail="Tenant deleted successfully")


@router.get("/tenants/{tenant_id}/members", response_model=list[TenantMemberRead])
async def read_tenant_members(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[TenantMemberRead]:
    return await list_tenant_members(db, tenant_id)


@router.post(
    "/tenants/{tenant_id}/members", response_model=TenantMemberRead, status_code=201
)
async def add_member(
    tenant_id: uuid.UUID,
    payload: TenantMemberCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> TenantMemberRead:
    return await add_tenant_member(db, tenant_id, payload)


@router.delete("/tenants/{tenant_id}/members/{user_id}", response_model=Message)
async def remove_member(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> Message:
    await remove_tenant_member(db, tenant_id, user_id)
    return Message(detail="Member removed from tenant")


@router.get("/tenants/{tenant_id}/usage", response_model=TenantUsageSummary)
async def read_tenant_usage(
    tenant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> TenantUsageSummary:
    return await get_tenant_usage(db, tenant_id)
