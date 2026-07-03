import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.user import User
from app.schemas.common import Message
from app.schemas.tenancy import ProvisioningJobRead, TenancyOverview
from app.services.tenancy_service import (
    advance_provisioning_job,
    dismiss_breach_alert,
    get_tenancy_overview,
    provisioning_job_to_read,
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
