from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.compliance import ComplianceOverview
from app.services.compliance_service import get_compliance_overview

router = APIRouter()


@router.get("/overview", response_model=ComplianceOverview)
async def read_compliance_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ComplianceOverview:
    return await get_compliance_overview(db)
