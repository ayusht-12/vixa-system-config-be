from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.engine import CommandCenterOverview
from app.services.engine_service import get_command_center_overview

router = APIRouter()


@router.get("/overview", response_model=CommandCenterOverview)
async def read_command_center_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> CommandCenterOverview:
    """Aggregate snapshot backing the Command Center screen."""
    return await get_command_center_overview(db)
