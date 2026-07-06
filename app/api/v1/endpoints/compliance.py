import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.compliance import AssessmentStatus, ControlStatus, FrameworkCode
from app.models.user import User
from app.schemas.compliance import (
    AssessmentCreate,
    AssessmentRead,
    ComplianceOverview,
    ComplianceSummary,
    ControlRead,
    FrameworkRead,
    GapRead,
    ScoreTrendsResponse,
)
from app.services.compliance_service import (
    complete_assessment,
    get_assessment,
    get_compliance_overview,
    get_compliance_summary,
    get_control,
    get_framework,
    get_gaps,
    get_score_trends,
    list_assessments,
    list_controls,
    list_frameworks,
    start_assessment,
)

router = APIRouter()


@router.get("/overview", response_model=ComplianceOverview)
async def read_compliance_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ComplianceOverview:
    return await get_compliance_overview(db)


@router.get("/frameworks", response_model=list[FrameworkRead])
async def read_frameworks(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[FrameworkRead]:
    return await list_frameworks(db)


@router.get("/frameworks/{framework_id}", response_model=FrameworkRead)
async def read_framework(
    framework_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> FrameworkRead:
    return await get_framework(db, framework_id)


@router.get("/controls", response_model=list[ControlRead])
async def read_controls(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    framework: FrameworkCode | None = Query(default=None),
    status_filter: ControlStatus | None = Query(default=None, alias="status"),
) -> list[ControlRead]:
    return await list_controls(db, framework_code=framework, control_status=status_filter)


@router.get("/controls/{control_id}", response_model=ControlRead)
async def read_control(
    control_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ControlRead:
    return await get_control(db, control_id)


@router.post("/assessments", response_model=AssessmentRead, status_code=201)
async def create_assessment(
    payload: AssessmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> AssessmentRead:
    return await start_assessment(db, payload, started_by=current_user.email)


@router.get("/assessments", response_model=list[AssessmentRead])
async def read_assessments(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    framework_id: uuid.UUID | None = Query(default=None),
    status_filter: AssessmentStatus | None = Query(default=None, alias="status"),
) -> list[AssessmentRead]:
    return await list_assessments(db, framework_id=framework_id, assessment_status=status_filter)


@router.get("/assessments/{assessment_id}", response_model=AssessmentRead)
async def read_assessment(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AssessmentRead:
    return await get_assessment(db, assessment_id)


@router.post("/assessments/{assessment_id}/complete", response_model=AssessmentRead)
async def finish_assessment(
    assessment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> AssessmentRead:
    return await complete_assessment(db, assessment_id)


@router.get("/summary", response_model=ComplianceSummary)
async def read_compliance_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ComplianceSummary:
    return await get_compliance_summary(db)


@router.get("/gaps", response_model=list[GapRead])
async def read_gaps(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    framework: FrameworkCode | None = Query(default=None),
) -> list[GapRead]:
    return await get_gaps(db, framework_code=framework)


@router.get("/score-trends", response_model=ScoreTrendsResponse)
async def read_score_trends(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    window_days: int = Query(default=30, ge=1, le=365),
) -> ScoreTrendsResponse:
    return await get_score_trends(db, window_days=window_days)
