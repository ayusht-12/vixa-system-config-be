import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.models.anomaly import AnomalySeverity, AnomalyStatus
from app.models.user import User
from app.schemas.anomaly import (
    AnomalyDetectionOverview,
    AnomalyEventCreate,
    AnomalyEventRead,
)
from app.schemas.common import Page
from app.services.anomaly_service import (
    create_anomaly_event,
    get_anomaly_detection_overview,
    get_anomaly_event,
    list_anomaly_events,
    update_anomaly_status,
)

router = APIRouter()


@router.get("/overview", response_model=AnomalyDetectionOverview)
async def read_anomaly_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnomalyDetectionOverview:
    return await get_anomaly_detection_overview(db)


@router.get("/events", response_model=Page[AnomalyEventRead])
async def read_anomaly_events(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    status_filter: AnomalyStatus | None = Query(default=None, alias="status"),
    severity: AnomalySeverity | None = None,
    category: str | None = None,
    tenant_id: uuid.UUID | None = None,
) -> Page[AnomalyEventRead]:
    items, total = await list_anomaly_events(
        db,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        severity_filter=severity,
        category=category,
        tenant_id=tenant_id,
    )
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/events/{event_id}", response_model=AnomalyEventRead)
async def read_anomaly_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await get_anomaly_event(db, event_id)
    return AnomalyEventRead.model_validate(event)


@router.post("/events", response_model=AnomalyEventRead, status_code=status.HTTP_201_CREATED)
async def ingest_anomaly_event(
    payload: AnomalyEventCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await create_anomaly_event(db, payload, audit_actor=current_user.email)
    return AnomalyEventRead.model_validate(event)


@router.post("/events/{event_id}/acknowledge", response_model=AnomalyEventRead)
async def acknowledge_anomaly_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await update_anomaly_status(
        db, event_id, AnomalyStatus.INVESTIGATING, audit_actor=current_user.email
    )
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return AnomalyEventRead.model_validate(event)


@router.post("/events/{event_id}/resolve", response_model=AnomalyEventRead)
async def resolve_anomaly_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await update_anomaly_status(
        db, event_id, AnomalyStatus.RESOLVED, audit_actor=current_user.email
    )
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return AnomalyEventRead.model_validate(event)


@router.post("/events/{event_id}/dismiss", response_model=AnomalyEventRead)
async def dismiss_anomaly_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await update_anomaly_status(
        db, event_id, AnomalyStatus.DISMISSED, audit_actor=current_user.email
    )
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return AnomalyEventRead.model_validate(event)


@router.post("/events/{event_id}/reopen", response_model=AnomalyEventRead)
async def reopen_anomaly_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await update_anomaly_status(
        db, event_id, AnomalyStatus.OPEN, audit_actor=current_user.email
    )
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return AnomalyEventRead.model_validate(event)
