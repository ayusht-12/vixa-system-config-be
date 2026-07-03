import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.anomaly import AnomalyStatus
from app.models.user import User
from app.schemas.anomaly import (
    AnomalyDetectionOverview,
    AnomalyEventCreate,
    AnomalyEventRead,
)
from app.services.anomaly_service import (
    create_anomaly_event,
    get_anomaly_detection_overview,
    update_anomaly_status,
)

router = APIRouter()


@router.get("/overview", response_model=AnomalyDetectionOverview)
async def read_anomaly_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnomalyDetectionOverview:
    return await get_anomaly_detection_overview(db)


@router.post("/events", response_model=AnomalyEventRead, status_code=status.HTTP_201_CREATED)
async def ingest_anomaly_event(
    payload: AnomalyEventCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await create_anomaly_event(db, payload)
    return AnomalyEventRead.model_validate(event)


@router.post("/events/{event_id}/acknowledge", response_model=AnomalyEventRead)
async def acknowledge_anomaly_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await update_anomaly_status(db, event_id, AnomalyStatus.INVESTIGATING)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return AnomalyEventRead.model_validate(event)


@router.post("/events/{event_id}/resolve", response_model=AnomalyEventRead)
async def resolve_anomaly_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await update_anomaly_status(db, event_id, AnomalyStatus.RESOLVED)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return AnomalyEventRead.model_validate(event)


@router.post("/events/{event_id}/dismiss", response_model=AnomalyEventRead)
async def dismiss_anomaly_event(
    event_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AnomalyEventRead:
    event = await update_anomaly_status(db, event_id, AnomalyStatus.DISMISSED)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly not found")
    return AnomalyEventRead.model_validate(event)
