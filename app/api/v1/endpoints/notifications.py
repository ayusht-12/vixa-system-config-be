import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.user import User
from app.schemas.notification import (
    AlertRuleCreate,
    AlertRuleRead,
    AlertRuleUpdate,
    MarkAllReadResponse,
    NotificationRead,
    UnreadCountResponse,
)
from app.services.notification_service import (
    create_alert_rule,
    delete_alert_rule,
    get_unread_count,
    list_alert_rules,
    list_notifications,
    mark_all_read,
    mark_notification_read,
    update_alert_rule,
)

# Two routers: per-user notifications, and admin-managed alert rules.
router = APIRouter()
alert_rules_router = APIRouter(dependencies=[Depends(require_admin)])


# --------------------------------------------------------------------------- #
# Notifications (current user)
# --------------------------------------------------------------------------- #


@router.get("/notifications", response_model=list[NotificationRead])
async def read_notifications(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    unread_only: bool = False,
    category: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[NotificationRead]:
    return await list_notifications(
        db, current_user.id, unread_only=unread_only, category=category, limit=limit
    )


@router.get("/notifications/unread-count", response_model=UnreadCountResponse)
async def read_unread_count(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UnreadCountResponse:
    return await get_unread_count(db, current_user.id)


@router.post("/notifications/read-all", response_model=MarkAllReadResponse)
async def mark_all_notifications_read(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MarkAllReadResponse:
    return await mark_all_read(db, current_user.id)


@router.post("/notifications/{notification_id}/read", response_model=NotificationRead)
async def mark_notification_as_read(
    notification_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NotificationRead:
    return await mark_notification_read(db, current_user.id, notification_id)


# --------------------------------------------------------------------------- #
# Alert rules (admin)
# --------------------------------------------------------------------------- #


@alert_rules_router.get("/alert-rules", response_model=list[AlertRuleRead])
async def read_alert_rules(
    db: AsyncSession = Depends(get_db),
    source: str | None = Query(default=None),
    is_enabled: bool | None = None,
) -> list[AlertRuleRead]:
    return await list_alert_rules(db, source=source, is_enabled=is_enabled)


@alert_rules_router.post("/alert-rules", response_model=AlertRuleRead, status_code=201)
async def create_new_alert_rule(
    payload: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> AlertRuleRead:
    return await create_alert_rule(db, payload, created_by=current_user.email)


@alert_rules_router.patch("/alert-rules/{rule_id}", response_model=AlertRuleRead)
async def patch_alert_rule(
    rule_id: uuid.UUID,
    payload: AlertRuleUpdate,
    db: AsyncSession = Depends(get_db),
) -> AlertRuleRead:
    return await update_alert_rule(db, rule_id, payload)


@alert_rules_router.delete("/alert-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_alert_rule(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    await delete_alert_rule(db, rule_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
