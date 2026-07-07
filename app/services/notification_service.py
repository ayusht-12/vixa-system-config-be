import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.notification import AlertRule, Notification, NotificationSeverity
from app.schemas.notification import (
    AlertRuleCreate,
    AlertRuleRead,
    AlertRuleUpdate,
    MarkAllReadResponse,
    NotificationRead,
    UnreadCountResponse,
)


# --------------------------------------------------------------------------- #
# Notifications (scoped to the requesting user)
# --------------------------------------------------------------------------- #


def _notification_to_read(row: Notification) -> NotificationRead:
    return NotificationRead(
        id=row.id,
        severity=row.severity.value,
        category=row.category,
        title=row.title,
        body=row.body,
        source=row.source,
        link=row.link,
        is_read=row.is_read,
        read_at=row.read_at,
        created_at=row.created_at,
    )


async def list_notifications(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    unread_only: bool = False,
    category: str | None = None,
    limit: int = 50,
) -> list[NotificationRead]:
    query = select(Notification).where(Notification.user_id == user_id)
    if unread_only:
        query = query.where(Notification.is_read.is_(False))
    if category:
        query = query.where(Notification.category == category)
    query = query.order_by(Notification.created_at.desc()).limit(limit)
    rows = (await db.execute(query)).scalars().all()
    return [_notification_to_read(r) for r in rows]


async def get_unread_count(db: AsyncSession, user_id: uuid.UUID) -> UnreadCountResponse:
    total = (
        await db.execute(
            select(func.count()).select_from(Notification).where(Notification.user_id == user_id)
        )
    ).scalar_one()
    unread = (
        await db.execute(
            select(func.count())
            .select_from(Notification)
            .where(Notification.user_id == user_id, Notification.is_read.is_(False))
        )
    ).scalar_one()
    return UnreadCountResponse(unread=unread, total=total)


async def mark_notification_read(
    db: AsyncSession, user_id: uuid.UUID, notification_id: uuid.UUID
) -> NotificationRead:
    notification = await db.get(Notification, notification_id)
    # 404 rather than 403 for another user's id so ownership isn't disclosed.
    if notification is None or notification.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found"
        )
    if not notification.is_read:
        notification.is_read = True
        notification.read_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(notification)
    return _notification_to_read(notification)


async def mark_all_read(db: AsyncSession, user_id: uuid.UUID) -> MarkAllReadResponse:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(Notification)
        .where(Notification.user_id == user_id, Notification.is_read.is_(False))
        .values(is_read=True, read_at=now)
    )
    await db.commit()
    return MarkAllReadResponse(detail="All notifications marked read", marked_read=result.rowcount or 0)


# --------------------------------------------------------------------------- #
# Alert rules (admin-configured)
# --------------------------------------------------------------------------- #


def _alert_rule_to_read(rule: AlertRule) -> AlertRuleRead:
    return AlertRuleRead(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        source=rule.source,
        condition=rule.condition,
        threshold_severity=rule.threshold_severity.value,
        channel=rule.channel.value,
        target=rule.target,
        is_enabled=rule.is_enabled,
        created_by=rule.created_by,
        last_triggered_at=rule.last_triggered_at,
        trigger_count=rule.trigger_count,
        created_at=rule.created_at,
    )


async def list_alert_rules(
    db: AsyncSession, *, source: str | None = None, is_enabled: bool | None = None
) -> list[AlertRuleRead]:
    query = select(AlertRule).order_by(AlertRule.name)
    if source:
        query = query.where(AlertRule.source == source)
    if is_enabled is not None:
        query = query.where(AlertRule.is_enabled == is_enabled)
    rules = (await db.execute(query)).scalars().all()
    return [_alert_rule_to_read(r) for r in rules]


async def _get_rule_orm(db: AsyncSession, rule_id: uuid.UUID) -> AlertRule:
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")
    return rule


async def create_alert_rule(
    db: AsyncSession, payload: AlertRuleCreate, *, created_by: str
) -> AlertRuleRead:
    existing = (
        await db.execute(select(AlertRule).where(AlertRule.name == payload.name))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An alert rule with this name already exists",
        )
    rule = AlertRule(
        id=uuid.uuid4(),
        name=payload.name,
        description=payload.description,
        source=payload.source,
        condition=payload.condition,
        threshold_severity=payload.threshold_severity,
        channel=payload.channel,
        target=payload.target,
        is_enabled=payload.is_enabled,
        created_by=created_by,
        trigger_count=0,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _alert_rule_to_read(rule)


async def update_alert_rule(
    db: AsyncSession, rule_id: uuid.UUID, payload: AlertRuleUpdate
) -> AlertRuleRead:
    rule = await _get_rule_orm(db, rule_id)
    data = payload.model_dump(exclude_unset=True)

    new_name = data.get("name")
    if new_name is not None and new_name != rule.name:
        clash = (
            await db.execute(
                select(AlertRule).where(AlertRule.name == new_name, AlertRule.id != rule.id)
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An alert rule with this name already exists",
            )

    for field, value in data.items():
        setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    return _alert_rule_to_read(rule)


async def delete_alert_rule(db: AsyncSession, rule_id: uuid.UUID) -> None:
    rule = await _get_rule_orm(db, rule_id)
    await db.delete(rule)
    await db.commit()
