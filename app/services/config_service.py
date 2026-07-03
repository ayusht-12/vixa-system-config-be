import uuid
from datetime import datetime, timezone
from itertools import groupby

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.config import ConfigChange, ConfigChangeStatus, ConfigParameter
from app.schemas.audit import AuditLogEntryCreate
from app.schemas.config import (
    ConfigChangeRead,
    ConfigManagerOverview,
    ConfigParameterRead,
    ConfigParameterStage,
    ConfigTierSummary,
)
from app.services.audit_service import append_entry_in_transaction


def _validate_value(parameter: ConfigParameter, value: str) -> None:
    if parameter.value_type.value == "enum" and parameter.allowed_values:
        allowed = {v.strip() for v in parameter.allowed_values.split(",")}
        if value not in allowed:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"'{value}' is not one of the allowed values for {parameter.key}: {sorted(allowed)}",
            )
    if parameter.value_type.value == "integer" and not value.lstrip("-").isdigit():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{parameter.key} expects an integer value",
        )
    if parameter.value_type.value == "boolean" and value.lower() not in {"true", "false"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{parameter.key} expects a boolean value ('true'/'false')",
        )


async def stage_config_change(
    db: AsyncSession, parameter_id: uuid.UUID, payload: ConfigParameterStage
) -> ConfigParameter:
    parameter = await db.get(ConfigParameter, parameter_id)
    if parameter is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parameter not found")

    _validate_value(parameter, payload.value)

    if payload.value == parameter.active_value:
        parameter.pending_value = None
    else:
        parameter.pending_value = payload.value
        db.add(
            ConfigChange(
                parameter_id=parameter.id,
                previous_value=parameter.active_value,
                new_value=payload.value,
                reason=payload.reason,
                changed_by=payload.changed_by,
                status=ConfigChangeStatus.PENDING,
            )
        )

    await db.commit()
    await db.refresh(parameter)
    return parameter


async def revert_config_change(db: AsyncSession, parameter_id: uuid.UUID) -> ConfigParameter:
    parameter = await db.get(ConfigParameter, parameter_id)
    if parameter is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parameter not found")

    parameter.pending_value = None

    pending_changes = await db.execute(
        select(ConfigChange).where(
            ConfigChange.parameter_id == parameter_id,
            ConfigChange.status == ConfigChangeStatus.PENDING,
        )
    )
    for change in pending_changes.scalars():
        change.status = ConfigChangeStatus.REVERTED

    await db.commit()
    await db.refresh(parameter)
    return parameter


async def apply_pending_changes(db: AsyncSession, changed_by: str = "admin@nexus") -> int:
    """Promote every staged value to active, close out its change record, and
    write one audit-log entry per applied parameter — config mutations are
    exactly the kind of event the immutable log exists to capture.
    """
    applied_count = 0
    async with db.begin():
        result = await db.execute(
            select(ConfigParameter).where(ConfigParameter.pending_value.is_not(None))
        )
        parameters = result.scalars().all()

        for parameter in parameters:
            pending_changes = await db.execute(
                select(ConfigChange).where(
                    ConfigChange.parameter_id == parameter.id,
                    ConfigChange.status == ConfigChangeStatus.PENDING,
                )
            )
            change = pending_changes.scalars().first()

            previous_value = parameter.active_value
            parameter.active_value = parameter.pending_value
            parameter.pending_value = None

            if change:
                change.status = ConfigChangeStatus.APPLIED
                change.applied_at = datetime.now(timezone.utc)

            await append_entry_in_transaction(
                db,
                AuditLogEntryCreate(
                    severity="info",
                    event_type="config_change",
                    event_subtype="PARAMETER_UPDATED",
                    actor=changed_by,
                    description=(
                        f"Config parameter '{parameter.key}' updated: "
                        f"{previous_value!r} -> {parameter.active_value!r}"
                    ),
                    metadata_json={
                        "parameter_key": parameter.key,
                        "previous_value": previous_value,
                        "new_value": parameter.active_value,
                        "requires_restart": parameter.requires_restart,
                    },
                ),
            )
            applied_count += 1

    return applied_count


async def get_config_manager_overview(db: AsyncSession) -> ConfigManagerOverview:
    result = await db.execute(
        select(ConfigParameter).order_by(ConfigParameter.section, ConfigParameter.key)
    )
    parameters = result.scalars().all()

    sections: dict[str, list[ConfigParameterRead]] = {}
    for section, group in groupby(parameters, key=lambda p: p.section):
        sections[section] = [ConfigParameterRead.from_model(p) for p in group]

    tier_counts: dict[str, list[int]] = {}
    for parameter in parameters:
        tier = parameter.tier.value
        counts = tier_counts.setdefault(tier, [0, 0])
        counts[0] += 1
        if parameter.has_pending_change:
            counts[1] += 1

    changes_result = await db.execute(
        select(ConfigChange)
        .where(ConfigChange.status == ConfigChangeStatus.PENDING)
        .order_by(ConfigChange.created_at.desc())
    )
    changes = changes_result.scalars().all()
    change_reads = []
    for change in changes:
        parameter = await db.get(ConfigParameter, change.parameter_id)
        change_reads.append(
            ConfigChangeRead(
                id=change.id,
                parameter_key=parameter.key if parameter else "unknown",
                previous_value=change.previous_value,
                new_value=change.new_value,
                reason=change.reason,
                changed_by=change.changed_by,
                status=change.status.value,
                created_at=change.created_at,
                applied_at=change.applied_at,
            )
        )

    return ConfigManagerOverview(
        sections=sections,
        tier_summary=[
            ConfigTierSummary(tier=tier, total=counts[0], pending=counts[1])
            for tier, counts in tier_counts.items()
        ],
        pending_changes=change_reads,
    )
