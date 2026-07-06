import hashlib
import json
import uuid
from datetime import datetime, timezone
from itertools import groupby
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.config import (
    ConfigChange,
    ConfigChangeStatus,
    ConfigParameter,
    Configuration,
    ConfigurationStatus,
)
from app.schemas.audit import AuditLogEntryCreate
from app.schemas.config import (
    ConfigChangeRead,
    ConfigManagerOverview,
    ConfigParameterRead,
    ConfigParameterStage,
    ConfigTierSummary,
    ConfigurationCompareResponse,
    ConfigurationCreate,
    ConfigurationExportItem,
    ConfigurationExportResponse,
    ConfigurationImportRequest,
    ConfigurationImportResponse,
    ConfigurationImportResultRow,
    ConfigurationRead,
    ConfigurationUpdate,
    ConfigurationValidateRequest,
    ConfigurationValidateResponse,
)
from app.services.audit_service import append_entry_in_transaction

_REDACTED_CONFIG_VALUE = "[REDACTED]"


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
    try:
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
            audit_previous_value = (
                _REDACTED_CONFIG_VALUE if parameter.is_sensitive else previous_value
            )
            audit_new_value = (
                _REDACTED_CONFIG_VALUE if parameter.is_sensitive else parameter.active_value
            )

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
                        f"{audit_previous_value!r} -> {audit_new_value!r}"
                    ),
                    metadata_json={
                        "parameter_key": parameter.key,
                        "previous_value": audit_previous_value,
                        "new_value": audit_new_value,
                        "requires_restart": parameter.requires_restart,
                    },
                ),
            )
            applied_count += 1

        await db.commit()
    except Exception:
        await db.rollback()
        raise

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


# --------------------------------------------------------------------------- #
# Versioned configuration documents
# --------------------------------------------------------------------------- #

_MASK = "••••••••"
_MAX_PAYLOAD_KEYS = 200


def _checksum(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mask_payload(payload: dict[str, Any], sensitive_keys: list[str] | None) -> dict[str, Any]:
    sensitive = set(sensitive_keys or [])
    return {k: (_MASK if k in sensitive else v) for k, v in payload.items()}


def _to_read(config: Configuration) -> ConfigurationRead:
    return ConfigurationRead(
        id=config.id,
        name=config.name,
        version=config.version,
        status=config.status.value,
        payload=_mask_payload(config.payload, config.sensitive_keys),
        sensitive_keys=list(config.sensitive_keys or []),
        checksum=config.checksum,
        description=config.description,
        created_by=config.created_by,
        activated_at=config.activated_at,
        archived_at=config.archived_at,
        deleted_at=config.deleted_at,
        is_deleted=config.is_deleted,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


def _validate_payload(
    payload: dict[str, Any], sensitive_keys: list[str] | None
) -> list[str]:
    """Structural validation rules shared by create / update / validate / import."""
    errors: list[str] = []
    if not isinstance(payload, dict) or not payload:
        return ["payload must be a non-empty object"]
    if len(payload) > _MAX_PAYLOAD_KEYS:
        errors.append(f"payload has too many keys (>{_MAX_PAYLOAD_KEYS})")
    for key in payload:
        if not isinstance(key, str) or not key.strip():
            errors.append(f"invalid payload key: {key!r}")
        elif key != key.strip():
            errors.append(f"key '{key}' has leading/trailing whitespace")
    for sensitive_key in sensitive_keys or []:
        if sensitive_key not in payload:
            errors.append(f"sensitive key '{sensitive_key}' is not present in payload")
    return errors


async def _get_configuration_orm(db: AsyncSession, config_id: uuid.UUID) -> Configuration:
    config = await db.get(Configuration, config_id)
    if config is None or config.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Configuration not found"
        )
    return config


async def _next_version(db: AsyncSession, name: str) -> int:
    # Max over ALL rows (including soft-deleted) so version numbers stay
    # monotonic and never collide with the (name, version) unique constraint.
    result = await db.execute(
        select(func.max(Configuration.version)).where(Configuration.name == name)
    )
    return (result.scalar_one() or 0) + 1


async def _active_configuration(db: AsyncSession, name: str) -> Configuration | None:
    result = await db.execute(
        select(Configuration)
        .where(
            Configuration.name == name,
            Configuration.status == ConfigurationStatus.ACTIVE,
            Configuration.deleted_at.is_(None),
        )
        .order_by(Configuration.version.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _audit_config(
    db: AsyncSession, actor: str, subtype: str, description: str, metadata: dict
) -> None:
    await append_entry(
        db,
        AuditLogEntryCreate(
            severity="info",
            event_type="config_change",
            event_subtype=subtype,
            actor=actor,
            description=description,
            metadata_json=metadata,
        ),
    )


async def list_configurations(
    db: AsyncSession,
    *,
    name: str | None = None,
    config_status: ConfigurationStatus | None = None,
    include_deleted: bool = False,
) -> list[ConfigurationRead]:
    query = select(Configuration).order_by(
        Configuration.name, Configuration.version.desc()
    )
    if not include_deleted:
        query = query.where(Configuration.deleted_at.is_(None))
    if name is not None:
        query = query.where(Configuration.name == name)
    if config_status is not None:
        query = query.where(Configuration.status == config_status)
    result = await db.execute(query)
    return [_to_read(c) for c in result.scalars().all()]


async def create_configuration(
    db: AsyncSession, payload: ConfigurationCreate, created_by: str
) -> ConfigurationRead:
    existing = await db.execute(
        select(Configuration.id).where(Configuration.name == payload.name).limit(1)
    )
    if existing.first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Configuration '{payload.name}' already exists; PATCH it to add a version",
        )
    errors = _validate_payload(payload.payload, payload.sensitive_keys)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="; ".join(errors)
        )

    config = Configuration(
        id=uuid.uuid4(),
        name=payload.name,
        version=1,
        status=ConfigurationStatus.DRAFT,
        payload=payload.payload,
        sensitive_keys=payload.sensitive_keys,
        checksum=_checksum(payload.payload),
        description=payload.description,
        created_by=created_by,
    )
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return _to_read(config)


async def get_configuration(db: AsyncSession, config_id: uuid.UUID) -> ConfigurationRead:
    return _to_read(await _get_configuration_orm(db, config_id))


async def get_latest_configuration(db: AsyncSession, *, name: str) -> ConfigurationRead:
    result = await db.execute(
        select(Configuration)
        .where(Configuration.name == name, Configuration.deleted_at.is_(None))
        .order_by(Configuration.version.desc())
        .limit(1)
    )
    config = result.scalar_one_or_none()
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No configuration found for name '{name}'",
        )
    return _to_read(config)


async def get_latest_active_configuration(
    db: AsyncSession, *, name: str
) -> ConfigurationRead:
    config = await _active_configuration(db, name)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active configuration for name '{name}'",
        )
    return _to_read(config)


async def create_successor_version(
    db: AsyncSession, config_id: uuid.UUID, payload: ConfigurationUpdate, created_by: str
) -> ConfigurationRead:
    base = await _get_configuration_orm(db, config_id)
    sensitive = (
        payload.sensitive_keys if payload.sensitive_keys is not None else base.sensitive_keys
    )
    errors = _validate_payload(payload.payload, sensitive)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="; ".join(errors)
        )

    config = Configuration(
        id=uuid.uuid4(),
        name=base.name,
        version=await _next_version(db, base.name),
        status=ConfigurationStatus.DRAFT,
        payload=payload.payload,
        sensitive_keys=list(sensitive),
        checksum=_checksum(payload.payload),
        description=payload.description if payload.description is not None else base.description,
        created_by=created_by,
    )
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return _to_read(config)


async def delete_configuration(db: AsyncSession, config_id: uuid.UUID) -> None:
    config = await _get_configuration_orm(db, config_id)
    if config.status == ConfigurationStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete an active configuration; archive it first",
        )
    config.deleted_at = datetime.now(timezone.utc)
    await db.commit()


async def get_configuration_history(
    db: AsyncSession, config_id: uuid.UUID
) -> list[ConfigurationRead]:
    config = await _get_configuration_orm(db, config_id)
    result = await db.execute(
        select(Configuration)
        .where(Configuration.name == config.name, Configuration.deleted_at.is_(None))
        .order_by(Configuration.version.desc())
    )
    return [_to_read(c) for c in result.scalars().all()]


async def activate_configuration(
    db: AsyncSession, config_id: uuid.UUID, actor: str
) -> ConfigurationRead:
    config = await _get_configuration_orm(db, config_id)
    if config.status == ConfigurationStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Configuration version is already active",
        )
    now = datetime.now(timezone.utc)
    current = await _active_configuration(db, config.name)
    if current is not None and current.id != config.id:
        current.status = ConfigurationStatus.ARCHIVED
        current.archived_at = now
    config.status = ConfigurationStatus.ACTIVE
    config.activated_at = now
    config.archived_at = None
    await _audit_config(
        db,
        actor,
        "CONFIGURATION_ACTIVATED",
        f"Configuration '{config.name}' v{config.version} activated",
        {"name": config.name, "version": config.version, "checksum": config.checksum},
    )
    await db.commit()
    await db.refresh(config)
    return _to_read(config)


async def archive_configuration(
    db: AsyncSession, config_id: uuid.UUID, actor: str
) -> ConfigurationRead:
    config = await _get_configuration_orm(db, config_id)
    if config.status == ConfigurationStatus.ARCHIVED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Configuration version is already archived",
        )
    config.status = ConfigurationStatus.ARCHIVED
    config.archived_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(config)
    return _to_read(config)


async def rollback_configuration(
    db: AsyncSession, config_id: uuid.UUID, actor: str
) -> ConfigurationRead:
    """Roll back to an earlier version by creating a *new* version that copies
    its payload and activating it — history is preserved, never rewritten.
    """
    base = await _get_configuration_orm(db, config_id)
    now = datetime.now(timezone.utc)
    version = await _next_version(db, base.name)
    config = Configuration(
        id=uuid.uuid4(),
        name=base.name,
        version=version,
        status=ConfigurationStatus.DRAFT,
        payload=dict(base.payload),
        sensitive_keys=list(base.sensitive_keys or []),
        checksum=base.checksum,
        description=f"Rollback of '{base.name}' to v{base.version}",
        created_by=actor,
    )
    db.add(config)
    await db.flush()

    current = await _active_configuration(db, base.name)
    if current is not None and current.id != config.id:
        current.status = ConfigurationStatus.ARCHIVED
        current.archived_at = now
    config.status = ConfigurationStatus.ACTIVE
    config.activated_at = now

    await _audit_config(
        db,
        actor,
        "CONFIGURATION_ROLLED_BACK",
        f"Configuration '{base.name}' rolled back to v{base.version} (activated as v{version})",
        {"name": base.name, "restored_from_version": base.version, "new_version": version},
    )
    await db.commit()
    await db.refresh(config)
    return _to_read(config)


async def compare_configurations(
    db: AsyncSession, config_id: uuid.UUID, other_version: int
) -> ConfigurationCompareResponse:
    base = await _get_configuration_orm(db, config_id)
    result = await db.execute(
        select(Configuration).where(
            Configuration.name == base.name,
            Configuration.version == other_version,
            Configuration.deleted_at.is_(None),
        )
    )
    other = result.scalar_one_or_none()
    if other is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Version {other_version} not found for configuration '{base.name}'",
        )

    base_p, other_p = base.payload, other.payload
    base_m = _mask_payload(base_p, base.sensitive_keys)
    other_m = _mask_payload(other_p, other.sensitive_keys)
    base_keys, other_keys = set(base_p), set(other_p)

    added = {k: other_m[k] for k in other_keys - base_keys}
    removed = {k: base_m[k] for k in base_keys - other_keys}
    changed: dict[str, dict[str, Any]] = {}
    unchanged = 0
    for key in base_keys & other_keys:
        # Compare raw values to detect a change, but only ever surface the
        # masked values so sensitive data never leaks through a diff.
        if base_p[key] != other_p[key]:
            changed[key] = {"from": base_m[key], "to": other_m[key]}
        else:
            unchanged += 1

    return ConfigurationCompareResponse(
        name=base.name,
        base_version=base.version,
        other_version=other.version,
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged,
    )


async def validate_configuration_payload(
    req: ConfigurationValidateRequest,
) -> ConfigurationValidateResponse:
    errors = _validate_payload(req.payload, req.sensitive_keys)
    return ConfigurationValidateResponse(
        valid=not errors,
        errors=errors,
        checksum=_checksum(req.payload) if not errors else None,
    )


async def export_configurations(db: AsyncSession) -> ConfigurationExportResponse:
    result = await db.execute(
        select(Configuration)
        .where(Configuration.deleted_at.is_(None))
        .order_by(Configuration.name, Configuration.version)
    )
    # Metadata only — payloads (which may hold secrets) are never exported.
    items = [
        ConfigurationExportItem(
            name=c.name,
            version=c.version,
            status=c.status.value,
            checksum=c.checksum,
            description=c.description,
            created_by=c.created_by,
            created_at=c.created_at,
        )
        for c in result.scalars().all()
    ]
    return ConfigurationExportResponse(
        exported_at=datetime.now(timezone.utc), count=len(items), items=items
    )


async def import_configurations(
    db: AsyncSession, req: ConfigurationImportRequest, created_by: str
) -> ConfigurationImportResponse:
    rows: list[ConfigurationImportResultRow] = []
    imported = skipped = 0
    for item in req.items:
        errors = _validate_payload(item.payload, item.sensitive_keys)
        if errors:
            skipped += 1
            rows.append(
                ConfigurationImportResultRow(
                    name=item.name, version=None, outcome="skipped", detail="; ".join(errors)
                )
            )
            continue
        version = await _next_version(db, item.name)
        db.add(
            Configuration(
                id=uuid.uuid4(),
                name=item.name,
                version=version,
                status=ConfigurationStatus.DRAFT,
                payload=item.payload,
                sensitive_keys=item.sensitive_keys,
                checksum=_checksum(item.payload),
                description=item.description,
                created_by=created_by,
            )
        )
        # Flush so a repeated name within the same batch sees the prior insert
        # and increments the version rather than colliding on (name, version).
        await db.flush()
        imported += 1
        rows.append(
            ConfigurationImportResultRow(
                name=item.name, version=version, outcome="created", detail=f"created v{version}"
            )
        )
    await db.commit()
    return ConfigurationImportResponse(imported=imported, skipped=skipped, rows=rows)
