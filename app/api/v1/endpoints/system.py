import logging
import os

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.core.config import settings
from app.models.user import User
from app.schemas.system import (
    DependenciesResponse,
    DependencyHealth,
    LivenessResponse,
    ReadinessResponse,
    VersionResponse,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# Kept in sync with the version reported by the FastAPI app in app.main.
APP_VERSION = "0.1.0"


async def _check_database(db: AsyncSession, *, expose_detail: bool = False) -> DependencyHealth:
    """Probe database connectivity with a trivial round-trip query.

    Raw exception text can disclose host/port/driver internals, so it is only
    placed in the response for privileged callers (``expose_detail=True``). The
    unauthenticated readiness probe returns a generic reason instead; either
    way the real error is logged server-side.
    """
    try:
        await db.execute(text("SELECT 1"))
        return DependencyHealth(name="database", status="up")
    except Exception as exc:  # pragma: no cover - only on a real DB outage
        logger.warning("Database health check failed: %s", exc)
        detail = str(exc)[:200] if expose_detail else "unavailable"
        return DependencyHealth(name="database", status="down", detail=detail)


def _check_audit_signing_key() -> DependencyHealth:
    """The audit-log signing key is a real local dependency: without it the
    tamper-evident audit chain cannot be signed. It is generated at bootstrap,
    so its absence is reported honestly rather than treated as fatal here."""
    present = os.path.exists(settings.AUDIT_SIGNING_KEY_PATH)
    return DependencyHealth(
        name="audit_signing_key",
        status="up" if present else "down",
        detail=None if present else "signing key file not found (generated at bootstrap)",
    )


@router.get("/live", response_model=LivenessResponse)
async def liveness() -> LivenessResponse:
    """Liveness probe: the process is up and serving. Intentionally does no
    I/O so it never fails on a slow/unavailable dependency."""
    return LivenessResponse(status="alive")


@router.get("/ready", response_model=ReadinessResponse)
async def readiness(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> ReadinessResponse:
    """Readiness probe: reports whether hard dependencies are reachable.
    Unauthenticated so orchestrators (k8s, load balancers) can call it; it
    exposes only up/down states, never data. Returns 503 when not ready."""
    dependencies = [await _check_database(db)]
    ready = all(dep.status == "up" for dep in dependencies)
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(
        status="ready" if ready else "not_ready", dependencies=dependencies
    )


@router.get("/version", response_model=VersionResponse)
async def version(_: User = Depends(get_current_user)) -> VersionResponse:
    return VersionResponse(
        name=settings.PROJECT_NAME,
        version=APP_VERSION,
        environment=settings.ENVIRONMENT,
        api_prefix=settings.API_V1_PREFIX,
    )


@router.get("/dependencies", response_model=DependenciesResponse)
async def dependencies(
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> DependenciesResponse:
    checks = [await _check_database(db, expose_detail=True), _check_audit_signing_key()]
    healthy = all(check.status == "up" for check in checks)
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return DependenciesResponse(
        status="healthy" if healthy else "degraded", dependencies=checks
    )
