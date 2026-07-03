from fastapi import APIRouter

from app.api.v1.endpoints import (
    anomalies,
    audit_log,
    auth,
    compliance,
    config_manager,
    engine,
    hsm,
    tenancy,
)

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(engine.router, prefix="/engine", tags=["command-center"])
api_router.include_router(anomalies.router, prefix="/anomalies", tags=["anomaly-detection"])
api_router.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
api_router.include_router(config_manager.router, prefix="/config", tags=["config-manager"])
api_router.include_router(audit_log.router, prefix="/audit-log", tags=["audit-log"])
api_router.include_router(hsm.router, prefix="/hsm", tags=["hsm-security"])
api_router.include_router(tenancy.router, prefix="/tenancy", tags=["tenancy"])
