from fastapi import APIRouter

from app.api.v1.endpoints import (
    anomalies,
    audit_log,
    auth,
    compliance,
    config_manager,
    dashboard,
    engine,
    hsm,
    notifications,
    operations,
    rbac,
    system,
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
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(system.router, prefix="/system", tags=["system"])
api_router.include_router(rbac.router, prefix="/rbac", tags=["rbac"])
api_router.include_router(notifications.router, tags=["notifications"])
api_router.include_router(notifications.alert_rules_router, tags=["notifications"])
api_router.include_router(operations.router, prefix="/operations", tags=["operations"])
