from pydantic import BaseModel


class LivenessResponse(BaseModel):
    status: str  # "alive"


class DependencyHealth(BaseModel):
    name: str
    status: str  # "up" | "down"
    detail: str | None = None


class ReadinessResponse(BaseModel):
    status: str  # "ready" | "not_ready"
    dependencies: list[DependencyHealth]


class VersionResponse(BaseModel):
    name: str
    version: str
    environment: str
    api_prefix: str


class DependenciesResponse(BaseModel):
    status: str  # "healthy" | "degraded"
    dependencies: list[DependencyHealth]
