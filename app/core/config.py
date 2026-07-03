from functools import lru_cache

from pydantic import PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration, sourced from environment variables / .env."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- General ---
    PROJECT_NAME: str = "Nexus Engine API"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"  # development | staging | production
    DEBUG: bool = True

    # --- Database ---
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "vscbe"
    POSTGRES_PASSWORD: str = "vscbe_dev_password"
    POSTGRES_DB: str = "vsc_be"
    DATABASE_URL: PostgresDsn | None = None

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_url(cls, value: str | None, info) -> str:
        if isinstance(value, str) and value:
            return value
        data = info.data
        return (
            f"postgresql+asyncpg://{data['POSTGRES_USER']}:{data['POSTGRES_PASSWORD']}"
            f"@{data['POSTGRES_HOST']}:{data['POSTGRES_PORT']}/{data['POSTGRES_DB']}"
        )

    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 5

    # --- Auth ---
    SECRET_KEY: str = "change-me-in-production-this-is-a-dev-only-secret"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # --- CORS ---
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # --- Audit log signing (ECDSA P-384, generated at bootstrap if absent) ---
    AUDIT_SIGNING_KEY_PATH: str = "./var/audit_signing_key.pem"

    # --- Pagination ---
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 200


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
