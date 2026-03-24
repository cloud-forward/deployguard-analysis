"""
Configuration management for the application.
"""
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    """
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    PROJECT_NAME: str = "deployguard-analysis"
    DEBUG: bool = False
    
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/deployguard"
    SCAN_CREATED_STALE_SECONDS: int = 1800

    S3_BUCKET_NAME: str = "dg-raw-scans"
    AWS_REGION: str = "ap-northeast-2"
    CORS_ALLOWED_ORIGINS: list[str] = [
        "http://localhost:5173",
        "https://deployguard.org",
    ]

    @field_validator("CORS_ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_allowed_origins(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.startswith("["):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


settings = Settings()
