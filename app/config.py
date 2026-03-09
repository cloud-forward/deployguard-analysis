"""
Configuration management for the application.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    """
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    PROJECT_NAME: str = "deployguard-analysis"
    DEBUG: bool = False
    
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/deployguard"

    S3_BUCKET_NAME: str = "dg-raw-scans"
    AWS_REGION: str = "ap-northeast-2"


settings = Settings()
