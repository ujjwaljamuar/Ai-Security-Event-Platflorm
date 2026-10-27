from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "development"
    aws_region: str = "ap-south-1"
    kinesis_stream_name: str = "security-events-dev"

    sqlite_path: str = "./data/security_events.db"

    brute_force_threshold: int = Field(default=5, ge=1)
    brute_force_window_seconds: int = Field(default=300, gt=0)

    llm_api_key: str | None = Field(default=None, repr=False)
    jwt_secret: str | None = None
    jwt_issuer: str = "ai-security-event-platform"
    jwt_audience: str = "security-event-api"


@lru_cache
def get_settings() -> Settings:
    return Settings()
