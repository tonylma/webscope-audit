from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "WebScope Audit & Defense"
    environment: str = "development"
    debug: bool = False
    database_url: str = Field(min_length=10)
    max_scan_depth: int = Field(default=1, ge=0, le=3)
    max_urls_per_scan: int = Field(default=40, ge=1, le=100)
    max_download_size_bytes: int = Field(default=25_000_000, ge=1_000, le=25_000_000)
    timeout_seconds: int = Field(default=8, ge=1, le=30)
    cors_origins: str = "http://localhost:5173"
    rate_limit_per_minute: int = Field(default=60, ge=1, le=600)
    clamav_host: str = "clamav"
    clamav_port: int = Field(default=3310, ge=1, le=65535)
    clamav_max_bytes: int = Field(default=25_000_000, ge=1, le=25_000_000)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

@lru_cache
def get_settings() -> Settings:
    return Settings()
