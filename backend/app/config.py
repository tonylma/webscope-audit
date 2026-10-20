from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = 'WebScope Audit'
    debug: bool = False
    environment: str = 'development'
    celery_broker_url: str = 'redis://localhost:6379/0'
    celery_result_backend: str = 'redis://localhost:6379/0'
    max_scan_depth: int = 2
    max_urls_per_scan: int = 100
    max_download_size_bytes: int = 2_000_000
    timeout_seconds: int = 10

    model_config = SettingsConfigDict(env_file='.env', extra='ignore')


@lru_cache
def get_settings() -> Settings:
    return Settings()
