from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = 'WebScope Audit Premium'
    environment: str = 'development'
    debug: bool = False

    database_url: str = 'postgresql+psycopg://webscope:webscope@postgres:5432/webscope'
    redis_url: str = 'redis://redis:6379/0'
    celery_broker_url: str = 'redis://redis:6379/0'
    celery_result_backend: str = 'redis://redis:6379/0'

    max_scan_depth: int = 2
    max_urls_per_scan: int = 150
    max_download_size_bytes: int = 2_000_000
    timeout_seconds: int = 10
    allowed_schemes: str = 'http,https'

    model_config = SettingsConfigDict(env_file='.env', extra='ignore')


@lru_cache
def get_settings() -> Settings:
    return Settings()
