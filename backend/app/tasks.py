from __future__ import annotations

from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    'webscope_tasks',
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=['app.tasks'],
)


@celery_app.task(name='webscope.scan_url')
def scan_url_task(target_url: str):
    from app.services.scanner_service import analyze_target

    return analyze_target(target_url)
