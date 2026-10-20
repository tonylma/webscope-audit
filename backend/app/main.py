from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    'webscope_tasks',
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=['app.tasks']
)


@celery_app.task(name='webscope.create_scan')
def create_scan_task(target_url: str):
    from app.services.scanner_service import analyze_target

    result = analyze_target(target_url)
    return result
