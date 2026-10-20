from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    'webscope_audit_tasks',
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=['app.workers.tasks'],
)

celery_app.conf.task_serializer = 'json'
celery_app.conf.result_serializer = 'json'
celery_app.conf.accept_content = ['json']
