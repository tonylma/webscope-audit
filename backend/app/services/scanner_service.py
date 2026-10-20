from __future__ import annotations

from app.workers.celery_app import celery_app


@celery_app.task(name='webscope.scan_task')
def scan_task(target_url: str):
    from app.services.scanner_service import run_scan

    return run_scan(target_url)
