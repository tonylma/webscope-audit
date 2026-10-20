from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.routes.scans import SCAN_STORE
from app.services.report_service import render_html_report, render_json_report

router = APIRouter(prefix='/reports', tags=['reports'])


@router.get('/{scan_id}')
def get_report_data(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')
    return {
        'html': render_html_report(result),
        'json': render_json_report(result),
    }
