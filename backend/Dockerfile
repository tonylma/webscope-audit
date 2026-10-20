from __future__ import annotations

from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import Scan
from app.schemas import ReportResponse, ScanCreateRequest, ScanResponse
from app.services.scanner_service import analyze_target

app = FastAPI(title='WebScope Audit API', version='1.0.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

SCAN_STORE: dict[int, dict] = {}


@app.get('/health')
def healthcheck():
    return {'status': 'ok', 'service': 'webscope-audit'}


@app.post('/scan', response_model=ScanResponse)
def create_scan(payload: ScanCreateRequest):
    try:
        result = analyze_target(str(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_id = len(SCAN_STORE) + 1
    SCAN_STORE[scan_id] = result
    return ScanResponse(
        id=scan_id,
        target_url=result['target_url'],
        status='completed',
        risk_score=result['risk_score'],
        summary=result['summary'],
    )


@app.get('/scan/{scan_id}', response_model=ScanResponse)
def get_scan(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')
    return ScanResponse(
        id=scan_id,
        target_url=result['target_url'],
        status='completed',
        risk_score=result['risk_score'],
        summary=result['summary'],
    )


@app.get('/scan/{scan_id}/report', response_model=ReportResponse)
def get_report(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')
    return ReportResponse(
        scan_id=scan_id,
        summary=result['summary'],
        risk_score=result['risk_score'],
        findings=result['findings'],
        subdomains=[{'name': s, 'status': 'active'} for s in result['subdomains']],
        urls=[{'url': u, 'source': 'crawl', 'status_code': 200, 'depth': 1} for u in result['urls']],
    )


@app.get('/history')
def history():
    return {
        'scans': [
            {
                'id': scan_id,
                'target_url': data['target_url'],
                'status': 'completed',
                'risk_score': data['risk_score'],
                'summary': data['summary'],
            }
            for scan_id, data in sorted(SCAN_STORE.items())
        ]
    }
