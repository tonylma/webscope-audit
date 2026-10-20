from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import ScanCreateRequest, ScanReport, ScanResult
from app.services.scanner_service import analyze_target
from app.tasks import scan_url_task

app = FastAPI(title='WebScope Audit API', version='1.0.0', docs_url='/docs')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

SCAN_STORE: Dict[int, Dict[str, Any]] = {}


@app.get('/health')
def healthcheck():
    return {
        'status': 'ok',
        'service': 'webscope-audit',
        'version': '1.0.0',
    }


@app.post('/scan', response_model=ScanResult)
def create_scan(payload: ScanCreateRequest):
    try:
        result = analyze_target(str(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_id = len(SCAN_STORE) + 1
    result['scan_id'] = scan_id
    SCAN_STORE[scan_id] = result

    return ScanResult(
        id=scan_id,
        target_url=result['target_url'],
        status='completed',
        risk_score=result['risk_score'],
        summary=result['summary'],
    )


@app.post('/scan/async', response_model=ScanResult)
def create_scan_async(payload: ScanCreateRequest):
    try:
        result = analyze_target(str(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        job = scan_url_task.apply_async(args=[str(payload.url)])
        result['scan_id'] = len(SCAN_STORE) + 1
        result['job_id'] = job.id
        SCAN_STORE[result['scan_id']] = result
        return ScanResult(
            id=result['scan_id'],
            target_url=result['target_url'],
            status='queued',
            risk_score=result['risk_score'],
            summary=result['summary'],
        )
    except Exception:
        scan_id = len(SCAN_STORE) + 1
        result['scan_id'] = scan_id
        SCAN_STORE[scan_id] = result
        return ScanResult(
            id=scan_id,
            target_url=result['target_url'],
            status='completed',
            risk_score=result['risk_score'],
            summary=result['summary'],
        )


@app.get('/scan/{scan_id}', response_model=ScanResult)
def get_scan(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')

    return ScanResult(
        id=scan_id,
        target_url=result['target_url'],
        status='completed',
        risk_score=result['risk_score'],
        summary=result['summary'],
    )


@app.get('/scan/{scan_id}/report', response_model=ScanReport)
def get_report(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Rapport introuvable')

    return ScanReport(
        scan_id=scan_id,
        summary=result['summary'],
        risk_score=result['risk_score'],
        status='completed',
        findings=[
            {
                'category': finding.get('category', 'general'),
                'title': finding.get('title', 'Signalement'),
                'severity': finding.get('severity', 'medium'),
                'description': finding.get('description', ''),
                'evidence': finding.get('evidence', ''),
            }
            for finding in result.get('findings', [])
        ],
        subdomains=[{'name': s, 'ip': None, 'status': 'active'} for s in result.get('subdomains', [])],
        urls=[{'url': u, 'source': 'crawl', 'status_code': 200, 'depth': 1} for u in result.get('urls', [])],
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
