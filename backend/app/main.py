from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import ScanCreateRequest, ScanReport, ScanResult
from app.services.report_service import generate_report_html, generate_report_json
from app.services.scanner_service import analyze_target

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


@app.get('/scan/{scan_id}/subdomains')
def get_subdomains(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')
    return {'subdomains': result.get('subdomains', [])}


@app.get('/scan/{scan_id}/urls')
def get_urls(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')
    return {'urls': result.get('urls', [])}


@app.get('/scan/{scan_id}/files')
def get_files(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')
    return {'files': result.get('files', [])}


@app.get('/scan/{scan_id}/report', response_model=ScanReport)
def get_report(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')

    return ScanReport(
        scan_id=scan_id,
        summary=result['summary'],
        risk_score=result['risk_score'],
        status='completed',
        findings=[
            {
                'category': item.get('category', 'general'),
                'title': item.get('title', 'Signalement'),
                'severity': item.get('severity', 'medium'),
                'description': item.get('description', ''),
                'evidence': item.get('evidence', ''),
            }
            for item in result.get('findings', [])
        ],
        subdomains=[{'name': s, 'status': 'active'} for s in result.get('subdomains', [])],
        urls=[{'url': u, 'source': 'crawl', 'status_code': 200, 'depth': 1} for u in result.get('urls', [])],
    )


@app.get('/reports/{scan_id}')
def get_report_raw(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail='Scan introuvable')
    return {
        'html': generate_report_html(result),
        'json': generate_report_json(result),
    }


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
