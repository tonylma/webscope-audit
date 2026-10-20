from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, HTTPException

from app.schemas import ScanCreateRequest, ScanReport, ScanResult
from app.services.scanner_service import run_scan

router = APIRouter(prefix='/scan', tags=['scans'])
SCAN_STORE: Dict[int, Dict] = {}


@router.post('', response_model=ScanResult)
def create_scan(payload: ScanCreateRequest):
    try:
        result = run_scan(str(payload.url))
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


@router.get('/{scan_id}', response_model=ScanResult)
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


@router.get('/{scan_id}/report', response_model=ScanReport)
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
