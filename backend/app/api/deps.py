from __future__ import annotations

from fastapi import APIRouter

from app.api.routes.scans import SCAN_STORE

router = APIRouter(tags=['history'])


@router.get('/history')
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
