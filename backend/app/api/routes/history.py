from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.core.security import require_analyst_key
from app.api.routes.scans import SCAN_STORE

router = APIRouter(prefix="/reports", tags=["reports"], dependencies=[Depends(require_analyst_key)])

@router.get("/{scan_id}")
def get_report_data(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return {"report": result}
