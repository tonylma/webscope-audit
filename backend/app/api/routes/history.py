from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.routes.auth import require_roles
from app.db.user_models import User
from app.api.routes.scans import SCAN_STORE

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/{scan_id}")
def get_report_data(scan_id: int, _: User = Depends(require_roles("security_analyst", "fraud_analyst", "auditor", "reader"))):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return {"report": result}
