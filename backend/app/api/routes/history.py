from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.routes.auth import require_roles
from app.db.models import ScanRecord
from app.db.session import get_db

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/{scan_id}")
def get_report_data(scan_id: int, _: object = Depends(require_roles("security_analyst", "fraud_analyst", "auditor", "reader")),
                    db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return {"report": record.payload_json or {
        "scan_id": record.id, "target_url": record.target_url, "status": record.status,
        "risk_score": record.risk_score, "summary": record.summary,
    }}
