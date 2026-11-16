from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.routes.auth import require_roles
from app.db.models import ScanRecord
from app.db.session import get_db

router = APIRouter(tags=["history"])

@router.get("/history")
def get_history(_: object = Depends(require_roles("security_analyst", "fraud_analyst", "auditor", "reader")),
                db: Session = Depends(get_db)):
    records = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(100).all()
    return {"scans": [{
        "id": item.id,
        "target_url": item.target_url,
        "status": item.status,
        "risk_score": item.risk_score,
        "summary": item.summary,
    } for item in records]}
