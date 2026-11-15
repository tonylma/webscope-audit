from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.security import require_analyst_key

router = APIRouter(tags=["history"], dependencies=[Depends(require_analyst_key)])
SCAN_STORE: dict[int, dict] = {}

@router.get("/history")
def get_history():
    scans = []
    for scan_id, item in sorted(SCAN_STORE.items(), reverse=True):
        scans.append({
            "id": scan_id,
            "target_url": item.get("target_url", ""),
            "status": "completed",
            "risk_score": item.get("risk_score", 0),
            "summary": item.get("summary", ""),
        })
    return {"scans": scans}
