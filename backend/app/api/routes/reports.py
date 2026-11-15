from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException

from app.api.routes.auth import require_roles
from app.db.user_models import User
from app.core.security import analyst_identity
from app.schemas import ScanCreateRequest, ScanReport, ScanResult
from app.services.audit_log import append_event
from app.services.scanner_service import run_scan
from app.api.routes.scans import SCAN_STORE

router = APIRouter(prefix="/scan", tags=["surface-audit"], dependencies=[Depends(require_roles("security_analyst", "auditor"))])

@router.post("", response_model=ScanResult)
def create_scan(payload: ScanCreateRequest, user: User = Depends(require_roles("security_analyst"))):
    try:
        result = run_scan(str(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan_id = max(SCAN_STORE.keys(), default=0) + 1
    result["scan_id"] = scan_id
    try:
        append_event("surface.url_analysis", user.username, {
            "scan_id": scan_id, "host": result.get("hostname"),
            "risk_score": result.get("risk_score", 0),
            "signal_codes": [item.get("code") for item in result.get("signals", [])],
            "network_access": "none",
        })
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Journal d'audit non configuré.") from exc
    SCAN_STORE[scan_id] = result
    return ScanResult(id=scan_id, target_url=result["target_url"], status="completed",
                      risk_score=result["risk_score"], summary=result["summary"])

@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return ScanResult(id=scan_id, target_url=result["target_url"], status="completed",
                      risk_score=result["risk_score"], summary=result["summary"])

@router.get("/{scan_id}/report", response_model=ScanReport)
def get_report(scan_id: int):
    result = SCAN_STORE.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    findings = [{
        "category": "url",
        "title": item.get("label", "Signalement"),
        "severity": item.get("severity", "low"),
        "description": item.get("explanation", ""),
        "evidence": item.get("code", ""),
    } for item in result.get("signals", [])]
    return ScanReport(scan_id=scan_id, summary=result["summary"], risk_score=result["risk_score"],
                      status="completed", findings=findings, subdomains=[], urls=[])
