from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.routes.auth import require_roles
from app.db.models import ScanRecord
from app.db.session import get_db
from app.db.user_models import User
from app.schemas import ScanCreateRequest, ScanReport, ScanResult
from app.services.audit_log import append_event
from app.services.scanner_service import run_scan

router = APIRouter(prefix="/scan", tags=["surface-audit"])

@router.post("", response_model=ScanResult)
def create_scan(payload: ScanCreateRequest, user: User = Depends(require_roles("security_analyst")),
                db: Session = Depends(get_db)):
    try:
        result = run_scan(str(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        record = ScanRecord(
            target_url=result["target_url"],
            status="completed",
            risk_score=result["risk_score"],
            summary=result["summary"],
            payload_json=result,
        )
        db.add(record)
        db.flush()
        append_event("surface.url_analysis", user.username, {
            "scan_id": record.id, "host": result.get("hostname"),
            "risk_score": result.get("risk_score", 0),
            "signal_codes": [item.get("code") for item in result.get("signals", [])],
            "network_access": "none",
        })
        db.commit()
        db.refresh(record)
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Journal d'audit non configuré.") from exc
    except Exception:
        db.rollback()
        raise
    return ScanResult(id=record.id, target_url=record.target_url, status=record.status,
                      risk_score=int(record.risk_score), summary=record.summary)

@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: int, _: object = Depends(require_roles("security_analyst", "auditor")),
             db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return ScanResult(id=record.id, target_url=record.target_url, status=record.status,
                      risk_score=int(record.risk_score), summary=record.summary)

@router.get("/{scan_id}/report", response_model=ScanReport)
def get_report(scan_id: int, _: object = Depends(require_roles("security_analyst", "auditor")),
               db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    result = record.payload_json or {}
    findings = [{
        "category": "url",
        "title": item.get("label", "Signalement"),
        "severity": item.get("severity", "low"),
        "description": item.get("explanation", ""),
        "evidence": item.get("code", ""),
    } for item in result.get("signals", [])]
    return ScanReport(scan_id=record.id, summary=record.summary, risk_score=int(record.risk_score),
                      status=record.status, findings=findings, subdomains=[], urls=[])
