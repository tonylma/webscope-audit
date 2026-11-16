from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.routes.auth import require_roles
from app.db.models import FindingRecord, ScanRecord
from app.db.session import get_db
from app.db.user_models import User
from app.schemas import ScanCreateRequest, ScanReport, ScanResult
from app.services.audit_log import append_event
from app.services.scanner_service import run_scan

router = APIRouter(prefix="/scan", tags=["surface-audit"])

@router.post("", response_model=ScanResult)
def create_scan(payload: ScanCreateRequest, user: User = Depends(require_roles("security_analyst")),
                db: Session = Depends(get_db)):
    if not payload.authorized_scope:
        raise HTTPException(status_code=400, detail="Confirmez que vous êtes autorisé à auditer cette cible.")
    try:
        result = run_scan(str(payload.url), authorized_scope=True)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail="Audit réseau non concluant ; la cible n'a pas été scannée complètement.") from exc
    try:
        record = ScanRecord(
            target_url=result["target_url"],
            status="completed",
            risk_score=result["risk_score"],
            summary=result["summary"],
        )
        db.add(record)
        db.flush()
        for finding in result.get("findings", []):
            db.add(FindingRecord(
                scan_id=record.id,
                category=finding.get("category", "web_audit"),
                title=finding.get("title", "Signalement"),
                severity=finding.get("severity", "low"),
                description=finding.get("description", ""),
                evidence=finding.get("evidence", ""),
            ))
        append_event("surface.web_audit", user.username, {
            "scan_id": record.id, "host": result.get("hostname"),
            "risk_score": result.get("risk_score", 0),
            "finding_count": len(result.get("findings", [])),
            "network_access": result.get("network_access"),
            "authorized_scope": True,
        })
        db.commit()
        db.refresh(record)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Enregistrement de l'analyse impossible ; vérifier la base et le journal d'audit.") from exc
    return ScanResult(
        id=record.id, target_url=record.target_url, status=record.status,
        risk_score=int(record.risk_score), summary=record.summary,
    )

@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: int, _: User = Depends(require_roles("security_analyst", "auditor")),
             db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analyse introuvable.")
    return ScanResult(
        id=record.id, target_url=record.target_url, status=record.status,
        risk_score=int(record.risk_score), summary=record.summary,
    )

@router.get("/{scan_id}/report", response_model=ScanReport)
def get_report(scan_id: int, _: User = Depends(require_roles("security_analyst", "auditor")),
               db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analyse introuvable.")
    rows = db.query(FindingRecord).filter(FindingRecord.scan_id == scan_id).order_by(FindingRecord.id).all()
    findings = [{
        "category": item.category, "title": item.title, "severity": item.severity,
        "description": item.description, "evidence": item.evidence,
    } for item in rows]
    return ScanReport(
        scan_id=record.id, summary=record.summary, risk_score=int(record.risk_score),
        status=record.status, findings=findings, subdomains=[], urls=[],
    )
