from __future__ import annotations

import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.routes.auth import require_roles
from app.core.security import pseudonymize
from app.db.models import FraudCase
from app.db.session import get_db
from app.db.user_models import User
from app.services.audit_log import append_event, verify_chain
from app.services.crypto_service import decrypt_sensitive_data, encrypt_sensitive_data
from app.services.fraud_engine import CONTROL_CATALOG, F3_FRAMEWORK_URL, F3_VERSION, evaluate_mobile_money_event

router = APIRouter(prefix="/fraud", tags=["mobile-money-fraud"])

class FraudEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_reference: str | None = Field(default=None, max_length=120)
    sim_change_hours: float | None = Field(default=None, ge=0, le=8760)
    beneficiary_added: bool = False
    beneficiary_age_minutes: int | None = Field(default=None, ge=0, le=525600)
    remote_access_tool_detected: bool = False
    accessibility_abuse_detected: bool = False
    screen_capture_detected: bool = False
    app_integrity_warning: bool = False
    social_engineering_reported: bool = False
    phone_number_spoofing_suspected: bool = False
    otp_failures_15m: int = Field(default=0, ge=0, le=10000)
    new_device: bool = False
    impossible_travel: bool = False
    mobile_api_anomaly: bool = False
    transactions_10m: int = Field(default=0, ge=0, le=100000)
    amount_vs_30d_median: float = Field(default=1.0, ge=0, le=1000000)
    shared_beneficiary_accounts_24h: int = Field(default=0, ge=0, le=100000)
    rapid_cashout: bool = False
    channel: Literal["wallet", "bank_transfer", "cashout", "merchant", "unknown"] = "unknown"

class FraudCaseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "under_review", "escalated", "resolved", "false_positive"]
    review_note: str | None = Field(default=None, max_length=4000)

def _aad(case_id: int, field: str) -> bytes:
    return f"webscope:fraud-case:v1:{case_id}:{field}".encode("utf-8")

def _decrypt_case(case: FraudCase) -> dict:
    try:
        original = json.loads(decrypt_sensitive_data(case.encrypted_input, _aad(case.id, "input")))
        result = json.loads(decrypt_sensitive_data(case.encrypted_result, _aad(case.id, "result")))
        note = None
        if case.encrypted_review_note:
            note = decrypt_sensitive_data(case.encrypted_review_note, _aad(case.id, "review-note")).decode("utf-8")
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Données chiffrées du dossier invalides ou altérées.") from exc
    return {
        "id": case.id, "case_token": case.case_token, "status": case.status,
        "risk_score": case.risk_score, "risk_level": case.risk_level,
        "created_at": case.created_at, "updated_at": case.updated_at,
        "created_by_user_id": case.created_by_user_id, "reviewed_by_user_id": case.reviewed_by_user_id,
        "input": original, "evaluation": result, "review_note": note,
    }

@router.get("/framework")
def framework(_: User = Depends(require_roles("fraud_analyst", "auditor", "reader"))):
    return {
        "name": "MITRE Fight Fraud Framework", "version": F3_VERSION, "url": F3_FRAMEWORK_URL,
        "tactics": ["reconnaissance", "resource-development", "initial-access", "stealth",
                    "positioning", "execution", "monetization", "defense-impairment"],
        "note": "ATT&CK décrit les opérations techniques ; F3 relie l'accès, le positionnement, l'exécution et la monétisation de la fraude.",
    }

@router.get("/controls")
def controls(_: User = Depends(require_roles("fraud_analyst", "auditor", "reader"))):
    return {
        "controls": CONTROL_CATALOG, "count": len(CONTROL_CATALOG),
        "note": "Catalogue de tests de contrôle interne à adapter aux procédures, produits et obligations de l'établissement.",
    }

@router.post("/evaluate")
def evaluate(payload: FraudEventRequest, user: User = Depends(require_roles("fraud_analyst")),
             db: Session = Depends(get_db)):
    input_data = payload.model_dump()
    result = evaluate_mobile_money_event(payload.model_dump(exclude={"case_reference"}))
    seed = payload.case_reference.strip() if payload.case_reference else uuid.uuid4().hex
    case_token = pseudonymize(seed, f"fraud-case:{uuid.uuid4().hex}")[:32]
    record = FraudCase(
        case_token=case_token,
        created_by_user_id=user.id,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        status="open",
        encrypted_input="pending",
        encrypted_result="pending",
    )
    try:
        db.add(record)
        db.flush()
        record.encrypted_input = encrypt_sensitive_data(
            json.dumps(input_data, ensure_ascii=False, sort_keys=True).encode("utf-8"),
            _aad(record.id, "input"),
        )
        record.encrypted_result = encrypt_sensitive_data(
            json.dumps(result, ensure_ascii=False, sort_keys=True).encode("utf-8"),
            _aad(record.id, "result"),
        )
        append_event("fraud.case_created", user.username, {
            "case_id": record.id, "case_token": case_token,
            "risk_score": result["risk_score"], "risk_level": result["risk_level"],
            "rule_ids": [item["rule_id"] for item in result["signals"]],
            "f3_technique_ids": [item["id"] for item in result["mitre_f3"]["techniques"]],
        })
        db.commit()
        db.refresh(record)
    except Exception as exc:
        db.rollback()
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=503, detail="Création du dossier impossible ; vérifier les clés et le journal d'audit.") from exc
    return {**result, "case_id": record.id, "case_token": case_token, "case_status": record.status}

@router.get("/cases")
def list_cases(status_filter: str | None = Query(default=None, alias="status", pattern="^(open|under_review|escalated|resolved|false_positive)$"),
               limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
               _: User = Depends(require_roles("fraud_analyst", "auditor", "reader")),
               db: Session = Depends(get_db)):
    query = db.query(FraudCase)
    if status_filter:
        query = query.filter(FraudCase.status == status_filter)
    total = query.count()
    rows = query.order_by(FraudCase.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "cases": [{
            "id": row.id, "case_token": row.case_token, "status": row.status,
            "risk_score": row.risk_score, "risk_level": row.risk_level,
            "created_at": row.created_at, "updated_at": row.updated_at,
        } for row in rows],
    }

@router.get("/cases/{case_id}")
def get_case(case_id: int, user: User = Depends(require_roles("fraud_analyst", "auditor")),
             db: Session = Depends(get_db)):
    record = db.query(FraudCase).filter(FraudCase.id == case_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Dossier antifraude introuvable.")
    try:
        append_event("fraud.case_viewed", user.username, {"case_id": record.id, "status": record.status})
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Lecture bloquée : journal d'audit non disponible.") from exc
    return _decrypt_case(record)

@router.patch("/cases/{case_id}")
def update_case(case_id: int, payload: FraudCaseUpdate,
                user: User = Depends(require_roles("fraud_analyst")), db: Session = Depends(get_db)):
    record = db.query(FraudCase).filter(FraudCase.id == case_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Dossier antifraude introuvable.")
    allowed_transitions = {
        "open": {"open", "under_review", "escalated", "false_positive"},
        "under_review": {"under_review", "open", "escalated", "resolved", "false_positive"},
        "escalated": {"escalated", "under_review", "resolved", "false_positive"},
        "resolved": {"resolved", "open"},
        "false_positive": {"false_positive", "open"},
    }
    if payload.status not in allowed_transitions.get(record.status, set()):
        raise HTTPException(status_code=409, detail=f"Transition interdite : {record.status} → {payload.status}.")
    try:
        record.status = payload.status
        record.reviewed_by_user_id = user.id
        if payload.review_note is not None:
            record.encrypted_review_note = encrypt_sensitive_data(
                payload.review_note.encode("utf-8"), _aad(record.id, "review-note")
            )
        append_event("fraud.case_updated", user.username, {
            "case_id": record.id, "status": record.status,
            "review_note_updated": payload.review_note is not None,
        })
        db.commit()
        db.refresh(record)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Mise à jour du dossier impossible.") from exc
    return {
        "id": record.id, "case_token": record.case_token, "status": record.status,
        "risk_score": record.risk_score, "risk_level": record.risk_level,
    }

@router.get("/audit/verify")
def audit_verify(_: User = Depends(require_roles("admin"))):
    try:
        return verify_chain()
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Vérification du journal impossible.") from exc
