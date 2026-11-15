from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from app.api.routes.auth import require_roles
from app.db.user_models import User
from app.core.security import pseudonymize
from app.services.audit_log import append_event, verify_chain
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

@router.get("/framework")
def framework(_: User = Depends(require_roles("fraud_analyst", "auditor", "reader"))):
    return {"name": "MITRE Fight Fraud Framework", "version": F3_VERSION, "url": F3_FRAMEWORK_URL,
            "tactics": ["reconnaissance", "resource-development", "initial-access", "stealth",
                        "defense-impairment", "positioning", "execution", "monetization"],
            "note": "ATT&CK décrit les opérations techniques ; F3 relie l'accès, le positionnement, l'exécution et la monétisation de la fraude."}

@router.get("/controls")
def controls(_: User = Depends(require_roles("fraud_analyst", "auditor", "reader"))):
    return {"controls": CONTROL_CATALOG, "count": len(CONTROL_CATALOG),
            "note": "Catalogue de tests de contrôle interne à adapter aux procédures, produits et obligations de l'établissement."}

@router.post("/evaluate")
def evaluate(payload: FraudEventRequest, user: User = Depends(require_roles("fraud_analyst"))):
    result = evaluate_mobile_money_event(payload.model_dump(exclude={"case_reference"}))
    try:
        case_token = pseudonymize(payload.case_reference, "fraud-case")[:32] if payload.case_reference else None
        audit = append_event("fraud.evaluate", user.username, {
            "case_token": case_token,
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "rule_ids": [item["rule_id"] for item in result["signals"]],
            "f3_technique_ids": [item["id"] for item in result["mitre_f3"]["techniques"]],
        })
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Configuration cryptographique ou journal d'audit incomplète.") from exc
    return {**result, "case_token": case_token, "audit": audit}

@router.get("/audit/verify")
def audit_verify(_: User = Depends(require_roles("admin"))):
    try:
        return verify_chain()
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Vérification du journal impossible.") from exc
