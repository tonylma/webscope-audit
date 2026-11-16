from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.api.routes.auth import require_roles
from app.db.user_models import User
from app.services.audit_log import append_event
from app.services.defense_engine import analyze_url, inspect_file_bytes
from app.services.clamav_service import scan_with_clamav
from app.core.config import get_settings

router = APIRouter(prefix="/defense", tags=["defense"])

class UrlAnalysisRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)

@router.post("/url-analysis")
def url_analysis(payload: UrlAnalysisRequest, user: User = Depends(require_roles("security_analyst", "auditor"))):
    try:
        result = analyze_url(payload.url)
        append_event("defense.url_analysis", user.username, {
            "host": result["normalized_host"], "risk_score": result["risk_score"],
            "signal_codes": [item["code"] for item in result["signals"]],
            "network_access": "none",
        })
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Configuration du journal d'audit incomplète.") from exc
    return result

@router.post("/file-triage")
async def file_triage(file: UploadFile = File(...), user: User = Depends(require_roles("security_analyst"))):
    maximum = get_settings().max_download_size_bytes
    sample = await file.read(maximum + 1)
    if len(sample) > maximum:
        await file.close()
        raise HTTPException(status_code=413, detail="Fichier trop volumineux (25 Mo maximum).")
    try:
        result = inspect_file_bytes(sample)
        antivirus = scan_with_clamav(sample)
        if antivirus.get('status') == 'malware_detected':
            result['risk_level'] = 'critical'
            result['risk_score'] = 100
            result['verdict'] = 'malware_detected_by_clamav'
        audit = append_event("defense.file_triage", user.username, {
            "sha256": result["sha256"], "size_bytes": result["size_bytes"],
            "file_type": result["file_type"], "risk_level": result["risk_level"],
            "execution_performed": False,
            "antivirus_status": antivirus["status"],
        })
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=422 if isinstance(exc, ValueError) else 503, detail="Analyse impossible ou journal d'audit non configuré.") from exc
    finally:
        await file.close()
    return {**result, "antivirus": antivirus, "audit": audit}
