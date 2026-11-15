from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.core.security import analyst_identity, require_analyst_key
from app.services.audit_log import append_event
from app.services.defense_engine import analyze_url, inspect_file_bytes

router = APIRouter(prefix="/defense", tags=["defense"], dependencies=[Depends(require_analyst_key)])

class UrlAnalysisRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)

@router.post("/url-analysis")
def url_analysis(payload: UrlAnalysisRequest, analyst: str = "analyst"):
    try:
        result = analyze_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        append_event("defense.url_analysis", analyst_identity(analyst), {
            "host": result["normalized_host"], "risk_score": result["risk_score"],
            "signal_codes": [item["code"] for item in result["signals"]],
            "network_access": "none",
        })
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return result

@router.post("/file-triage")
async def file_triage(file: UploadFile = File(...), x_analyst_id: str | None = None):
    maximum = 25_000_000
    sample = await file.read(maximum + 1)
    if len(sample) > maximum:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux (25 Mo maximum).")
    try:
        result = inspect_file_bytes(sample)
        audit = append_event("defense.file_triage", analyst_identity(x_analyst_id), {
            "sha256": result["sha256"], "size_bytes": result["size_bytes"],
            "file_type": result["file_type"], "risk_level": result["risk_level"],
            "execution_performed": False,
        })
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=422 if isinstance(exc, ValueError) else 503, detail=str(exc)) from exc
    finally:
        await file.close()
    return {**result, "audit": audit}
