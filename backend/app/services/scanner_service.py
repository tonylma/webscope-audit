from __future__ import annotations

from typing import Any

from app.services.defense_engine import analyze_url

def run_scan(target_url: str) -> dict[str, Any]:
    """Safe-by-default URL assessment: analyzes syntax and indicators without contacting the target."""
    result = analyze_url(target_url)
    summary = (
        f"Analyse syntaxique terminée pour {result['normalized_host']}. "
        f"Niveau de risque : {result['risk_level']} ({result['risk_score']}/100). "
        f"{len(result['signals'])} indicateur(s) identifié(s). Aucun accès réseau n'a été effectué."
    )
    return {
        "target_url": target_url,
        "hostname": result["normalized_host"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "signals": result["signals"],
        "findings": result["signals"],
        "summary": summary,
        "network_access": "none",
    }
