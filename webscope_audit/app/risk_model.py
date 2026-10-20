from __future__ import annotations

from typing import Any


def _level_weight(level: str) -> int:
    weights = {
        "critical": 30,
        "high": 25,
        "medium": 15,
        "low": 8,
        "info": 4,
    }
    return weights.get(str(level).lower(), 0)


def build_risk_overview(scan_result: dict[str, Any]) -> dict[str, Any]:
    findings = scan_result.get("findings", [])
    level_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    weighted = 0

    for item in findings:
        level = str(item.get("level", "info")).lower()
        if level not in level_counts:
            level = "info"
        level_counts[level] += 1
        weighted += _level_weight(level)

    weighted += len(scan_result.get("errors", [])) * 12
    weighted += len(scan_result.get("ports", {}).get("open", [])) * 5
    weighted += min(len(scan_result.get("subdomains", [])) * 2, 20)

    score = max(0, min(100, 100 - weighted))

    if score >= 85:
        rating = "A"
        status = "Fort" 
    elif score >= 70:
        rating = "B"
        status = "Satisfaisant"
    elif score >= 55:
        rating = "C"
        status = "À surveiller"
    elif score >= 35:
        rating = "D"
        status = "Moyen"
    else:
        rating = "E"
        status = "Critique"

    return {
        "score": int(score),
        "rating": rating,
        "status": status,
        "levels": level_counts,
        "total_findings": len(findings),
    }


def prioritize_recommendations(scan_result: dict[str, Any]) -> list[dict[str, str]]:
    base_items = scan_result.get("recommendations", [])
    if not base_items:
        return [{"priority": "medium", "title": "Poursuivre le suivi public de la cible"}]

    recommendations: list[dict[str, str]] = []
    for item in base_items:
        if isinstance(item, dict):
            title = str(item.get("title") or item.get("label") or "Recommandation")
            priority = str(item.get("priority") or "medium").lower()
            description = str(item.get("description") or title)
        else:
            title = str(item)
            priority = "medium"
            description = str(item)

        if "redirection" in title.lower() or "redirect" in title.lower():
            priority = "high"
        elif "TLS" in title.upper() or "certificat" in title.lower():
            priority = "high"
        elif "sous-domaine" in title.lower() or "port" in title.lower():
            priority = "medium"

        recommendations.append({"priority": priority, "title": title, "description": description})

    recommendations.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["priority"], 1))
    return recommendations
