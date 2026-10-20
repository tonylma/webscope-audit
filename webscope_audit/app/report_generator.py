from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .risk_model import build_risk_overview, prioritize_recommendations


def render_report_html(scan_result: dict) -> str:
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    enriched = dict(scan_result)
    enriched["risk"] = build_risk_overview(scan_result)
    enriched["priority_recommendations"] = prioritize_recommendations(scan_result)
    enriched["risk_table"] = [
        ("Critique", enriched["risk"]["levels"].get("critical", 0)),
        ("Élevé", enriched["risk"]["levels"].get("high", 0)),
        ("Moyen", enriched["risk"]["levels"].get("medium", 0)),
        ("Faible", enriched["risk"]["levels"].get("low", 0)),
        ("Info", enriched["risk"]["levels"].get("info", 0)),
    ]
    return template.render(result=enriched)
