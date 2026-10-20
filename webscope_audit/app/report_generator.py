from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .exporters import export_docx_report, export_pdf_report


def _summary_of_result(scan_result: dict) -> dict:
    findings = scan_result.get("findings", [])
    severe = sum(1 for item in findings if str(item.get("level", "")).lower() in {"high", "critical"})
    medium = sum(1 for item in findings if str(item.get("level", "")).lower() == "medium")
    okish = sum(1 for item in findings if str(item.get("level", "")).lower() in {"info", "low"})
    return {
        "target": scan_result.get("target", ""),
        "title": scan_result.get("title", "WebScope Audit V4"),
        "issued_at": scan_result.get("collected_at", ""),
        "risk_summary": {
            "critical": severe,
            "medium": medium,
            "info": okish,
        },
        "errors": len(scan_result.get("errors", [])),
        "subdomains": len(scan_result.get("subdomains", [])),
        "ports_open": len(scan_result.get("ports", {}).get("open", [])),
    }


def render_report_html(scan_result: dict) -> str:
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    enriched = dict(scan_result)
    enriched["summary"] = _summary_of_result(scan_result)
    return template.render(result=enriched)


def write_report_files(scan_result: dict, output_dir: str | Path) -> tuple[Path, Path]:
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    html_path = folder / f"report-{timestamp}.html"
    json_path = folder / f"report-{timestamp}.json"
    docx_path = folder / f"report-{timestamp}.docx"
    pdf_path = folder / f"report-{timestamp}.pdf"

    html_path.write_text(render_report_html(scan_result), encoding="utf-8")
    json_path.write_text(json.dumps(scan_result, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        export_docx_report(scan_result, docx_path)
    except Exception:
        pass
    try:
        export_pdf_report(scan_result, pdf_path)
    except Exception:
        pass

    return html_path, json_path
