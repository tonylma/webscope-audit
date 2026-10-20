import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_report_html(scan_result: dict) -> str:
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    return template.render(result=scan_result)


def write_report_files(scan_result: dict, output_dir: str | Path) -> tuple[Path, Path]:
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    filename = f"report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.html"
    html_path = folder / filename
    json_path = folder / filename.replace(".html", ".json")
    html_path.write_text(render_report_html(scan_result), encoding="utf-8")
    json_path.write_text(json.dumps(scan_result, ensure_ascii=False, indent=2), encoding="utf-8")
    return html_path, json_path
