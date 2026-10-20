import json

from webscope_audit.app.database import AuditDatabase
from webscope_audit.app.report_generator import render_report_html


def test_database save_and_history(tmp_path):
    db_path = tmp_path / "audit.db"
    database = AuditDatabase(db_path)
    inserted = database.save_analysis({"target": "https://example.com", "collected_at": "2024-01-01", "scope": "test", "errors": []})
    assert inserted > 0
    history = database.list_history(5)
    assert history[0]["target_url"] == "https://example.com"


def test_report_html_renders_structure():
    html = render_report_html({
        "target": "https://example.com",
        "collected_at": "2024-01-01",
        "scope": "public web analysis",
        "dns": {"hostname": "example.com", "records": {}, "errors": []},
        "http": {"status": 200, "url": "https://example.com", "headers": {}, "final_url": "https://example.com"},
        "tls": {"hostname": "example.com", "certificate": {"validation_status": "valid"}},
        "technologies": {"confirmed": [], "suspected": []},
        "recommendations": ["Valider les redirections"],
        "errors": [],
        "limits": {"max_redirects": 5},
    })
    assert "WebScope Audit" in html
    assert "Valider les redirections" in html
