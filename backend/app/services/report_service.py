from __future__ import annotations

from typing import Any, Dict, List

from app.services.scanner_service import analyze_target


def generate_report_html(scan_result: Dict[str, Any]) -> str:
    findings = scan_result.get('findings', [])
    subdomains = scan_result.get('subdomains', [])
    urls = scan_result.get('urls', [])

    findings_html = ''.join(
        f"<li><strong>{item.get('title', 'Signalement')}</strong> - {item.get('severity', 'medium')}<br>{item.get('description', '')}</li>"
        for item in findings
    ) or '<li>Aucun signalement notable.</li>'

    subdomains_html = ''.join(f'<li>{sub}</li>' for sub in subdomains) or '<li>Aucun sous-domaine détecté.</li>'
    urls_html = ''.join(f'<li>{url}</li>' for url in urls[:20]) or '<li>Aucune URL détectée.</li>'

    return f"""
    <html>
      <head>
        <meta charset=\"utf-8\" />
        <title>WebScope Audit Report</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 24px; color: #111827; }}
          h1 {{ margin-bottom: 8px; }}
          .meta {{ color: #475569; margin-bottom: 16px; }}
          .card {{ border: 1px solid #dbeafe; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
          ul {{ padding-left: 18px; }}
        </style>
      </head>
      <body>
        <h1>WebScope Audit Report</h1>
        <div class=\"meta\">Cible: {scan_result.get('target_url')}<br>Score: {scan_result.get('risk_score')}<br>Résumé: {scan_result.get('summary')}</div>

        <div class=\"card\">
          <h2>Signalements</h2>
          <ul>{findings_html}</ul>
        </div>

        <div class=\"card\">
          <h2>Sous-domaines</h2>
          <ul>{subdomains_html}</ul>
        </div>

        <div class=\"card\">
          <h2>URLs exposées</h2>
          <ul>{urls_html}</ul>
        </div>
      </body>
    </html>
    """


def generate_report_json(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'target_url': scan_result.get('target_url'),
        'final_url': scan_result.get('final_url'),
        'status_code': scan_result.get('status_code'),
        'risk_score': scan_result.get('risk_score'),
        'summary': scan_result.get('summary'),
        'subdomains': scan_result.get('subdomains', []),
        'urls': scan_result.get('urls', []),
        'findings': scan_result.get('findings', []),
        'files': scan_result.get('files', []),
    }
