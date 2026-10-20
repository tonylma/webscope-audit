from __future__ import annotations

from typing import Any, Dict, List


def build_summary(target_url: str, findings: List[Dict[str, Any]], subdomains: List[str], urls: List[str]) -> str:
    risk = 'faible' if not findings else 'modéré'
    return (
        f'Analyse publique de {target_url}. '
        f'{len(subdomains)} sous-domaines détectés, {len(urls)} URLs exposées, '
        f'{len(findings)} signalements détectés. Niveau de risque global: {risk}.'
    )


def render_html_report(scan: Dict[str, Any]) -> str:
    findings = scan.get('findings', [])
    subdomains = scan.get('subdomains', [])
    urls = scan.get('urls', [])
    findings_html = ''.join(
        f"<li><strong>{item.get('title', 'Signalement')}</strong> ({item.get('severity', 'medium')}) - {item.get('description', '')}</li>"
        for item in findings
    ) or '<li>Aucun signalement notable.</li>'

    return f"""
    <html>
      <head><meta charset=\"utf-8\" /><title>WebScope Audit Report</title></head>
      <body style=\"font-family: Arial, sans-serif; padding: 24px; color: #101827;\">
        <h1>WebScope Audit Report</h1>
        <p><strong>Cible:</strong> {scan.get('target_url')}</p>
        <p><strong>Résumé:</strong> {scan.get('summary')}</p>
        <h2>Signalements</h2>
        <ul>{findings_html}</ul>
        <h2>Sous-domaines</h2>
        <ul>{''.join(f'<li>{s}</li>' for s in subdomains) or '<li>Aucun sous-domaine détecté.</li>'}</ul>
        <h2>URLs</h2>
        <ul>{''.join(f'<li>{u}</li>' for u in urls[:20]) or '<li>Aucune URL détectée.</li>'}</ul>
      </body>
    </html>
    """


def render_json_report(scan: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'target_url': scan.get('target_url'),
        'final_url': scan.get('final_url'),
        'status_code': scan.get('status_code'),
        'risk_score': scan.get('risk_score'),
        'summary': scan.get('summary'),
        'subdomains': scan.get('subdomains', []),
        'urls': scan.get('urls', []),
        'findings': scan.get('findings', []),
        'files': scan.get('files', []),
    }
