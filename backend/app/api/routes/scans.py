from __future__ import annotations

from typing import Any, Dict, List

import httpx

from app.core.constants import COMMON_PATHS
from app.services.dns_service import find_common_subdomains, resolve_domain_records
from app.services.http_service import extract_links_from_html, fetch_url
from app.services.public_file_service import collect_public_files
from app.services.report_service import build_summary
from app.services.subdomain_service import discover_subdomains
from app.services.tls_service import inspect_tls


def run_scan(target_url: str) -> Dict[str, Any]:
    if not target_url.startswith(('http://', 'https://')):
        raise ValueError('URL invalide')

    page = fetch_url(target_url)
    hostname = target_url.split('://', 1)[-1].split('/', 1)[0]
    dns_records = resolve_domain_records(hostname)
    subdomains = discover_subdomains(hostname)
    links = []
    if page.get('ok'):
        links = extract_links_from_html(target_url, page.get('text', ''))

    suspicious_paths = []
    for path in COMMON_PATHS:
        candidate = f'{target_url.rstrip("/")}{path}'
        try:
            response = httpx.get(candidate, timeout=5, follow_redirects=False)
            if response.status_code in {200, 301, 302, 401, 403, 500}:
                suspicious_paths.append(candidate)
        except Exception:
            continue

    files = collect_public_files(links[:8])
    findings: List[Dict[str, Any]] = []
    if page.get('status_code', 0) >= 400:
        findings.append({
            'category': 'http',
            'title': 'Réponse HTTP problématique',
            'severity': 'medium',
            'description': 'Le site répond avec un code d’erreur important.',
            'evidence': f'HTTP {page.get("status_code")}',
        })
    if subdomains:
        findings.append({
            'category': 'subdomain',
            'title': 'Sous-domaines exposés',
            'severity': 'medium',
            'description': 'Des sous-domaines visibles publiquement ont été détectés.',
            'evidence': ', '.join(subdomains[:5]),
        })
    if suspicious_paths:
        findings.append({
            'category': 'path',
            'title': 'Chemins sensibles susceptibles d’être exposés',
            'severity': 'high',
            'description': 'Des chemins d’administration ou de debug potentiellement exposés ont été détectés.',
            'evidence': ', '.join(suspicious_paths[:3]),
        })

    summary = build_summary(target_url, findings, subdomains, links[:20])
    return {
        'target_url': target_url,
        'final_url': page.get('final_url', target_url),
        'status_code': page.get('status_code', 0),
        'hostname': hostname,
        'dns_records': dns_records,
        'subdomains': subdomains,
        'urls': links[:20],
        'files': files,
        'findings': findings,
        'summary': summary,
        'risk_score': max(20, 35 + min(len(subdomains) * 8, 40) + min(len(links) * 2, 20) + (12 if suspicious_paths else 0)),
        'tls': inspect_tls(hostname),
    }
