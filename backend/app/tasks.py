from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.schemas import build_scan_summary, crawl_public_urls, discover_subdomains, validate_url


def analyze_target(target_url: str) -> Dict[str, Any]:
    validated = validate_url(target_url)
    hostname = validated['hostname']

    try:
        response = httpx.get(target_url, timeout=10, follow_redirects=True)
        status_code = response.status_code
        headers = dict(response.headers)
        final_url = str(response.url)
    except Exception:
        status_code = 0
        headers = {}
        final_url = target_url

    discovered = crawl_public_urls(target_url)
    subdomains = discover_subdomains(hostname)
    urls = [u for u in discovered if u not in {target_url, final_url}][:50]

    findings: List[Dict[str, str]] = []
    if status_code >= 400:
        findings.append({'category': 'http', 'title': 'Réponse HTTP problématique', 'severity': 'medium', 'description': 'Le site répond avec un code d’erreur important.', 'evidence': f'HTTP {status_code}'})
    if subdomains:
        findings.append({'category': 'subdomain', 'title': 'Sous-domaines exposés', 'severity': 'medium', 'description': 'Des sous-domaines de production ou de service sont visibles publiquement.', 'evidence': ', '.join(subdomains[:5])})

    summary = build_scan_summary(target_url, subdomains, urls, findings)
    return {
        'target_url': target_url,
        'final_url': final_url,
        'status_code': status_code,
        'headers': headers,
        'hostname': hostname,
        'subdomains': subdomains,
        'urls': urls,
        'findings': findings,
        'summary': summary,
        'risk_score': 35 + min(len(subdomains) * 8, 45) + min(len(urls) * 2, 20),
    }
