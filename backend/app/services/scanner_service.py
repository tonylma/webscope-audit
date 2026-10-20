from __future__ import annotations

import hashlib
from typing import Any, Dict, List
from urllib.parse import urlparse

import dns.resolver
import httpx
from bs4 import BeautifulSoup

COMMON_SUBDOMAINS = [
    'www', 'api', 'admin', 'staging', 'dev', 'app', 'm', 'blog', 'cdn', 'ftp', 'mail', 'login', 'static', 'assets'
]
COMMON_PATHS = [
    '/admin', '/login', '/api', '/v1', '/docs', '/swagger', '/graphql', '/robots.txt', '/sitemap.xml',
    '/backup', '/uploads', '/config', '/settings', '/.git', '/.svn', '/.env', '/debug', '/private',
    '/static', '/assets', '/vendor', '/logs', '/dump'
]


def validate_url(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError('URL invalide')
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('Seules les URL HTTP/HTTPS sont acceptées')
    return {
        'scheme': parsed.scheme,
        'host': parsed.netloc,
        'hostname': parsed.hostname,
        'path': parsed.path or '/',
    }


def resolve_dns(hostname: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            records.append({'type': 'A', 'value': str(rdata)})
    except Exception:
        pass
    return records


def discover_subdomains(base_domain: str) -> List[str]:
    subdomains: List[str] = []
    for prefix in COMMON_SUBDOMAINS:
        candidate = f'{prefix}.{base_domain}'
        try:
            dns.resolver.resolve(candidate, 'A')
            subdomains.append(candidate)
        except Exception:
            continue
    return sorted(set(subdomains))


def crawl_public_urls(base_url: str) -> List[str]:
    seen: set[str] = set()
    urls: List[str] = []
    try:
        response = httpx.get(base_url, timeout=10, follow_redirects=True)
        if response.status_code >= 400:
            return urls
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'source']):
            for attr in ('href', 'src', 'action', 'data-src', 'content'):
                value = tag.get(attr)
                if not value:
                    continue
                candidate = value
                if candidate.startswith('/'):
                    parsed = urlparse(base_url)
                    candidate = f'{parsed.scheme}://{parsed.netloc}{candidate}'
                if candidate.startswith('http') and candidate not in seen:
                    seen.add(candidate)
                    urls.append(candidate)
    except Exception:
        pass
    return urls


def probe_common_paths(base_url: str) -> List[str]:
    parsed = urlparse(base_url)
    base_origin = f'{parsed.scheme}://{parsed.netloc}'
    candidates: List[str] = []
    for path in COMMON_PATHS:
        candidate = base_origin + path
        try:
            response = httpx.get(candidate, timeout=5, follow_redirects=False)
            if response.status_code in {200, 301, 302, 403, 401, 500}:
                candidates.append(candidate)
        except Exception:
            continue
    return candidates


def download_public_file(url: str, max_bytes: int = 2_000_000) -> Dict[str, Any]:
    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        content = response.content
        if len(content) > max_bytes:
            return {'url': url, 'skipped': True, 'reason': 'size_limit'}
        return {
            'url': url,
            'skipped': False,
            'sha256': hashlib.sha256(content).hexdigest(),
            'size_bytes': len(content),
            'content_type': response.headers.get('content-type', 'unknown'),
        }
    except Exception:
        return {'url': url, 'skipped': True, 'reason': 'request_failed'}


def build_scan_summary(target_url: str, subdomains: List[str], urls: List[str], findings: List[Dict[str, str]]) -> str:
    risk = 'faible' if not findings else 'modéré'
    return (
        f'Analyse publique de {target_url}. '
        f'{len(subdomains)} sous-domaines détectés, {len(urls)} URLs exposées, '
        f'{len(findings)} signalements détectés. Niveau de risque global: {risk}.'
    )


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

    dns_records = resolve_dns(hostname)
    subdomains = discover_subdomains(hostname)
    discovered_urls = crawl_public_urls(target_url)
    guessed_paths = probe_common_paths(target_url)
    urls = list(dict.fromkeys(discovered_urls + guessed_paths))[:60]

    files = []
    for url in urls[:8]:
        file_info = download_public_file(url)
        if not file_info['skipped']:
            files.append(file_info)

    findings: List[Dict[str, str]] = []
    if status_code >= 400:
        findings.append({
            'category': 'http',
            'title': 'Réponse HTTP problématique',
            'severity': 'medium',
            'description': 'Le site répond avec un code d’erreur important.',
            'evidence': f'HTTP {status_code}',
        })
    if subdomains:
        findings.append({
            'category': 'subdomain',
            'title': 'Sous-domaines exposés',
            'severity': 'medium',
            'description': 'Des sous-domaines visibles publiquement peuvent exposer des services ou des zones internes.',
            'evidence': ', '.join(subdomains[:5]),
        })
    if guessed_paths:
        findings.append({
            'category': 'paths',
            'title': 'Chemins publics sensibles découverts',
            'severity': 'high',
            'description': 'Des chemins exposés ou potentiellement sensibles ont été détectés.',
            'evidence': ', '.join(guessed_paths[:3]),
        })
    if not dns_records:
        findings.append({
            'category': 'dns',
            'title': 'Résolution DNS limitée',
            'severity': 'low',
            'description': 'Aucun enregistrement A n’a été résolu pour le domaine principal.',
            'evidence': hostname,
        })

    summary = build_scan_summary(target_url, subdomains, urls, findings)
    return {
        'target_url': target_url,
        'final_url': final_url,
        'status_code': status_code,
        'hostname': hostname,
        'dns_records': dns_records,
        'subdomains': subdomains,
        'urls': urls,
        'files': files,
        'findings': findings,
        'summary': summary,
        'risk_score': max(15, 35 + min(len(subdomains) * 8, 45) + min(len(urls) * 2, 20) + (15 if guessed_paths else 0)),
        'headers': headers,
    }
