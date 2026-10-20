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
    '/backup', '/uploads', '/config', '/settings', '/.git', '/.svn', '/.env', '/debug', '/private'
]


def validate_url(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError('URL invalide')
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('Seules les URLs HTTP/HTTPS sont acceptées')
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
    subdomains = []
    for prefix in COMMON_SUBDOMAINS:
        candidate = f'{prefix}.{base_domain}'
        try:
            dns.resolver.resolve(candidate, 'A')
            subdomains.append(candidate)
        except Exception:
            continue
    return sorted(set(subdomains))


def crawl_public_urls(base_url: str) -> List[str]:
    seen = set()
    urls = []
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
                if value.startswith('http') or value.startswith('/'):
                    if value.startswith('/'):
                        value = urlparse(base_url).scheme + '://' + urlparse(base_url).netloc + value
                    if value not in seen:
                        seen.add(value)
                        urls.append(value)
    except Exception:
        pass
    return urls


def download_public_file(url: str, max_bytes: int = 2_000_000) -> Dict[str, Any]:
    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        content = response.content
        if len(content) > max_bytes:
            return {'url': url, 'skipped': True, 'reason': 'size_limit'}
        digest = hashlib.sha256(content).hexdigest()
        return {'url': url, 'skipped': False, 'sha256': digest, 'size_bytes': len(content), 'content_type': response.headers.get('content-type', 'unknown')}
    except Exception:
        return {'url': url, 'skipped': True, 'reason': 'request_failed'}


def build_scan_summary(target_url: str, subdomains: List[str], urls: List[str], findings: List[Dict[str, str]]) -> str:
    risk = 'faible' if not findings else 'modéré'
    return (
        f'Analyse publique de {target_url}. '
        f'{len(subdomains)} sous-domaines détectés, {len(urls)} URLs exposées, '
        f'{len(findings)} signalements détectés. Niveau de risque global: {risk}.'
    )
