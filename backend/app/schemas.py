from __future__ import annotations

from typing import Any, Dict, List

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
    from urllib.parse import urlparse

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
    from urllib.parse import urlparse

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


def build_scan_summary(target_url: str, subdomains: List[str], urls: List[str], findings: List[Dict[str, str]]) -> str:
    risk = 'faible' if not findings else 'modéré'
    return (
        f'Analyse publique de {target_url}. '
        f'{len(subdomains)} sous-domaines détectés, {len(urls)} URLs exposées, '
        f'{len(findings)} signalements détectés. Niveau de risque global: {risk}.'
    )


def download_public_file(url: str, max_bytes: int = 2_000_000) -> Dict[str, Any]:
    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        content = response.content
        if len(content) > max_bytes:
            return {'url': url, 'skipped': True, 'reason': 'size_limit'}
        return {
            'url': url,
            'skipped': False,
            'sha256': __import__('hashlib').sha256(content).hexdigest(),
            'size_bytes': len(content),
            'content_type': response.headers.get('content-type', 'unknown'),
        }
    except Exception:
        return {'url': url, 'skipped': True, 'reason': 'request_failed'}
