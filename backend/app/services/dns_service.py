from __future__ import annotations

from typing import Any, Dict, List

import dns.resolver
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from app.core.constants import COMMON_PATHS, COMMON_SUBDOMAINS


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
        for answer in answers:
            records.append({'type': 'A', 'value': str(answer)})
    except Exception:
        pass
    return records


def discover_subdomains(base_domain: str) -> List[str]:
    matches: List[str] = []
    for prefix in COMMON_SUBDOMAINS:
        candidate = f'{prefix}.{base_domain}'
        try:
            dns.resolver.resolve(candidate, 'A')
            matches.append(candidate)
        except Exception:
            continue
    return sorted(set(matches))


def crawl_public_urls(base_url: str) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    try:
        response = httpx.get(base_url, timeout=10, follow_redirects=True)
        if response.status_code >= 400:
            return out
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
                    out.append(candidate)
    except Exception:
        pass
    return out


def probe_common_paths(base_url: str) -> List[str]:
    parsed = urlparse(base_url)
    origin = f'{parsed.scheme}://{parsed.netloc}'
    results: List[str] = []
    for path in COMMON_PATHS:
        candidate = origin + path
        try:
            resp = httpx.get(candidate, timeout=5, follow_redirects=False)
            if resp.status_code in {200, 301, 302, 401, 403, 500}:
                results.append(candidate)
        except Exception:
            continue
    return results
