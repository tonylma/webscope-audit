from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


def fetch_url(url: str, timeout: int = 10) -> Dict[str, Any]:
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        return {
            'ok': True,
            'status_code': response.status_code,
            'final_url': str(response.url),
            'headers': dict(response.headers),
            'content_type': response.headers.get('content-type', 'unknown'),
            'text': response.text,
        }
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}


def extract_links_from_html(base_url: str, html: str) -> List[str]:
    links: List[str] = []
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup.find_all(['a', 'link', 'script', 'img', 'source']):
        for attr in ('href', 'src', 'action', 'data-src', 'content'):
            value = tag.get(attr)
            if not value:
                continue
            absolute = urljoin(base_url, value)
            if absolute.startswith('http'):
                links.append(absolute)
    return list(dict.fromkeys(links))


def detect_redirect_chain(url: str) -> List[str]:
    chain: List[str] = []
    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        chain = [str(response.url)]
    except Exception:
        pass
    return chain
