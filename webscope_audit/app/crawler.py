from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup


def crawl_public_pages(start_url: str, max_pages: int = 5, timeout: float = 8.0) -> dict[str, Any]:
    visited: set[str] = set()
    queue: list[str] = [start_url]
    found: list[str] = []
    depth = 0

    while queue and len(found) < max_pages and depth < 3:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        found.append(current)

        try:
            response = httpx.get(current, timeout=timeout, follow_redirects=True, headers={"User-Agent": "WebScopeAudit/3.0"})
        except httpx.HTTPError:
            continue

        if response.status_code >= 400:
            continue

        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            continue

        base = urlsplit(current)
        for tag in soup.find_all("a", href=True):
            href = tag.get("href")
            if not href:
                continue
            joined = urljoin(current, href)
            parsed = urlsplit(joined)
            if parsed.scheme not in {"http", "https"}:
                continue
            if parsed.hostname != base.hostname:
                continue
            if joined not in visited and joined not in queue:
                queue.append(joined)

        depth += 1

    return {"visited": sorted(found), "pages": len(found)}
