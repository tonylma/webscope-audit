from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from .config import AppConfig
from .safety import validate_redirect_destination


def fetch_http_response(url: str, config: AppConfig) -> dict[str, Any]:
    headers = {"User-Agent": "WebScopeAudit/2.0"}
    redirects: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    current_url = url
    response = None
    error: str | None = None

    for _ in range(config.max_redirects):
        try:
            response = httpx.get(
                current_url,
                follow_redirects=False,
                headers=headers,
                timeout=config.timeout,
                max_redirects=0,
            )
        except httpx.HTTPError as exc:
            error = str(exc)
            break

        if response.status_code in {301, 302, 303, 307, 308} and "location" in response.headers:
            next_url = httpx.URL(current_url).join(response.headers["location"])
            if not validate_redirect_destination(current_url, str(next_url), seen_hosts):
                error = "Redirection non autorisée détectée."
                break
            redirects.append({"from": current_url, "to": str(next_url), "status": response.status_code})
            current_url = str(next_url)
            continue
        break

    if response is None:
        return {
            "url": url,
            "status": None,
            "final_url": url,
            "headers": {},
            "server": None,
            "redirects": redirects,
            "error": error or "Impossible de récupérer la page.",
            "response_time_ms": 0,
            "available": False,
            "html": "",
        }

    html = response.text[: config.max_response_bytes]
    return {
        "url": url,
        "status": response.status_code,
        "final_url": str(response.url),
        "headers": dict(response.headers),
        "server": response.headers.get("server"),
        "redirects": redirects,
        "error": error,
        "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2) if response.elapsed else 0,
        "available": response.status_code < 500,
        "html": html,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def check_endpoint_availability(hostname: str, config: AppConfig) -> dict[str, bool]:
    results = {"http": False, "https": False}
    for scheme in ("http", "https"):
        url = f"{scheme}://{hostname}/"
        try:
            response = httpx.get(
                url,
                follow_redirects=False,
                headers={"User-Agent": "WebScopeAudit/2.0"},
                timeout=config.timeout,
            )
            results[scheme] = response.status_code < 500
        except httpx.HTTPError:
            results[scheme] = False
    return results
