from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "admin",
    "dev",
    "staging",
    "beta",
    "mail",
    "login",
    "cdn",
    "assets",
    "blog",
    "support",
    "m",
]


def discover_subdomains(hostname: str, resolver: Any | None = None, limit: int = 20) -> list[str]:
    resolver = resolver or dns.resolver
    results: list[str] = []
    seen: set[str] = set()

    for sub in COMMON_SUBDOMAINS:
        candidate = f"{sub}.{hostname}"
        try:
            answers = resolver.resolve(candidate, "A")
        except dns.exception.DNSException:
            continue
        if answers:
            value = str(candidate)
            if value not in seen:
                seen.add(value)
                results.append(value)
                if len(results) >= limit:
                    break
    return results
