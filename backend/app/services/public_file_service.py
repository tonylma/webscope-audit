from __future__ import annotations

from typing import List

import dns.resolver

from app.core.constants import COMMON_SUBDOMAINS


def discover_subdomains(base_domain: str) -> List[str]:
    results: List[str] = []
    for prefix in COMMON_SUBDOMAINS:
        candidate = f'{prefix}.{base_domain}'
        try:
            dns.resolver.resolve(candidate, 'A')
            results.append(candidate)
        except Exception:
            continue
    return sorted(set(results))
