from __future__ import annotations

from typing import Any, Dict, List

import dns.resolver

from app.core.constants import COMMON_SUBDOMAINS


def resolve_domain_records(hostname: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    try:
        for record_type in ('A', 'AAAA', 'CNAME'):
            answers = dns.resolver.resolve(hostname, record_type)
            for answer in answers:
                records.append({'type': record_type, 'value': str(answer)})
    except Exception:
        pass
    return records


def find_common_subdomains(base_domain: str) -> List[str]:
    found: List[str] = []
    for prefix in COMMON_SUBDOMAINS:
        candidate = f'{prefix}.{base_domain}'
        try:
            dns.resolver.resolve(candidate, 'A')
            found.append(candidate)
        except Exception:
            continue
    return sorted(set(found))
