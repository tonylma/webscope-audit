from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.resolver


def analyze_dns(hostname: str, resolver: Any | None = None) -> dict[str, Any]:
    resolver = resolver or dns.resolver
    records: dict[str, list[str]] = {}
    errors: list[str] = []
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(hostname, record_type)
            records[record_type] = [str(item) for item in answers]
        except dns.exception.DNSException as exc:
            errors.append(f"{record_type}: {exc}")

    return {
        "hostname": hostname,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "records": records,
        "errors": errors,
        "source": "dnspython",
    }
