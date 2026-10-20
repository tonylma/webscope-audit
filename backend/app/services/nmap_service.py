from __future__ import annotations

from typing import Any, Dict

import httpx


def nmap_probe(host: str, ports: str = '80,443,8080,8443,21,22,3306,5432') -> Dict[str, Any]:
    try:
        result = httpx.get(f'https://{host}', timeout=5, follow_redirects=True)
        return {
            'host': host,
            'status_code': result.status_code,
            'ports': ports,
            'probe': 'http_ok',
        }
    except Exception:
        return {
            'host': host,
            'status_code': 0,
            'ports': ports,
            'probe': 'http_unreachable',
        }
