import hashlib
from typing import Any, Dict, List

import httpx


def collect_public_files(urls: List[str], max_bytes: int = 2_000_000) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    for url in urls[:8]:
        try:
            response = httpx.get(url, timeout=10, follow_redirects=True)
            content = response.content
            if len(content) > max_bytes:
                continue
            collected.append({
                'url': url,
                'file_type': response.headers.get('content-type', 'unknown'),
                'size_bytes': len(content),
                'sha256': hashlib.sha256(content).hexdigest(),
                'risk_level': 'medium' if 'config' in url or 'log' in url else 'low',
            })
        except Exception:
            continue
    return collected
