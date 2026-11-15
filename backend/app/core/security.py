from __future__ import annotations

import hmac
import os
import re
from collections import defaultdict, deque
from typing import Deque

from fastapi import HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

def require_secret(name: str) -> bytes:
    value = os.getenv(name, "").strip()
    if len(value) < 32 or value.lower() in {"change-me", "replace-me", "development"}:
        raise RuntimeError(f"{name} doit contenir au moins 32 caractères aléatoires.")
    return value.encode("utf-8")

def pseudonymize(value: str, context: str = "ref") -> str:
    import hashlib
    key = require_secret("WEBSCOPE_PSEUDONYMIZATION_KEY")
    return hmac.new(key, f"{context}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()

def analyst_identity(raw: str | None) -> str:
    value = re.sub(r"[^A-Za-z0-9_.@-]", "", raw or "analyst")[:80]
    return value or "analyst"

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    """Single-process fallback; deploy a shared API gateway/Redis limiter for multiple workers."""
    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == "/health":
            return await call_next(request)
        import time
        now = time.monotonic()
        client = request.client.host if request.client else "unknown"
        bucket = self.requests[client]
        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            return JSONResponse(status_code=429, content={"detail": "Trop de requêtes. Réessayez plus tard."})
        bucket.append(now)
        if len(self.requests) > 10000:
            self.requests.clear()
        return await call_next(request)
