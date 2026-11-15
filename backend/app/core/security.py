from __future__ import annotations

import hmac
import os
import re
import secrets
from collections import defaultdict, deque
from typing import Deque

from fastapi import Header, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

def require_analyst_key(x_analyst_key: str | None = Header(default=None, alias="X-Analyst-Key")) -> None:
    configured = os.getenv("WEBSCOPE_ANALYST_API_KEY", "").strip()
    if len(configured) < 32 or configured.lower() in {"change-me", "replace-me", "development"}:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Accès analyste désactivé : configurez une clé forte WEBSCOPE_ANALYST_API_KEY.")
    if not x_analyst_key or not hmac.compare_digest(x_analyst_key, configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Clé analyste invalide.")

def require_secret(name: str) -> bytes:
    value = os.getenv(name, "").strip()
    if len(value) < 32 or value.lower() in {"change-me", "replace-me", "development"}:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=f"Configuration requise : {name} doit contenir au moins 32 caractères aléatoires.")
    return value.encode("utf-8")

def pseudonymize(value: str, context: str = "ref") -> str:
    key = require_secret("WEBSCOPE_PSEUDONYMIZATION_KEY")
    digest = hmac.new(key, f"{context}:{value}".encode("utf-8"), "sha256").hexdigest()
    return digest

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
        return response

class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    """Single-process emergency guard; use a gateway/Redis limiter for multi-worker production."""
    def __init__(self, app, max_requests: int = 60, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == "/health" or not (
            request.url.path.startswith("/scan") or
            request.url.path.startswith("/defense") or
            request.url.path.startswith("/fraud")
        ):
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
