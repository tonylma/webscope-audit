from __future__ import annotations

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.history import router as history_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scans import router as scans_router
from app.api.routes.defense import router as defense_router
from app.api.routes.fraud import router as fraud_router
from app.core.security import SecurityHeadersMiddleware, InMemoryRateLimitMiddleware

environment = os.getenv("ENVIRONMENT", "development").lower()
docs_enabled = environment != "production"
app = FastAPI(
    title="WebScope Audit & Defense",
    description="Audit défensif, triage statique et contrôle antifraude mobile money.",
    version="3.0.0",
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
)

origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if item.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-Analyst-Key", "X-Analyst-Id"])
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(InMemoryRateLimitMiddleware, max_requests=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))

@app.get("/health")
def healthcheck():
    return {"status": "ok", "service": "webscope-defense", "version": "3.0.0"}

app.include_router(scans_router)
app.include_router(reports_router)
app.include_router(history_router)
app.include_router(defense_router)
app.include_router(fraud_router)
