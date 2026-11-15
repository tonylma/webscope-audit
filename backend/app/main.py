from __future__ import annotations

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.auth import router as auth_router
from app.api.routes.history import router as history_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scans import router as scans_router
from app.api.routes.defense import router as defense_router
from app.api.routes.fraud import router as fraud_router
from app.core.security import SecurityHeadersMiddleware, InMemoryRateLimitMiddleware
from app.db.base import Base
from app.db.session import engine, SessionLocal
from app.db.user_models import User
from app.core.auth import hash_password
from app.services.audit_log import append_event

environment = os.getenv("ENVIRONMENT", "development").lower()
docs_enabled = environment != "production"
app = FastAPI(
    title="WebScope Audit & Defense",
    description="Plateforme d'audit défensif, de triage statique et de contrôle antifraude Mobile Money.",
    version="3.0.0",
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
)

origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if item.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type", "X-Analyst-Id"])
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(InMemoryRateLimitMiddleware, max_requests=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))

@app.on_event("startup")
def initialize_database_and_admin():
    Base.metadata.create_all(bind=engine)
    username = os.getenv("WEBSCOPE_BOOTSTRAP_ADMIN_USERNAME", "").strip()
    password = os.getenv("WEBSCOPE_BOOTSTRAP_ADMIN_PASSWORD", "")
    if bool(username) != bool(password):
        raise RuntimeError("Renseignez à la fois WEBSCOPE_BOOTSTRAP_ADMIN_USERNAME et WEBSCOPE_BOOTSTRAP_ADMIN_PASSWORD.")
    if username:
        if len(password) < 18:
            raise RuntimeError("Le mot de passe initial administrateur doit comporter au moins 18 caractères.")
        with SessionLocal() as db:
            exists = db.query(User).filter(User.username == username).first()
            if not exists:
                user = User(
                    username=username,
                    display_name=os.getenv("WEBSCOPE_BOOTSTRAP_ADMIN_DISPLAY_NAME", "WebScope Administrator"),
                    password_hash=hash_password(password),
                    role="admin",
                    is_active=True,
                )
                db.add(user)
                db.commit()
                append_event("auth.bootstrap_admin_created", username, {"role": "admin"})

@app.get("/health")
def healthcheck():
    return {"status": "ok", "service": "webscope-defense", "version": "3.0.0"}

app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(reports_router)
app.include_router(history_router)
app.include_router(defense_router)
app.include_router(fraud_router)
