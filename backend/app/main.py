from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.routes.auth import router as auth_router
from app.api.routes.defense import router as defense_router
from app.api.routes.fraud import router as fraud_router
from app.api.routes.history import router as history_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scans import router as scans_router
from app.core.auth import hash_password
from app.core.config import get_settings
from app.core.security import InMemoryRateLimitMiddleware, SecurityHeadersMiddleware
from app.db.base import Base
from app.db.models import FraudCase, FindingRecord, ScanRecord
from app.db.session import SessionLocal, engine
from app.db.user_models import User
from app.services.audit_log import append_event
from app.services.startup_checks import validate_security_configuration

settings = get_settings()
environment = settings.environment.lower()
docs_enabled = environment != "production"

app = FastAPI(
    title="WebScope Audit & Defense",
    description="Audit défensif, triage statique de fichiers suspects et contrôle antifraude Mobile Money.",
    version="3.1.0",
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
)

origins = [item.strip() for item in settings.cors_origins.split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(InMemoryRateLimitMiddleware, max_requests=settings.rate_limit_per_minute)

@app.on_event("startup")
def initialize_database_and_admin() -> None:
    validate_security_configuration()
    Base.metadata.create_all(bind=engine)
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    username = os.getenv("WEBSCOPE_BOOTSTRAP_ADMIN_USERNAME", "").strip()
    password = os.getenv("WEBSCOPE_BOOTSTRAP_ADMIN_PASSWORD", "")
    if bool(username) != bool(password):
        raise RuntimeError("Renseignez ensemble WEBSCOPE_BOOTSTRAP_ADMIN_USERNAME et WEBSCOPE_BOOTSTRAP_ADMIN_PASSWORD.")
    with SessionLocal() as db:
        user_count = db.query(User).count()
        if user_count == 0 and not username:
            raise RuntimeError(
                "Aucun compte administrateur : configurez WEBSCOPE_BOOTSTRAP_ADMIN_USERNAME et "
                "WEBSCOPE_BOOTSTRAP_ADMIN_PASSWORD pour le premier démarrage."
            )
        if username and db.query(User).filter(User.username == username).first() is None:
            if len(password) < 18:
                raise RuntimeError("Le mot de passe initial administrateur doit comporter au moins 18 caractères.")
            administrator = User(
                username=username,
                display_name=os.getenv("WEBSCOPE_BOOTSTRAP_ADMIN_DISPLAY_NAME", "WebScope Administrator"),
                password_hash=hash_password(password),
                role="admin",
                is_active=True,
            )
            db.add(administrator)
            db.commit()
            append_event("auth.bootstrap_admin_created", username, {"role": "admin"})

@app.get("/health")
def healthcheck():
    return {"status": "ok", "service": "webscope-defense", "version": "3.1.0"}

app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(reports_router)
app.include_router(history_router)
app.include_router(defense_router)
app.include_router(fraud_router)
