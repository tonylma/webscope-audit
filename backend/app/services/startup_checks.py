from __future__ import annotations

import base64
import os
from urllib.parse import urlsplit

from app.core.auth import _jwt_secret

SECRET_NAMES = ("WEBSCOPE_AUDIT_HMAC_KEY", "WEBSCOPE_PSEUDONYMIZATION_KEY")

def validate_security_configuration() -> None:
    _jwt_secret()
    for name in SECRET_NAMES:
        value = os.getenv(name, "").strip()
        if len(value.encode("utf-8")) < 32 or value.lower() in {"change-me", "replace-me", "development"}:
            raise RuntimeError(f"{name} doit contenir au moins 32 octets aléatoires.")
    encoded = os.getenv("WEBSCOPE_DATA_ENCRYPTION_KEY", "").strip()
    if not encoded:
        raise RuntimeError("WEBSCOPE_DATA_ENCRYPTION_KEY est obligatoire.")
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as exc:
        raise RuntimeError("WEBSCOPE_DATA_ENCRYPTION_KEY doit être une clé base64url valide.") from exc
    if len(key) != 32:
        raise RuntimeError("WEBSCOPE_DATA_ENCRYPTION_KEY doit décoder exactement 32 octets pour AES-256-GCM.")
    origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if item.strip()]
    if not origins or "*" in origins:
        raise RuntimeError("CORS_ORIGINS doit énumérer des origines exactes ; le joker * est interdit.")
    if os.getenv("ENVIRONMENT", "development").lower() == "production":
        if any(urlsplit(origin).scheme != "https" for origin in origins):
            raise RuntimeError("En production, chaque origine CORS doit utiliser HTTPS.")
    minutes = int(os.getenv("ACCESS_TOKEN_MINUTES", "20"))
    if not 5 <= minutes <= 60:
        raise RuntimeError("ACCESS_TOKEN_MINUTES doit être compris entre 5 et 60.")
    if not os.getenv("WEBSCOPE_AUDIT_LOG_PATH", "/data/audit-chain.jsonl").strip():
        raise RuntimeError("WEBSCOPE_AUDIT_LOG_PATH est obligatoire.")
