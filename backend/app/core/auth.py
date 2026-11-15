from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()
ALLOWED_ROLES = {"admin", "security_analyst", "fraud_analyst", "auditor", "reader"}

def _jwt_secret() -> str:
    secret = os.getenv("WEBSCOPE_JWT_SECRET", "").strip()
    if len(secret) < 32 or secret.lower() in {"change-me", "replace-me", "development"}:
        raise RuntimeError("WEBSCOPE_JWT_SECRET doit être configuré avec au moins 32 caractères aléatoires.")
    return secret

def hash_password(password: str) -> str:
    if len(password) < 14 or len(password) > 128:
        raise ValueError("Le mot de passe doit contenir entre 14 et 128 caractères.")
    return password_hash.hash(password)

def verify_password(password: str, encoded: str) -> bool:
    try:
        return password_hash.verify(password, encoded)
    except Exception:
        return False

def create_access_token(user_id: int, username: str, role: str, token_version: int) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=int(os.getenv("ACCESS_TOKEN_MINUTES", "20")))
    claims = {
        "sub": str(user_id), "preferred_username": username, "role": role,
        "ver": token_version, "iat": now, "nbf": now, "exp": expires,
        "iss": os.getenv("WEBSCOPE_JWT_ISSUER", "webscope-audit"),
        "aud": os.getenv("WEBSCOPE_JWT_AUDIENCE", "webscope-api"),
        "jti": os.urandom(16).hex(),
    }
    return jwt.encode(claims, _jwt_secret(), algorithm="HS256"), int(expires.timestamp())

def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token, _jwt_secret(), algorithms=["HS256"],
        issuer=os.getenv("WEBSCOPE_JWT_ISSUER", "webscope-audit"),
        audience=os.getenv("WEBSCOPE_JWT_AUDIENCE", "webscope-api"),
        options={"require": ["exp", "iat", "nbf", "sub", "iss", "aud", "jti"]},
        leeway=30,
    )
