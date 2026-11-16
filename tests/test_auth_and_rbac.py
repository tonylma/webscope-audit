from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.routes.auth import require_roles
from app.core.auth import create_access_token, decode_access_token, hash_password, verify_password

def test_password_hash_and_verification():
    encoded = hash_password("A-very-long-test-passphrase-2026")
    assert encoded != "A-very-long-test-passphrase-2026"
    assert verify_password("A-very-long-test-passphrase-2026", encoded)
    assert not verify_password("incorrect-password", encoded)

def test_jwt_issuer_audience_expiry_and_claims(monkeypatch):
    monkeypatch.setenv("WEBSCOPE_JWT_SECRET", "test-only-jwt-secret-" + "x" * 48)
    token, expires_at = create_access_token(7, "analyst", "fraud_analyst", 2)
    claims = decode_access_token(token)
    assert claims["sub"] == "7"
    assert claims["role"] == "fraud_analyst"
    assert claims["ver"] == 2
    assert expires_at > claims["iat"]

def test_rbac_denies_wrong_role_and_allows_admin():
    fraud_only = require_roles("fraud_analyst")
    with pytest.raises(HTTPException) as denied:
        fraud_only(user=SimpleNamespace(role="reader"))
    assert denied.value.status_code == 403
    assert fraud_only(user=SimpleNamespace(role="admin")).role == "admin"
    assert fraud_only(user=SimpleNamespace(role="fraud_analyst")).role == "fraud_analyst"
