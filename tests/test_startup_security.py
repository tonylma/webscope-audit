import base64
import os

import pytest

from app.services.startup_checks import validate_security_configuration

def set_valid_security_env(monkeypatch):
    monkeypatch.setenv("WEBSCOPE_JWT_SECRET", "j" * 64)
    monkeypatch.setenv("WEBSCOPE_AUDIT_HMAC_KEY", "h" * 64)
    monkeypatch.setenv("WEBSCOPE_PSEUDONYMIZATION_KEY", "p" * 64)
    monkeypatch.setenv("WEBSCOPE_DATA_ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173")
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("ACCESS_TOKEN_MINUTES", "20")
    monkeypatch.setenv("WEBSCOPE_AUDIT_LOG_PATH", "/tmp/audit.jsonl")

def test_startup_security_config_accepts_minimum_valid_values(monkeypatch):
    set_valid_security_env(monkeypatch)
    validate_security_configuration()

def test_startup_security_config_fails_closed_without_encryption_key(monkeypatch):
    set_valid_security_env(monkeypatch)
    monkeypatch.delenv("WEBSCOPE_DATA_ENCRYPTION_KEY")
    with pytest.raises(RuntimeError, match="WEBSCOPE_DATA_ENCRYPTION_KEY"):
        validate_security_configuration()

def test_startup_security_config_rejects_wildcard_cors(monkeypatch):
    set_valid_security_env(monkeypatch)
    monkeypatch.setenv("CORS_ORIGINS", "*")
    with pytest.raises(RuntimeError, match="joker"):
        validate_security_configuration()
