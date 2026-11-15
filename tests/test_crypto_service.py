import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from app.services.crypto_service import decrypt_sensitive_data, encrypt_sensitive_data

def test_aes_256_gcm_round_trip_and_authenticated_data(monkeypatch):
    key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    monkeypatch.setenv("WEBSCOPE_DATA_ENCRYPTION_KEY", key)
    plaintext = b'{"customer_reference":"CASE-009","amount":12500}'
    encrypted = encrypt_sensitive_data(plaintext, b"fraud-case:9:input")
    assert encrypted.startswith("v1.")
    assert decrypt_sensitive_data(encrypted, b"fraud-case:9:input") == plaintext
    with pytest.raises(InvalidTag):
        decrypt_sensitive_data(encrypted, b"fraud-case:10:input")

def test_encryption_rejects_non_256_bit_key(monkeypatch):
    monkeypatch.setenv("WEBSCOPE_DATA_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"short").decode("ascii"))
    with pytest.raises(RuntimeError):
        encrypt_sensitive_data(b"secret")
