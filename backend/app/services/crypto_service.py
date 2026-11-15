from __future__ import annotations

import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _key() -> bytes:
    encoded = os.getenv("WEBSCOPE_DATA_ENCRYPTION_KEY", "").strip()
    if not encoded:
        raise RuntimeError("WEBSCOPE_DATA_ENCRYPTION_KEY non configurée.")
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as exc:
        raise RuntimeError("Clé de chiffrement invalide : base64url attendu.") from exc
    if len(key) != 32:
        raise RuntimeError("WEBSCOPE_DATA_ENCRYPTION_KEY doit décoder exactement 32 octets (AES-256-GCM).")
    return key

def encrypt_sensitive_data(plaintext: bytes, associated_data: bytes = b"webscope:v1") -> str:
    """AES-256-GCM authenticated encryption; use a fresh random nonce for every encryption."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, associated_data)
    return "v1." + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii").rstrip("=")

def decrypt_sensitive_data(envelope: str, associated_data: bytes = b"webscope:v1") -> bytes:
    if not envelope.startswith("v1."):
        raise ValueError("Format de donnée chiffrée inconnu.")
    raw = envelope[3:]
    payload = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(payload) < 12 + 16:
        raise ValueError("Enveloppe chiffrée invalide.")
    return AESGCM(_key()).decrypt(payload[:12], payload[12:], associated_data)
