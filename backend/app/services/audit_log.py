from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from fcntl import LOCK_EX, LOCK_SH, flock

_THREAD_LOCK = threading.RLock()
_ZERO_HASH = "0" * 64

def _key() -> bytes:
    value = os.getenv("WEBSCOPE_AUDIT_HMAC_KEY", "").strip()
    if len(value.encode("utf-8")) < 32 or value.lower() in {"change-me", "replace-me", "development"}:
        raise RuntimeError("Configurez WEBSCOPE_AUDIT_HMAC_KEY avec au moins 32 octets aléatoires.")
    return value.encode("utf-8")

def _path() -> Path:
    path = Path(os.getenv("WEBSCOPE_AUDIT_LOG_PATH", "/data/audit-chain.jsonl"))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _verify_open_file(source: TextIO, key: bytes) -> dict:
    previous_hash = _ZERO_HASH
    checked = 0
    source.seek(0)
    for line_number, line in enumerate(source, 1):
        if not line.strip():
            continue
        try:
            envelope = json.loads(line)
            entry = {key_name: value for key_name, value in envelope.items()
                     if key_name not in {"entry_hash", "hmac_sha256"}}
            supplied_hash = envelope.get("entry_hash", "")
            supplied_signature = envelope.get("hmac_sha256", "")
            canonical = _canonical(entry)
            expected_hash = hashlib.sha256(canonical).hexdigest()
            expected_signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        except (json.JSONDecodeError, TypeError, ValueError):
            return {"valid": False, "entries_checked": checked, "invalid_line": line_number,
                    "reason": "malformed_entry", "last_hash": previous_hash}
        if (entry.get("previous_hash") != previous_hash
                or not hmac.compare_digest(supplied_hash, expected_hash)
                or not hmac.compare_digest(supplied_signature, expected_signature)):
            return {"valid": False, "entries_checked": checked, "invalid_line": line_number,
                    "reason": "hash_or_hmac_mismatch", "last_hash": previous_hash}
        previous_hash = supplied_hash
        checked += 1
    return {"valid": True, "entries_checked": checked, "last_hash": previous_hash}

def append_event(event_type: str, actor: str, details: dict) -> dict:
    key = _key()
    path = _path()
    with _THREAD_LOCK, path.open("a+", encoding="utf-8") as output:
        # flock coordinates multiple Uvicorn workers/containers sharing the same local volume.
        flock(output.fileno(), LOCK_EX)
        try:
            verification = _verify_open_file(output, key)
            if not verification["valid"]:
                raise RuntimeError(
                    f"Journal HMAC altéré à la ligne {verification.get('invalid_line')} ; écriture bloquée."
                )
            body = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": str(event_type)[:120],
                "actor": str(actor)[:80],
                "details": details,
                "previous_hash": verification["last_hash"],
            }
            canonical = _canonical(body)
            entry_hash = hashlib.sha256(canonical).hexdigest()
            signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()
            envelope = {**body, "entry_hash": entry_hash, "hmac_sha256": signature}
            output.seek(0, os.SEEK_END)
            output.write(json.dumps(envelope, sort_keys=True, ensure_ascii=False) + "\n")
            output.flush()
            os.fsync(output.fileno())
        finally:
            flock(output.fileno(), LOCK_EX)
    return {"timestamp": body["timestamp"], "entry_hash": entry_hash}

def verify_chain() -> dict:
    key = _key()
    path = _path()
    with _THREAD_LOCK, path.open("a+", encoding="utf-8") as source:
        flock(source.fileno(), LOCK_SH)
        try:
            return _verify_open_file(source, key)
        finally:
            flock(source.fileno(), LOCK_SH)
