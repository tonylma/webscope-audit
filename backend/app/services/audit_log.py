from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_LOCK = threading.Lock()

def _key() -> bytes:
    value = os.getenv("WEBSCOPE_AUDIT_HMAC_KEY", "").strip()
    if len(value) < 32 or value.lower() in {"change-me", "replace-me", "development"}:
        raise RuntimeError("Configurez WEBSCOPE_AUDIT_HMAC_KEY avec au moins 32 caractères aléatoires.")
    return value.encode("utf-8")

def _path() -> Path:
    path = Path(os.getenv("WEBSCOPE_AUDIT_LOG_PATH", "/data/audit-chain.jsonl"))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def append_event(event_type: str, actor: str, details: dict) -> dict:
    key = _key()
    path = _path()
    with _LOCK:
        previous_hash = "0" * 64
        if path.exists():
            with path.open("rb") as current:
                for line in current:
                    if line.strip():
                        previous_hash = json.loads(line).get("entry_hash", previous_hash)
        body = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "actor": actor[:80],
            "details": details,
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        entry_hash = hashlib.sha256(canonical).hexdigest()
        signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        entry = {**body, "entry_hash": entry_hash, "hmac_sha256": signature}
        with path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
            output.flush()
            os.fsync(output.fileno())
    return {"timestamp": body["timestamp"], "entry_hash": entry_hash}

def verify_chain() -> dict:
    key = _key()
    path = _path()
    previous_hash = "0" * 64
    checked = 0
    if not path.exists():
        return {"valid": True, "entries_checked": 0, "last_hash": previous_hash}
    with _LOCK, path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            entry = json.loads(line)
            signature = entry.pop("hmac_sha256", "")
            entry_hash = entry.pop("entry_hash", "")
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            expected_hash = hashlib.sha256(canonical).hexdigest()
            expected_signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()
            if entry.get("previous_hash") != previous_hash or not hmac.compare_digest(entry_hash, expected_hash) or not hmac.compare_digest(signature, expected_signature):
                return {"valid": False, "entries_checked": checked, "invalid_line": line_number, "last_hash": previous_hash}
            previous_hash = entry_hash
            checked += 1
    return {"valid": True, "entries_checked": checked, "last_hash": previous_hash}
