import json

from app.services.audit_log import append_event, verify_chain

def test_hmac_audit_chain_verifies_and_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSCOPE_AUDIT_HMAC_KEY", "test-audit-chain-key-" + "z" * 48)
    monkeypatch.setenv("WEBSCOPE_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    append_event("case.created", "fraud-analyst", {"case_id": 4, "risk": "high"})
    append_event("case.updated", "fraud-analyst", {"case_id": 4, "status": "under_review"})
    assert verify_chain()["valid"] is True
    path = tmp_path / "audit.jsonl"
    first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    first["details"]["risk"] = "low"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_chain()["valid"] is False
