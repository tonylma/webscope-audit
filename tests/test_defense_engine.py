from app.services.defense_engine import analyze_url, inspect_file_bytes
from app.services.scanner_service import run_scan

def test_url_analyzer_flags_userinfo_and_http():
    result = analyze_url("http://trusted.example@evil.example/login")
    codes = {item["code"] for item in result["signals"]}
    assert "URL_USERINFO" in codes
    assert "HTTP_CLEAR_TEXT" in codes
    assert result["network_access"] == "none"

def test_url_analyzer_flags_private_ip_without_requesting_it():
    result = analyze_url("http://192.168.1.10/admin")
    assert result["risk_level"] == "critical"
    assert any(item["code"] == "NON_PUBLIC_IP" for item in result["signals"])
    assert result["network_access"] == "none"

def test_url_analyzer_flags_shorteners_and_punycode():
    shortener = analyze_url("https://bit.ly/abc123")
    punycode = analyze_url("https://xn--example-ova.test")
    assert any(item["code"] == "URL_SHORTENER" for item in shortener["signals"])
    assert any(item["code"] == "IDN_PUNYCODE" for item in punycode["signals"])

def test_file_triage_is_static_and_hashes_sample():
    result = inspect_file_bytes(b"MZ" + b"powershell -enc " + b"payload")
    assert result["file_type"] == "windows_pe"
    assert len(result["sha256"]) == 64
    assert result["execution_performed"] is False
    assert result["archive_extraction_performed"] is False
    assert result["network_access_performed"] is False

def test_api_scan_uses_same_risk_engine_and_does_not_open_target():
    result = run_scan("https://example.com")
    assert result["hostname"] == "example.com"
    assert result["risk_score"] == 0
    assert result["network_access"] == "none"
    assert "Aucun accès réseau" in result["summary"]
