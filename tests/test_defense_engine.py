from app.services.defense_engine import analyze_url, inspect_file_bytes
from app.services.scanner_service import run_scan
import pytest

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

def test_scan_refuses_without_explicit_authorization():
    with pytest.raises(ValueError, match="autorisé"):
        run_scan("https://example.com")

def test_authorized_scan_is_bounded_and_does_not_download_files(monkeypatch):
    import app.services.scanner_service as scanner

    def fake_request(url, method="GET", timeout=4.0, max_bytes=65536):
        if method == "HEAD":
            return {
                "ok": True, "status_code": 404, "reason": "Not Found", "url": url,
                "ip": "93.184.216.34", "headers": {}, "content_type": "text/html",
                "content_length": "0", "body": b"", "body_truncated": False, "tls": None,
            }
        return {
            "ok": True, "status_code": 200, "reason": "OK", "url": url,
            "ip": "93.184.216.34",
            "headers": {
                "content-type": "text/html",
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
            },
            "content_type": "text/html",
            "content_length": "46",
            "body": b'<html><a href="/about">About</a><img src="/sample.apk"></html>',
            "body_truncated": False,
            "tls": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"},
        }

    monkeypatch.setattr(scanner, "_resolve_public_addresses", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(scanner, "_request_public", fake_request)
    monkeypatch.setattr(scanner, "_inspect_subdomains", lambda hostname: [])
    result = run_scan("https://example.com", authorized_scope=True)

    assert result["risk_score"] == 0
    assert result["network_access"] == "public_dns_and_http_https_only"
    assert result["limits"]["files_downloaded"] is False
    assert result["files"] == []
    assert any(item["url"] == "https://example.com/about" for item in result["urls"])
    # HTML resource references may be listed, but no linked file is downloaded or stored.
    assert result["files"] == []
    assert any(item["url"].endswith("/sample.apk") for item in result["urls"])
    assert result["limits"]["ports"] == [80, 443]
