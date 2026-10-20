from webscope_audit.app.safety import validate_url, validate_redirect_destination


def test_validate_url_accepts_public_https():
    ok, result = validate_url("https://example.com")
    assert ok is True
    assert result.startswith("https://example.com")


def test_validate_url_rejects_localhost():
    ok, message = validate_url("http://localhost:8000")
    assert ok is False
    assert "public" in message.lower()


def test_validate_redirect_destination_maintains_scheme_and_host():
    seen = {"example.com"}
    assert validate_redirect_destination("https://example.com", "https://www.example.com/", seen) is True
