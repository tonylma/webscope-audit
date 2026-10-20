from webscope_audit.app.port_scanner import scan_ports


def test_scan_ports_detects_open_port(monkeypatch):
    def fake_create_connection(address, timeout):
        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        if address[1] in {80, 443}:
            return FakeSocket()
        raise OSError("closed")

    monkeypatch.setattr("socket.create_connection", fake_create_connection)
    result = scan_ports("example.com", ports=[80, 443, 8443], timeout=1.0)
    assert 80 in result["open"]
    assert 443 in result["open"]
    assert 8443 not in result["open"]
