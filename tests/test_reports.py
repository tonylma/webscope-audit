from webscope_audit.app.dns_analyzer import analyze_dns
from webscope_audit.app.subdomain_discovery import discover_subdomains
from webscope_audit.app.technology_detector import detect_technologies


class StubResolver:
    def resolve(self, hostname, record_type):
        if hostname == "example.com" and record_type == "A":
            return ["93.184.216.34"]
        if hostname.startswith("www.") and record_type == "A":
            return ["93.184.216.34"]
        raise Exception("No record")


def test_analyze_dns_collects_records():
    result = analyze_dns("example.com", resolver=StubResolver())
    assert result["hostname"] == "example.com"
    assert result["records"]["A"] == ["93.184.216.34"]


def test_discover_subdomains_detects_common_names():
    result = discover_subdomains("example.com", resolver=StubResolver(), limit=5)
    assert "www.example.com" in result


def test_detect_technologies_from_headers_and_html():
    headers = {"server": "nginx", "x-powered-by": "PHP"}
    html = '<html><head><script src="/js/jquery.min.js"></script></head><body>Hello</body></html>'
    result = detect_technologies(headers, html)
    names = [item["name"] for item in result["confirmed"]]
    assert "nginx" in names
    assert "jquery" in names
