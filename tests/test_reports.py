from webscope_audit.app.dns_analyzer import analyze_dns
from webscope_audit.app.technology_detector import detect_technologies


class StubResolver:
    def resolve(self, hostname, record_type):
        if record_type == "A":
            return ["93.184.216.34"]
        raise Exception("No record")


def test_analyze_dns_collects_records():
    result = analyze_dns("example.com", resolver=StubResolver())
    assert result["hostname"] == "example.com"
    assert result["records"]["A"] == ["93.184.216.34"]


def test_detect_technologies_from_headers_and_html():
    headers = {"server": "nginx", "x-powered-by": "PHP"}
    html = '<html><head><script src="/js/jquery.min.js"></script></head><body>Hello</body></html>'
    result = detect_technologies(headers, html)
    names = [item["name"] for item in result["confirmed"]]
    assert "nginx" in names
    assert "jquery" in names
