from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from .config import AppConfig
from .database import AuditDatabase
from .dns_analyzer import analyze_dns
from .http_analyzer import check_endpoint_availability, fetch_http_response
from .safety import validate_url
from .technology_detector import detect_technologies
from .tls_analyzer import analyze_tls


class SiteScanner:
    def __init__(self, config: AppConfig | None = None, db_path: str | None = None):
        self.config = config or AppConfig()
        if db_path:
            self.config.db_path = db_path
        self.database = AuditDatabase(self.config.db_path)

    def analyze(self, target_url: str) -> dict:
        ok, normalized = validate_url(target_url)
        if not ok:
            raise ValueError(normalized)

        hostname = urlsplit(normalized).hostname or ""
        results: dict = {
            "target": normalized,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "scope": "public web analysis",
            "dns": {},
            "http": {},
            "tls": {},
            "technologies": {"confirmed": [], "suspected": []},
            "errors": [],
            "recommendations": [
                "Limiter les redirections à une chaîne courte et vérifiable.",
                "Ne pas contourner les mécanismes d'accès ou d'authentification.",
                "Comparer les technologies détectées avec les en-têtes et le HTML publiquement visibles.",
            ],
            "limits": {
                "max_redirects": self.config.max_redirects,
                "timeout_seconds": self.config.timeout,
                "max_response_bytes": self.config.max_response_bytes,
                "max_requests": self.config.max_requests,
            },
            "metadata": {
                "public_target": True,
                "allowed_schemes": ["http", "https"],
            },
        }

        if self.config.include_dns:
            results["dns"] = analyze_dns(hostname)

        if self.config.include_http:
            results["http"] = fetch_http_response(normalized, self.config)
            results["metadata"]["availability"] = check_endpoint_availability(hostname, self.config)

        if self.config.include_tls:
            results["tls"] = analyze_tls(hostname, timeout=self.config.timeout)

        if self.config.include_technologies and results.get("http", {}).get("html"):
            technology_result = detect_technologies(
                results["http"].get("headers", {}),
                results["http"].get("html", ""),
            )
            results["technologies"] = technology_result

        if not results["dns"]:
            results["errors"].append("Analyse DNS désactivée.")
        if results["http"].get("error"):
            results["errors"].append(f"HTTP: {results['http']['error']}")
        if results["tls"].get("errors"):
            results["errors"].append("TLS: vérification du certificat non conclue.")

        self.database.save_analysis(results)
        return results
