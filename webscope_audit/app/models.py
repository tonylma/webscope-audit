from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class AppConfig:
    target_url: str = "https://example.com"
    output_dir: str = "reports"
    timeout: float = 10.0
    max_redirects: int = 5
    max_response_bytes: int = 250000
    max_requests: int = 12
    max_pages: int = 5
    crawl_depth: int = 1
    max_subdomains: int = 20
    max_dns_queries: int = 25
    allowed_ports: tuple[int, ...] = (80, 443, 8080, 8443)
    enable_port_scan: bool = True
    enable_subdomain_scan: bool = True
    enable_crawl: bool = True
    allow_http: bool = True
    allow_https: bool = True
    include_dns: bool = True
    include_http: bool = True
    include_tls: bool = True
    include_technologies: bool = True
    db_path: str = "reports/webscope_audit.db"
    gui: bool = False
    report_title: str = "WebScope Audit V3"

    def output_path(self) -> Path:
        path = Path(self.output_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path


@dataclass
class Finding:
    status: str
    level: str = "info"
    title: str = ""
    description: str = ""
    confidence: str = "medium"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    target: str
    collected_at: str
    scope: str
    dns: Dict[str, Any] = field(default_factory=dict)
    http: Dict[str, Any] = field(default_factory=dict)
    tls: Dict[str, Any] = field(default_factory=dict)
    technologies: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    limits: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    ports: Dict[str, Any] = field(default_factory=dict)
    crawl: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "collected_at": self.collected_at,
            "scope": self.scope,
            "dns": self.dns,
            "http": self.http,
            "tls": self.tls,
            "technologies": self.technologies,
            "findings": [
                {
                    "status": finding.status,
                    "level": finding.level,
                    "title": finding.title,
                    "description": finding.description,
                    "confidence": finding.confidence,
                    "details": finding.details,
                }
                for finding in self.findings
            ],
            "errors": self.errors,
            "recommendations": self.recommendations,
            "limits": self.limits,
            "metadata": self.metadata,
            "subdomains": self.subdomains,
            "ports": self.ports,
            "crawl": self.crawl,
        }
