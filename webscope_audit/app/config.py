from dataclasses import dataclass
from pathlib import Path


@dataclass
class AppConfig:
    target_url: str = "https://example.com"
    output_dir: str = "reports"
    timeout: float = 10.0
    max_redirects: int = 5
    max_response_bytes: int = 250000
    max_requests: int = 12
    allow_http: bool = True
    allow_https: bool = True
    include_dns: bool = True
    include_http: bool = True
    include_tls: bool = True
    include_technologies: bool = True
    db_path: str = "reports/webscope_audit.db"
    gui: bool = False

    def output_path(self) -> Path:
        path = Path(self.output_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path
