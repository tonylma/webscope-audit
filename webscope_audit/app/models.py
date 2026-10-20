from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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
        }
