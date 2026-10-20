from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanCreateRequest(BaseModel):
    url: HttpUrl = Field(..., description='URL publique à analyser')


class ScanResult(BaseModel):
    id: int
    target_url: str
    status: str
    risk_score: float = 0.0
    summary: str = ''


class FindingItem(BaseModel):
    category: str
    title: str
    severity: str
    description: str = ''
    evidence: str = ''


class SubdomainItem(BaseModel):
    name: str
    ip: Optional[str] = None
    status: str = 'active'


class UrlItem(BaseModel):
    url: str
    source: str = 'crawl'
    status_code: int = 200
    depth: int = 1


class ScanReport(BaseModel):
    scan_id: int
    summary: str
    risk_score: float
    status: str = 'completed'
    findings: List[FindingItem] = []
    subdomains: List[SubdomainItem] = []
    urls: List[UrlItem] = []
