from typing import Optional, List
from pydantic import BaseModel, Field, HttpUrl


class ScanCreateRequest(BaseModel):
    url: HttpUrl = Field(..., description='URL publique à analyser')


class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str
    risk_score: float = 0.0
    summary: str = ''


class SubdomainItem(BaseModel):
    name: str
    ip: Optional[str] = None
    status: str = 'active'


class UrlItem(BaseModel):
    url: str
    source: str
    status_code: int = 0
    depth: int = 0


class FindingItem(BaseModel):
    category: str
    title: str
    severity: str
    description: str
    evidence: str


class ReportResponse(BaseModel):
    scan_id: int
    summary: str
    risk_score: float
    findings: List[FindingItem] = []
    subdomains: List[SubdomainItem] = []
    urls: List[UrlItem] = []
