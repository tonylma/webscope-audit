from pydantic import AnyHttpUrl, BaseModel, Field, ConfigDict

class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: AnyHttpUrl
    authorized_scope: bool = False

class ScanResult(BaseModel):
    id: int
    target_url: str
    status: str
    risk_score: int
    summary: str

class FindingOut(BaseModel):
    category: str
    title: str
    severity: str
    description: str
    evidence: str

class ScanReport(BaseModel):
    scan_id: int
    summary: str
    risk_score: int
    status: str
    findings: list[FindingOut] = Field(default_factory=list)
    subdomains: list[dict] = Field(default_factory=list)
    urls: list[dict] = Field(default_factory=list)
