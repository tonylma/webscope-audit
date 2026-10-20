export interface ScanResult {
  id: number;
  target_url: string;
  status: string;
  risk_score: number;
  summary: string;
}

export interface HistoryItem {
  id: number;
  target_url: string;
  status: string;
  risk_score: number;
  summary: string;
}

export interface FindingItem {
  category: string;
  title: string;
  severity: string;
  description: string;
  evidence: string;
}

export interface SubdomainItem {
  name: string;
  ip?: string | null;
  status: string;
}

export interface UrlItem {
  url: string;
  source: string;
  status_code: number;
  depth: number;
}

export interface Report {
  scan_id: number;
  summary: string;
  risk_score: number;
  status: string;
  findings: FindingItem[];
  subdomains: SubdomainItem[];
  urls: UrlItem[];
}
