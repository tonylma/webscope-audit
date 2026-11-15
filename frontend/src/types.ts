export type Role = 'admin' | 'security_analyst' | 'fraud_analyst' | 'auditor' | 'reader';

export interface UserInfo {
  id: number; username: string; display_name: string; email?: string | null;
  role: Role; is_active?: boolean;
}
export interface LoginResponse {
  access_token: string; token_type: 'bearer'; expires_at: number; user: UserInfo;
}
export interface ScanResult {
  id: number; target_url: string; status: string; risk_score: number; summary: string;
}
export interface HistoryItem extends ScanResult {}
export interface FindingItem {
  category: string; title: string; severity: string; description: string; evidence: string;
}
export interface Report {
  scan_id: number; summary: string; risk_score: number; status: string;
  findings: FindingItem[]; subdomains: {name: string; ip?: string | null; status: string}[];
  urls: {url: string; source: string; status_code: number; depth: number}[];
}
export interface UrlSignal {
  code: string; label: string; points: number; severity: string; explanation: string;
}
export interface UrlAnalysis {
  submitted_url: string; normalized_host: string; risk_score: number; risk_level: string;
  signals: UrlSignal[]; network_access: string; recommendation: string; limitations: string;
}
export interface StaticFileResult {
  sha256: string; size_bytes: number; file_type: string;
  static_indicators: {indicator: string; points: number}[];
  risk_score: number; risk_level: string; disposition: string;
  execution_performed: boolean; archive_extraction_performed: boolean;
  network_access_performed: boolean; verdict: string; limitations: string;
  antivirus?: {status: string; engine?: string; signature_response?: string; reason?: string};
  audit?: {timestamp: string; entry_hash: string};
}
export interface FraudForm {
  case_reference: string; sim_change_hours: string; beneficiary_added: boolean;
  beneficiary_age_minutes: string; remote_access_tool_detected: boolean;
  accessibility_abuse_detected: boolean; screen_capture_detected: boolean;
  app_integrity_warning: boolean; social_engineering_reported: boolean;
  phone_number_spoofing_suspected: boolean; otp_failures_15m: string;
  new_device: boolean; impossible_travel: boolean; mobile_api_anomaly: boolean;
  transactions_10m: string; amount_vs_30d_median: string;
  shared_beneficiary_accounts_24h: string; rapid_cashout: boolean;
  channel: 'wallet' | 'bank_transfer' | 'cashout' | 'merchant' | 'unknown';
}
export interface FraudCaseSummary { id: number; case_token: string; status: string; risk_score: number; risk_level: string; created_at: string; updated_at: string; }\nexport interface FraudCaseDetail { id: number; case_token: string; status: string; risk_score: number; risk_level: string; created_at: string; updated_at: string; input: Record<string, any>; evaluation: FraudEvaluation; review_note?: string | null; }\nexport interface FraudEvaluation {
  risk_score: number; risk_level: string;
  signals: {rule_id: string; label: string; points: number; severity: string;
    explanation: string; recommended_controls: string[]}[];
  recommended_actions: string[];
  mitre_f3: {version: string; tactics: string[]; techniques: {id: string; name: string; tactic: string; source: string}[]; framework_url: string};
  decision_note: string; case_token?: string;
  audit?: {timestamp: string; entry_hash: string};
}
export interface FraudControl {
  id: string; title: string; objective: string; test: string; evidence: string[];
  frequency: string; owner: string;
}
export interface AdminUser extends UserInfo { created_at?: string; }
