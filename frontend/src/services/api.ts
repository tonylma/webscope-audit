import axios from 'axios';
import type {
  AdminUser, FraudControl, FraudEvaluation, FraudForm, HistoryItem, LoginResponse,
  Report, ScanResult, StaticFileResult, UrlAnalysis, UserInfo,
} from '../types';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 45000,
  headers: { 'Content-Type': 'application/json' },
});

// Access token is intentionally memory-only. Reloading the page requires a new login;
// this avoids persisting bearer credentials in localStorage/sessionStorage.
let accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}
export function setAnalystCredentials(_key: string, _id: string) {
  // Legacy compatibility: user identity and authorization now come from the JWT.
}
api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
  return config;
});

export async function login(username: string, password: string): Promise<LoginResponse> {
  const response = await api.post('/auth/login', { username, password });
  setAccessToken(response.data.access_token);
  return response.data;
}
export async function getMe(): Promise<UserInfo> {
  const response = await api.get('/auth/me');
  return response.data;
}
export async function getUsers(): Promise<{ users: AdminUser[] }> {
  const response = await api.get('/auth/users');
  return response.data;
}
export async function createUser(payload: {username: string; display_name: string; email?: string; password: string; role: string}) {
  const response = await api.post('/auth/users', payload);
  return response.data;
}
export async function revokeUserSessions(userId: number) {
  const response = await api.post(`/auth/users/${userId}/revoke`);
  return response.data;
}
export async function createScan(url: string): Promise<ScanResult> {
  const response = await api.post('/scan', { url });
  return response.data;
}
export async function getReport(scanId: number): Promise<Report> {
  const response = await api.get(`/scan/${scanId}/report`);
  return response.data;
}
export async function getHistory(): Promise<{ scans: HistoryItem[] }> {
  const response = await api.get('/history');
  return response.data;
}
export async function analyzeUrl(url: string): Promise<UrlAnalysis> {
  const response = await api.post('/defense/url-analysis', { url });
  return response.data;
}
export async function triageFile(file: File): Promise<StaticFileResult> {
  const body = new FormData();
  body.append('file', file);
  const response = await api.post('/defense/file-triage', body, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
}
function toFraudPayload(form: FraudForm) {
  const numeric = (value: string, fallback: number | null = 0) =>
    value.trim() === '' ? fallback : Number(value);
  return {
    ...form,
    sim_change_hours: numeric(form.sim_change_hours, null),
    beneficiary_age_minutes: numeric(form.beneficiary_age_minutes, null),
    otp_failures_15m: numeric(form.otp_failures_15m, 0),
    transactions_10m: numeric(form.transactions_10m, 0),
    amount_vs_30d_median: numeric(form.amount_vs_30d_median, 1),
    shared_beneficiary_accounts_24h: numeric(form.shared_beneficiary_accounts_24h, 0),
  };
}
export async function evaluateFraud(form: FraudForm): Promise<FraudEvaluation> {
  const response = await api.post('/fraud/evaluate', toFraudPayload(form));
  return response.data;
}
export async function getFraudControls(): Promise<{controls: FraudControl[]; count: number; note: string}> {
  const response = await api.get('/fraud/controls');
  return response.data;
}
export async function getAuditStatus(): Promise<{valid: boolean; entries_checked: number; last_hash: string}> {
  const response = await api.get('/fraud/audit/verify');
  return response.data;
}
export default api;
