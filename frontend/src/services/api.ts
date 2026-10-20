import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 15000,
});

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

export async function createScan(url: string): Promise<ScanResult> {
  const response = await api.post('/scan', { url });
  return response.data;
}

export async function getHistory(): Promise<{ scans: HistoryItem[] }> {
  const response = await api.get('/history');
  return response.data;
}
