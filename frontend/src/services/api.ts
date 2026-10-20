import axios from 'axios';

import type { HistoryItem, Report, ScanResult } from '../types';

const api = axios.create({
  baseURL: 'http://localhost:8000',
  timeout: 20000,
});

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
