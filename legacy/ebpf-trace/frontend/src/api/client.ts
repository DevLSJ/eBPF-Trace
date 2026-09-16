import axios from 'axios';
import type { CaptureReport, DetectionEvent, EventPage, Health, SystemMetric, Thresholds } from '../types';

export const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || '', timeout: 10000 });
export function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) return error.response?.data?.error?.message || '서버에 연결할 수 없습니다.';
  return '요청을 처리하지 못했습니다.';
}
export const getEvents = (params: Record<string, unknown>, signal?: AbortSignal) => api.get<EventPage>('/api/events', { params, signal }).then(r => r.data);
export const getMetrics = () => api.get<SystemMetric | null>('/api/metrics').then(r => r.data);
export const getHealth = () => api.get<Health>('/health').then(r => r.data);
export const getEvent = (id: number, signal?: AbortSignal) => api.get<DetectionEvent>(`/api/events/${id}`, { signal }).then(r => r.data);
export const getThresholds = () => api.get<Thresholds>('/api/config/thresholds').then(r => r.data);
export const saveThresholds = (value: Thresholds, token: string) => api.put<Thresholds>('/api/config/thresholds', value, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.data);
export const getCaptureReport = () => api.get<{ items: CaptureReport[] }>('/api/analysis/pcap').then(r => r.data.items);
