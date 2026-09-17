import axios from 'axios';
import type { Scenario, ScenarioRun, EventSummary, CaptureReport, DetectionEvent, EventPage, Health, ModelAnalysis, SystemMetric, Thresholds } from '../types';

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
export const getModelAnalysis = () => api.get<ModelAnalysis>('/api/analysis/model').then(r => r.data);

export const getEventSummary = (params: Record<string, unknown>, signal?: AbortSignal) => api.get<EventSummary>('/api/events/summary', { params, signal }).then(r => r.data);
export const reviewEvent = (id: number, is_confirmed: boolean | null, note: string, token: string) => api.patch<DetectionEvent>(`/api/events/${id}/review`, { is_confirmed, note }, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.data);
export const getScenarios = () => api.get<{ items: Scenario[] }>('/api/scenarios').then(r => r.data.items);
export const getRuns = () => api.get<{ items: ScenarioRun[] }>('/api/scenarios/runs').then(r => r.data.items);
export const getRun = (id: string, signal?: AbortSignal) => api.get<ScenarioRun>(`/api/scenarios/runs/${id}`, { signal }).then(r => r.data);
export const startRun = (scenario_id: string, request_id: string, token: string) => api.post<ScenarioRun>('/api/scenarios/runs', { scenario_id, request_id }, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.data);
export const stopRun = (id: string, token: string) => api.post<ScenarioRun>(`/api/scenarios/runs/${id}/stop`, {}, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.data);
