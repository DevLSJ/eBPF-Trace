import axios from 'axios';
import type { EventPage, Health, SystemMetric } from '../types';

export const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || '', timeout: 10000 });
export function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) return error.response?.data?.error?.message || '서버에 연결할 수 없습니다.';
  return '요청을 처리하지 못했습니다.';
}
export const getEvents = (params: Record<string, unknown>, signal?: AbortSignal) => api.get<EventPage>('/api/events', { params, signal }).then(r => r.data);
export const getMetrics = () => api.get<SystemMetric | null>('/api/metrics').then(r => r.data);
export const getHealth = () => api.get<Health>('/health').then(r => r.data);
