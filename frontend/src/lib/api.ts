import type { AuditEntry, Info, Rule, Stats, Verdict } from './types';

const base = '/api';
const TOKEN_KEY = 'supplyguard.adminToken';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

// 관리자 토큰은 탭을 닫으면 사라지도록 sessionStorage에만 둔다
export const adminToken = {
  get: () => {
    try {
      return sessionStorage.getItem(TOKEN_KEY) ?? '';
    } catch {
      return '';
    }
  },
  set: (v: string) => {
    try {
      if (v) sessionStorage.setItem(TOKEN_KEY, v);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* 저장소 차단 시 이번 요청에만 사용 */
    }
  },
};

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = adminToken.get();
  if (token && init.method && init.method !== 'GET') headers.set('Authorization', `Bearer ${token}`);
  const res = await fetch(base + path, { ...init, headers });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = ((await res.json()) as { error?: string }).error ?? msg;
    } catch {
      /* 본문 없음 */
    }
    throw new ApiError(res.status, msg);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get('Content-Type') ?? '';
  return (ct.includes('json') ? res.json() : res.text()) as Promise<T>;
}

export interface AuditParams {
  kind?: string;
  action?: string;
  rule?: string;
  container?: string;
  since?: string;
  until?: string;
  before?: number;
  limit?: number;
}

export const api = {
  info: () => request<Info>('/info'),
  stats: () => request<Stats>('/stats'),
  recent: (limit = 500) => request<Verdict[]>(`/events/recent?limit=${limit}`),
  listRules: () => request<Rule[]>('/policies'),
  exportYaml: () => request<string>('/policies/export'),
  saveRule: (rule: Rule) =>
    request<Rule>('/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    }),
  applyYaml: (yaml: string) =>
    request<Rule[]>('/policies', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/yaml' },
      body: yaml,
    }),
  deleteRule: (id: string) => request<void>(`/policies/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  audit: (p: AuditParams) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(p)) if (v !== undefined && v !== '') q.set(k, String(v));
    return request<AuditEntry[]>(`/audit?${q}`);
  },
};
