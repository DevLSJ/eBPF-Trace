import type {
  AuditEntry,
  Blocklist,
  BlockList,
  Case,
  Change,
  Decision,
  Info,
  InstallSession,
  OsvResult,
  Preview,
  Proposal,
  Rule,
  Scan,
  Stats,
  Summary,
  SummaryRange,
  Verdict,
} from './types';

const base = '/api';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    // 백엔드가 JSON 오류 본문({error})을 줬는지 — 라우트 자체가 없으면 404 + 텍스트
    public json = false,
  ) {
    super(message);
  }
}

// 새 API 가 아직 백엔드에 없을 때(라우트 없음 → 404). 그 영역만 「백엔드 미지원」으로 보이고 앱은 계속 동작한다.
export const isUnsupported = (e: unknown) => e instanceof ApiError && e.status === 404 && !e.json;

export const errorText = (e: unknown) =>
  e instanceof ApiError ? (e.status ? `${e.status} · ${e.message}` : e.message) : e instanceof Error ? e.message : String(e);

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = readToken();
  if (token && init.method && init.method !== 'GET') headers.set('Authorization', `Bearer ${token}`);
  const res = await fetch(base + path, { ...init, headers });
  if (!res.ok) {
    let msg = res.statusText;
    let json = false;
    if ((res.headers.get('Content-Type') ?? '').includes('json')) {
      try {
        msg = ((await res.json()) as { error?: string }).error ?? msg;
        json = true;
      } catch {
        /* 본문 없음 */
      }
    }
    throw new ApiError(res.status, msg, json);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get('Content-Type') ?? '';
  return (ct.includes('json') ? res.json() : res.text()) as Promise<T>;
}

const TOKEN_KEY = 'supplyguard.adminToken';
function readToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? '';
  } catch {
    return memToken;
  }
}
let memToken = '';
const tokenListeners = new Set<() => void>();

// 관리자 토큰은 탭을 닫으면 사라지도록 sessionStorage에만 둔다. 여러 화면이 같은 값을 보도록 구독할 수 있다.
export const adminToken = {
  get: readToken,
  set: (v: string) => {
    memToken = v;
    try {
      if (v) sessionStorage.setItem(TOKEN_KEY, v);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* 저장소 차단 시 메모리에만 */
    }
    tokenListeners.forEach((f) => f());
  },
  subscribe: (f: () => void) => {
    tokenListeners.add(f);
    return () => tokenListeners.delete(f);
  },
};

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

const qs = (p: object) => {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) if (v !== undefined && v !== '' && v !== null) q.set(k, String(v));
  const s = q.toString();
  return s ? `?${s}` : '';
};
const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});
const enc = encodeURIComponent;

export const api = {
  info: () => request<Info>('/info'),
  stats: () => request<Stats>('/stats'),
  recent: (limit = 500) => request<Verdict[]>(`/events/recent?limit=${limit}`),
  listRules: () => request<Rule[]>('/policies'),
  exportYaml: () => request<string>('/policies/export'),
  saveRule: (rule: Rule) => request<Rule>('/policies', json('POST', rule)),
  applyYaml: (yaml: string) =>
    request<Rule[]>('/policies', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/yaml' },
      body: yaml,
    }),
  deleteRule: (id: string) => request<void>(`/policies/${enc(id)}`, { method: 'DELETE' }),
  audit: (p: AuditParams) => request<AuditEntry[]>(`/audit${qs(p)}`),

  // 설치 검사
  installs: (p: { status?: string; manager?: string; limit?: number } = {}) =>
    request<InstallSession[]>(`/installs${qs({ limit: 500, ...p })}`),
  install: (id: string) => request<InstallSession>(`/installs/${enc(id)}`),

  // 건 · 판정 · 제안
  cases: (p: { state?: string; source?: string } = {}) => request<Case[]>(`/cases${qs(p)}`),
  case: (id: string) => request<Case>(`/cases/${enc(id)}`),
  decide: (id: string, decision: Exclude<Decision, 'pending'>, note = '') =>
    request<{ case: Case; proposal: Proposal | null }>(`/cases/${enc(id)}/decide`, json('POST', { decision, note })),
  proposals: (state?: string) => request<Proposal[]>(`/proposals${qs({ state })}`),
  preview: (id: string) => request<Preview>(`/proposals/${enc(id)}/preview`, { method: 'POST' }),
  // 공급망 검사(10/16): 시작 · 차단은 관리자 토큰
  scans: () => request<Scan[]>('/scans'),
  scan: (id: string) => request<Scan>(`/scans/${enc(id)}`),
  startScan: (body: { kind: 'package' | 'repo'; manager?: string; name?: string; version?: string; url?: string } | File) => {
    if (body instanceof File) {
      const fd = new FormData();
      fd.append('file', body, body.name);
      return request<{ id: string }>('/scans', { method: 'POST', body: fd });
    }
    return request<{ id: string }>('/scans', json('POST', body));
  },
  scanBlock: (id: string) => request<{ proposalId: string }>(`/scans/${enc(id)}/block`, { method: 'POST' }),
  // eBPF 수집 종합(10/16)
  summary: (range: SummaryRange) => request<Summary>(`/summary?range=${range}`),
  // 정책 저장 전 확인(10/16): 바꾼 정책 하나로 감사 로그를 다시 평가(쓰기 없음)
  previewRule: (rule: Rule) => request<Preview>('/policies/preview', json('POST', rule)),
  applyProposal: (id: string) => request<Proposal>(`/proposals/${enc(id)}/apply`, { method: 'POST' }),
  discardProposal: (id: string) => request<Proposal>(`/proposals/${enc(id)}/discard`, { method: 'POST' }),

  // 차단 목록 · 변경 이력 · 정적 분석 비교
  blocklist: () => request<Blocklist>('/blocklist'),
  unblock: (list: BlockList, value: string) => request<void>(`/blocklist/${list}/${enc(value)}`, { method: 'DELETE' }),
  changes: (limit = 100) => request<Change[]>(`/changes?limit=${limit}`),
  osv: (ecosystem: string, name: string) => request<OsvResult>(`/osv${qs({ ecosystem, name })}`),
};
