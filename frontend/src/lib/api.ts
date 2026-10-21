import type {
  AuditEntry,
  AuthAuditEntry,
  Blocklist,
  BlockList,
  Case,
  Change,
  ChatFacts,
  ChatLink,
  ChatRequest,
  Decision,
  DecisionPreview,
  Evidence,
  Info,
  InstallSession,
  License,
  Me,
  OsvResult,
  PolicyDefaults,
  Preview,
  Proposal,
  Role,
  Rule,
  Scan,
  SessionState,
  Stats,
  Summary,
  SummaryRange,
  UserBrief,
  UserView,
  Verdict,
} from './types';
import { readSSE } from './sse';

const base = '/api';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    // 백엔드가 JSON 오류 본문({error})을 줬는지 — 라우트 자체가 없으면 404 + 텍스트
    public json = false,
    // 인증 오류 본문의 로그인 단계({error, state}) — need_password · need_license · need_otp_enroll · need_otp
    public state = '',
  ) {
    super(message);
  }
}

// 전역 인증 처리(W16): 401 → 본문 state 의 단계 화면(없으면 로그인), 403 → 「관리자만」 안내만(로그아웃하지 않음).
// AuthProvider 가 등록한다. 로그인 단계 화면이 직접 부르는 /api/auth/* 는 flow=true 로 이 처리를 건너뛴다(그 화면이 문구를 보인다).
export interface AuthHooks {
  unauthorized: (state: string, message: string) => void;
  forbidden: (message: string) => void;
}
let authHooks: AuthHooks | null = null;
export function setAuthHooks(h: AuthHooks | null) {
  authHooks = h;
}

// 새 API 가 아직 백엔드에 없을 때(라우트 없음 → 404). 그 영역만 「백엔드 미지원」으로 보이고 앱은 계속 동작한다.
export const isUnsupported = (e: unknown) => e instanceof ApiError && e.status === 404 && !e.json;

export const errorText = (e: unknown) =>
  e instanceof ApiError ? (e.status ? `${e.status} · ${e.message}` : e.message) : e instanceof Error ? e.message : String(e);

// 쿠키 세션(sg_session, HttpOnly)만 쓴다 — Authorization 헤더를 붙이지 않는다.
// 미들웨어는 Authorization 을 쿠키보다 먼저 보므로 옛 관리자 토큰이 남아 있으면 401 이 된다(W14).
async function send(path: string, init: RequestInit = {}, flow = false): Promise<Response> {
  const res = await fetch(base + path, { ...init, credentials: 'include' });
  if (!res.ok) {
    let msg = res.statusText;
    let json = false;
    let state = '';
    if ((res.headers.get('Content-Type') ?? '').includes('json')) {
      try {
        const b = (await res.json()) as { error?: string; state?: string };
        msg = b.error ?? msg;
        state = b.state ?? '';
        json = true;
      } catch {
        /* 본문 없음 */
      }
    }
    if (!flow && json && authHooks) {
      if (res.status === 401) authHooks.unauthorized(state, msg);
      else if (res.status === 403) authHooks.forbidden(msg);
    }
    throw new ApiError(res.status, msg, json, state);
  }
  return res;
}

async function request<T>(path: string, init: RequestInit = {}, flow = false): Promise<T> {
  const res = await send(path, init, flow);
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
  // 새 기본 규칙(10/20): 기본 정책 파일에는 있는데 지금 없는 규칙 · 조건이 다른 규칙(읽기 전용)
  policyDefaults: () => request<PolicyDefaults>('/policies/defaults'),
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
  // 판정 미리보기(W15): 판정하면 생길 제안 · 영향 — 저장 없음, 조회자도 부를 수 있다
  previewDecision: (id: string, decision: Exclude<Decision, 'pending'>) => request<DecisionPreview>(`/cases/${enc(id)}/preview`, json('POST', { decision })),
  proposals: (state?: string) => request<Proposal[]>(`/proposals${qs({ state })}`),
  preview: (id: string) => request<Preview>(`/proposals/${enc(id)}/preview`, { method: 'POST' }),
  // 공급망 검사(10/16): 시작 · 차단은 관리자
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
  // 사유(W18, 선택 · 500자)는 공급망 검사 건의 판정 메모로 남는다
  scanBlock: (id: string, reason = '') => request<{ proposalId: string }>(`/scans/${enc(id)}/block`, json('POST', reason ? { reason } : {})),
  // 저장소 · 파일 검사 결과에서 고른 패키지만 차단 제안(W4 · W18) — manager · version 을 비우면 백엔드가 검사 결과에서 채운다
  blockScanPackages: (id: string, packages: { manager?: string; name: string; version?: string }[], reason = '') =>
    request<{ proposalId: string }>(`/scans/${enc(id)}/block`, json('POST', reason ? { packages, reason } : { packages })),
  // eBPF 수집 종합(10/16)
  summary: (range: SummaryRange) => request<Summary>(`/summary?range=${range}`),
  // 정책 저장 전 확인(10/16): 바꾼 정책 하나로 감사 로그를 다시 평가(쓰기 없음)
  previewRule: (rule: Rule) => request<Preview>('/policies/preview', json('POST', rule)),
  // 적용 · 버림 · 차단 해제의 사유(W15, 선택 · 500자) → 변경 이력 reason
  applyProposal: (id: string, reason = '') => request<Proposal>(`/proposals/${enc(id)}/apply`, json('POST', { reason })),
  discardProposal: (id: string, reason = '') => request<Proposal>(`/proposals/${enc(id)}/discard`, json('POST', { reason })),

  // 차단 목록 · 변경 이력 · 정적 분석 비교
  blocklist: () => request<Blocklist>('/blocklist'),
  unblock: (list: BlockList, value: string, reason = '') => request<void>(`/blocklist/${list}/${enc(value)}`, json('DELETE', { reason })),
  changes: (limit = 100) => request<Change[]>(`/changes?limit=${limit}`),
  osv: (ecosystem: string, name: string) => request<OsvResult>(`/osv${qs({ ecosystem, name })}`),
  // kill 직전 증거(10/20) — 컨테이너 이름 또는 ID(앞부분), 최근 것부터
  evidence: (container: string) => request<Evidence[]>(`/evidence${qs({ container })}`),

  // AI 도우미(10/20): POST /api/chat → SSE token… → facts → links → done | error.
  // 시작 전 오류(400 · 429)는 ApiError 로 던지고, 스트림의 error 이벤트는 { error } 로 돌려준다. 멈추기는 signal(AbortError 를 던진다)
  chat,
};

// ── 인증(W16) — backend/internal/api/auth.go. 단계 경로는 flow=true(전역 401 처리 없이 화면이 문구를 보인다) ──
export const authApi = {
  me: () => request<Me>('/auth/me', {}, true),
  login: (username: string, password: string) =>
    request<{ state: SessionState; user: UserBrief }>('/auth/login', json('POST', { username, password }), true),
  // 첫 로그인 단계는 flow, 로그인 뒤 계정 메뉴의 변경은 전역 처리(현재 비밀번호 5번 틀림 → 401 → 로그인)
  password: (current: string, next: string, flow = true) =>
    request<{ state: SessionState }>('/auth/password', json('POST', { current, next }), flow),
  license: (key: string) => request<{ state: SessionState; license: License }>('/auth/license', json('POST', { key }), true),
  otpEnroll: () => request<{ secret: string; uri: string }>('/auth/otp/enroll', { method: 'POST' }, true),
  otpConfirm: (code: string) =>
    request<{ state: SessionState; recoveryCodes: string[] }>('/auth/otp/enroll/confirm', json('POST', { code }), true),
  otp: (b: { code: string } | { recovery: string }) => request<{ state: SessionState }>('/auth/otp', json('POST', b), true),
  logout: () => request<void>('/auth/logout', { method: 'POST' }, true),

  // 로그인 뒤(관리자 · 조회자): 라이선스 보기 / 관리자만: 계정 · 인증 감사
  getLicense: () => request<License>('/license'),
  // 라이선스 갱신(W21, 관리자만) — 응답은 getLicense 와 같은 모양. 형식 오류 400 은 로그인 단계와 같은 문구
  renewLicense: (key: string) => request<License>('/license', json('PUT', { key })),
  users: () => request<UserView[]>('/users'),
  createUser: (b: { username: string; displayName: string; role: Role }) =>
    request<{ user: UserView; tempPassword: string }>('/users', json('POST', b)),
  patchUser: (id: string, b: { role?: Role; disabled?: boolean; displayName?: string }) =>
    request<UserView>(`/users/${enc(id)}`, json('PATCH', b)),
  resetPassword: (id: string) => request<{ tempPassword: string }>(`/users/${enc(id)}/reset-password`, { method: 'POST' }),
  resetOtp: (id: string) => request<void>(`/users/${enc(id)}/reset-otp`, { method: 'POST' }),
  audit: (limit = 200) => request<AuthAuditEntry[]>(`/auth/audit?limit=${limit}`),
  // 알림 테스트 발송(관리자) — 202, 채널이 없으면 409. 발송은 비동기라 화면은 잠시 뒤 /api/info 를 다시 읽는다
  notifyTest: () => request<unknown>('/notify/test', { method: 'POST' }),
};

// 로그인 여부 다시 확인(실시간 연결이 열리기 전에 닫혔을 때) — active 가 아니면 전역 401 처리로 넘긴다
export async function recheckSession() {
  if (!authHooks) return;
  try {
    const m = await authApi.me();
    if (m.state !== 'active') authHooks.unauthorized(m.state, '');
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) authHooks?.unauthorized(e.state, e.message);
  }
}

export interface ChatHandlers {
  token: (t: string) => void;
  facts: (f: ChatFacts) => void;
  links: (l: ChatLink[]) => void;
}

async function chat(body: ChatRequest, on: ChatHandlers, signal?: AbortSignal): Promise<{ error: string | null }> {
  const res = await send('/chat', { ...json('POST', body), signal });
  if (!res.body) return { error: '응답 본문이 없습니다' };
  let end: { error: string | null } | null = null;
  await readSSE(res.body, ({ event, data }) => {
    let v: unknown;
    try {
      v = JSON.parse(data);
    } catch {
      return false; // 모양이 틀린 조각은 건너뛴다
    }
    if (event === 'token' && typeof v === 'string') on.token(v);
    else if (event === 'facts' && v && typeof v === 'object') on.facts(v as ChatFacts);
    else if (event === 'links' && Array.isArray(v)) on.links(v as ChatLink[]);
    else if (event === 'done') end = { error: null };
    else if (event === 'error') end = { error: typeof v === 'string' && v ? v : 'AI 모델 답을 받지 못했습니다' };
    return end !== null;
  });
  return end ?? { error: '답이 끝나기 전에 연결이 끊겼습니다' };
}
