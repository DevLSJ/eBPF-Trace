// 목록 필터는 주소에 남기지 않는다(10/21, 보안 — 사용자 결정). 주소에는 링크용 값(id · proposal · tab · view, 토폴로지 컨테이너 노드)만.
// 화면 안 링크는 필터를 history state 로 넘기고, 화면은 처음 그릴 때(또는 새 이동 때) 그 값을 초기 필터로 쓴 뒤 state 를 비운다(새로고침하면 기본값).

export type Filters = Record<string, string>;
export interface NavState {
  filters?: Filters;
}
// 화면 안 이동 대상 — Link 의 to · state 로 그대로 넘긴다
export interface Dest {
  to: string;
  state?: NavState;
}

// 화면별 필터 키와 기본값(여기 있는 키는 주소에 남기지 않는다)
export const FILTER_DEFAULTS = {
  '/': { range: '24h' },
  '/installs': { status: 'pending', manager: '' },
  '/events': { kind: '', level: '', normal: '', container: '' },
  '/audit': { kind: '', action: '', decision: '', rule: '', container: '', since: '', until: '' },
  '/scans': { verdict: '' },
  // node 는 컨테이너 노드(c:)만 링크로 주소에 남고, 파일 · 도메인 · IP · 프로세스 노드는 화면 상태로만
  '/topology': { container: '', node: '' },
  // 정책 마법사 미리 채우기
  '/policies': { tpl: '', intent: '', kind: '', value: '', default: '' },
} satisfies Record<string, Filters>;
export type FilterPath = keyof typeof FILTER_DEFAULTS;

export const filterKeys = (path: string): string[] => Object.keys((FILTER_DEFAULTS as Record<string, Filters>)[path] ?? {});
// 필터 키여도 링크로 주소에 남기는 값 — 토폴로지 컨테이너 노드
export const keepInUrl = (path: string, k: string, v: string) => path === '/topology' && k === 'node' && v.startsWith('c:');

// 화면을 처음 연 것처럼(기본 필터) — 사이드바 메뉴
export const FRESH: NavState = { filters: {} };

export function dest(to: string, filters?: Record<string, string | null | undefined>): Dest {
  if (!filters) return { to };
  const f: Filters = {};
  for (const [k, v] of Object.entries(filters)) if (v) f[k] = v;
  return { to, state: { filters: f } };
}

// 링크 문자열(AI 도우미 답 등 바깥에서 온 href)을 주소 + state 로 나눈다 — 그 화면의 필터 키는 state 로
export function splitHref(href: string): Dest {
  const q = href.indexOf('?');
  if (q < 0) return { to: href };
  const hashAt = href.indexOf('#', q);
  const path = href.slice(0, q);
  const hash = hashAt < 0 ? '' : href.slice(hashAt);
  const params = new URLSearchParams(href.slice(q + 1, hashAt < 0 ? undefined : hashAt));
  const keys = filterKeys(path);
  const filters: Filters = {};
  for (const k of keys) {
    const v = params.get(k);
    if (v === null || keepInUrl(path, k, v)) continue;
    filters[k] = v;
    params.delete(k);
  }
  const rest = params.toString();
  const to = `${path}${rest ? `?${rest}` : ''}${hash}`;
  return Object.keys(filters).length ? { to, state: { filters } } : { to };
}

const enc = encodeURIComponent;
// 자주 쓰는 이동 — 설치 세션 열기(결과 칩 기본 「전체」) · 토폴로지 컨테이너 노드
export const installDest = (id: string, status = 'all') => dest(`/installs?id=${enc(id)}`, { status });
export const topologyDest = (container: string) => dest(`/topology?node=${enc(`c:${container}`)}`, { container });
