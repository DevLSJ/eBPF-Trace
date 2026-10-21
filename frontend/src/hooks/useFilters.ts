import { useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate, type Location } from 'react-router-dom';
import { FILTER_DEFAULTS, keepInUrl, type FilterPath, type Filters, type NavState } from '../lib/nav';

export type FiltersOf<P extends FilterPath> = (typeof FILTER_DEFAULTS)[P];

// 이 이동이 필터를 가져왔나 — 화면 안 링크의 state.filters, 또는 바깥 링크 · 예전 북마크의 쿼리(그 화면의 필터 키)
function incoming(path: FilterPath, loc: Location): Filters | null {
  const defaults: Filters = FILTER_DEFAULTS[path];
  const keys = Object.keys(defaults);
  const params = new URLSearchParams(loc.search);
  const st = (loc.state as NavState | null)?.filters;
  const fromState = !!st && typeof st === 'object';
  let found = fromState;
  const out: Filters = {};
  for (const k of keys) {
    const v = params.get(k);
    if (v === null || keepInUrl(path, k, v)) continue;
    out[k] = v;
    found = true;
  }
  if (fromState) for (const k of keys) if (typeof st[k] === 'string') out[k] = st[k];
  return found ? { ...defaults, ...out } : null;
}

// 목록 필터(10/21) — 화면 상태로만 둔다. 초기값 = location.state ?? 쿼리 ?? 기본값.
// 들어온 필터는 한 번 적용한 뒤 주소(쿼리의 필터 키)와 state 에서 바로 지운다(replace, 링크용 키는 남김) — 새로고침 · 다시 열기는 기본값.
// 같은 화면에 머문 채 새 이동이 필터를 가져오면(검색 · 알림 · 사이드바) 그 값으로 다시 맞춘다.
export function useFilters<P extends FilterPath>(path: P): [FiltersOf<P>, (patch: Partial<FiltersOf<P>>) => void] {
  const loc = useLocation();
  const navigate = useNavigate();
  const [f, setF] = useState<Filters>(() => incoming(path, loc) ?? { ...FILTER_DEFAULTS[path] });
  const [seen, setSeen] = useState(loc.key);
  if (loc.key !== seen) {
    setSeen(loc.key);
    const next = incoming(path, loc);
    if (next) setF(next);
  }

  useEffect(() => {
    if (!incoming(path, loc)) return;
    const params = new URLSearchParams(loc.search);
    for (const k of Object.keys(FILTER_DEFAULTS[path])) {
      const v = params.get(k);
      if (v !== null && !keepInUrl(path, k, v)) params.delete(k);
    }
    const rest = { ...((loc.state as Record<string, unknown> | null) ?? {}) };
    delete rest.filters;
    const search = params.toString();
    navigate({ pathname: loc.pathname, search: search ? `?${search}` : '', hash: loc.hash }, { replace: true, state: Object.keys(rest).length ? rest : null });
  }, [path, loc, navigate]);

  const set = useCallback((patch: Partial<FiltersOf<P>>) => setF((cur) => ({ ...cur, ...(patch as Filters) })), []);
  return [f as FiltersOf<P>, set];
}
