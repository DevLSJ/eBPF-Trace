import { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useSearchParams, type Location } from 'react-router-dom';
import type { NavState } from '../lib/nav';
import { PAGE_SIZES, type SortState, type TableQuery } from './useTableKit';

// 목록 상태(11/09 · 10/21 결정 유지 — 사용자 11/09 재확인): 필터 · 검색 · 쪽 · 쪽 크기 · 정렬은 화면 상태(새로고침하면 기본값,
//   검색어가 주소 · 방문 기록에 남지 않음). 주소에는 열린 상세 id · 상세 탭(첫 탭 생략) · 그 화면이 넘겨준 링크용 키(proposal · view · node 등)만.
//   칸 보이기 · 폭 · 순서는 useTableKit(grid) 이 브라우저에 기억한다.
//   초기값 = location.state.filters(다른 화면 링크 — lib/nav dest()) ?? 옛 주소 쿼리(필터 키 · page · size · sort) ?? 기본값.
//   들어온 필터 · 쪽 · 정렬 키는 한 번 적용한 뒤 주소 · state 에서 replace 로 지운다(링크용 키는 남김) — hooks/useFilters.ts(10/21b)와 같은 규칙.
//   같은 화면에 머문 채 새 이동이 필터를 가져오면(검색 · 알림 · 사이드바) 그 값으로 다시 맞춘다.
//   틀린 값(모르는 정렬 칸 · 쪽 크기 · validate 실패 · 모르는 탭)은 기본값으로 읽고, 주소에 있던 것은 지운다.
//   필터 · 쪽 크기 · 정렬이 바뀌면 첫 쪽 · 주소 변경(상세 열기 · 탭)은 모두 replace(방문 기록을 늘리지 않음)
export interface ListQueryOptions<F extends Record<string, string>> {
  // 필터 기본값(키 = 옛 주소 · 링크 state 의 이름). 보통 '' = 전체
  filters: F;
  // 필터 값 검사 — false 면 기본값(예: 선택 상자에 없는 값)
  validate?: { [K in keyof F]?: (v: string) => boolean };
  sort?: SortState;
  // 받는 정렬 칸(없으면 영문으로 시작하는 1~64자 [A-Za-z0-9_.-])
  sortKeys?: readonly string[];
  size?: number;
  sizes?: readonly number[];
  // 상세 탭(첫 탭 = 기본, 주소에 쓰지 않음)
  tabs?: readonly string[];
  idParam?: string;
  idValid?: (v: string) => boolean;
}
export interface ListState<F> {
  filters: F;
  page: number;
  size: number;
  sort: SortState;
  id: string | null;
  tab: string | null;
}
type ScreenState<F> = Pick<ListState<F>, 'filters' | 'page' | 'size' | 'sort'>;

const SORT_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const MAX_VALUE = 200;
const LIST_KEYS = ['page', 'size', 'sort'];

export function useListQuery<F extends Record<string, string>>(o: ListQueryOptions<F>) {
  const [params, setParams] = useSearchParams();
  const loc = useLocation();
  const navigate = useNavigate();
  const idKey = o.idParam ?? 'id';
  const sizes = o.sizes ?? PAGE_SIZES;
  const defSize = o.size ?? 20;
  const defSort: SortState = o.sort ?? { key: null, dir: 'asc' };
  const tabsKey = (o.tabs ?? []).join('\n');
  const tabs = useMemo(() => (tabsKey ? tabsKey.split('\n') : []), [tabsKey]);
  const fkeys = Object.keys(o.filters) as (keyof F & string)[];
  const okFilter = (k: keyof F & string, v: unknown): v is string =>
    typeof v === 'string' && v.length <= MAX_VALUE && (v === '' || (o.validate?.[k]?.(v) ?? true));
  const defaults = (): ScreenState<F> => ({ filters: { ...o.filters }, page: 1, size: defSize, sort: defSort });

  // 이 이동이 목록 상태를 가져왔나 — 링크 state.filters, 또는 옛 주소 · 북마크의 필터 · 쪽 · 정렬 키(state 가 주소보다 먼저)
  const incoming = (l: Location): Partial<ScreenState<F>> | null => {
    const p = new URLSearchParams(l.search);
    const st = (l.state as NavState | null)?.filters;
    const fromState = !!st && typeof st === 'object';
    let found = fromState;
    const out: Partial<ScreenState<F>> = {};
    const filters = { ...o.filters };
    for (const k of fkeys) {
      const v = p.get(k);
      if (v === null) continue;
      found = true;
      if (okFilter(k, v)) (filters as Record<string, string>)[k] = v;
    }
    if (fromState) for (const k of fkeys) if (okFilter(k, st[k])) (filters as Record<string, string>)[k] = st[k];
    if (found) out.filters = filters;
    if (p.has('size')) {
      found = true;
      const sz = Number(p.get('size'));
      if (sizes.includes(sz)) out.size = sz;
    }
    if (p.has('page')) {
      found = true;
      const pg = Number(p.get('page'));
      if (Number.isInteger(pg) && pg >= 1 && pg <= 1_000_000) out.page = pg;
    }
    const raw = p.get('sort');
    if (raw !== null) {
      found = true;
      const [k, d] = raw.split(',');
      if ((o.sortKeys ? o.sortKeys.includes(k) : SORT_RE.test(k)) && (d === 'asc' || d === 'desc')) out.sort = { key: k, dir: d };
    }
    return found ? out : null;
  };

  const [st, setSt] = useState<ScreenState<F>>(() => ({ ...defaults(), ...(incoming(loc) ?? {}) }));
  const [seen, setSeen] = useState(loc.key);
  if (loc.key !== seen) {
    setSeen(loc.key);
    const next = incoming(loc);
    // 새 이동이 가져온 것만 바꾼다 — 필터를 가져오면 첫 쪽(옛 주소가 쪽을 함께 주면 그 쪽)
    if (next) setSt((cur) => ({ ...cur, ...next, page: next.page ?? (next.filters ? 1 : cur.page) }));
  }

  // 주소 정리: 들어온 필터 · 쪽 · 정렬 키와 link state 를 지우고(한 번 적용), 틀린 탭 · 첫 탭 · 상세 없는 탭도 지운다
  useEffect(() => {
    const cur = new URLSearchParams(loc.search);
    const next = new URLSearchParams(cur);
    for (const k of [...fkeys, ...LIST_KEYS]) next.delete(k);
    const id = next.get(idKey);
    const t = next.get('tab');
    if (t !== null && (!id || !tabs.includes(t) || t === tabs[0])) next.delete('tab');
    const hasState = !!(loc.state as NavState | null)?.filters;
    if (next.toString() === cur.toString() && !hasState) return;
    const rest = { ...((loc.state as Record<string, unknown> | null) ?? {}) };
    delete rest.filters;
    const search = next.toString();
    navigate({ pathname: loc.pathname, search: search ? `?${search}` : '', hash: loc.hash }, { replace: true, state: Object.keys(rest).length ? rest : null });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- 주소가 바뀔 때만 다시 본다(옵션 값은 같다)
  }, [loc.key, loc.search]);

  // 주소에 남는 것: 열린 상세 · 탭
  const idRaw = params.get(idKey);
  const id = idRaw && idRaw.length <= MAX_VALUE && (o.idValid?.(idRaw) ?? true) ? idRaw : null;
  const tRaw = params.get('tab');
  const tab = id && tRaw && tabs.includes(tRaw) ? tRaw : (tabs[0] ?? null);
  const writeUrl = useCallback(
    (fn: (p: URLSearchParams) => void) =>
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          fn(p);
          return p;
        },
        { replace: true },
      ),
    [setParams],
  );
  const putTab = useCallback((p: URLSearchParams, t: string | null) => (t && t !== tabs[0] ? p.set('tab', t) : p.delete('tab')), [tabs]);

  const setFilters = useCallback((patch: Partial<F>) => setSt((s) => ({ ...s, filters: { ...s.filters, ...patch }, page: 1 })), []);
  const clearFilters = useCallback(() => setSt((s) => ({ ...s, filters: { ...o.filters }, page: 1 })), [o.filters]);
  const setPage = useCallback((page: number) => setSt((s) => ({ ...s, page: Math.max(1, Math.floor(page)) })), []);
  const setSize = useCallback((size: number) => setSt((s) => ({ ...s, size, page: 1 })), []);
  const setSort = useCallback((sort: SortState) => setSt((s) => ({ ...s, sort, page: 1 })), []);
  const sortBy = useCallback(
    (k: string) => setSt((s) => ({ ...s, page: 1, sort: s.sort.key === k ? { key: k, dir: s.sort.dir === 'asc' ? 'desc' : 'asc' } : { key: k, dir: 'asc' } })),
    [],
  );
  // 상세 열기 — 이미 열려 있으면(앞뒤 넘김) 지금 탭을 그대로, 새로 열면 첫 탭
  const open = useCallback(
    (next: string, t?: string) =>
      writeUrl((p) => {
        const had = p.get(idKey);
        p.set(idKey, next);
        putTab(p, t ?? (had ? p.get('tab') : null));
      }),
    [writeUrl, putTab, idKey],
  );
  const close = useCallback(
    () =>
      writeUrl((p) => {
        p.delete(idKey);
        p.delete('tab');
      }),
    [writeUrl, idKey],
  );
  const setTab = useCallback((t: string) => writeUrl((p) => putTab(p, t)), [writeUrl, putTab]);
  const active = fkeys.some((k) => st.filters[k] !== o.filters[k]);
  const table: TableQuery = useMemo(() => ({ sort: st.sort, setSort, page: st.page, setPage, size: st.size, setSize }), [st.sort, setSort, st.page, setPage, st.size, setSize]);

  return { ...st, id, tab, active, setFilters, clearFilters, setPage, setSize, setSort, sortBy, open, close, setTab, table };
}
export type ListQuery<F extends Record<string, string>> = ReturnType<typeof useListQuery<F>>;
