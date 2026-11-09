import { useCallback, useEffect, useMemo } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import type { NavState } from '../lib/nav';
import { PAGE_SIZES, type SortState, type TableQuery } from './useTableKit';

// 목록 상태를 주소 쿼리에(11/09 메인 기본값 — 참고 제품의 목록 틀): 필터 · 검색 · 쪽 · 쪽 크기 · 정렬 · 열린 상세 id · 상세 탭.
//   새로고침 · 뒤로 가기 · 주소 공유가 그대로. 기존 useFilters(10/21 「필터는 화면 상태」)는 이 훅으로 옮긴 화면부터 대신한다.
//   쿼리 이름: 필터 키 그대로 · page · size · sort(`칸,asc|desc`) · id(idParam) · tab
//   기본값은 주소에서 지운다 · 틀린 값(모르는 정렬 칸 · 쪽 크기 · validate 실패 · 모르는 탭)은 기본값으로 읽고 주소에서도 지운다
//   필터 · 쪽 크기 · 정렬이 바뀌면 첫 쪽 · 모든 변경은 replace(방문 기록을 늘리지 않음) · 목록과 상관없는 쿼리 키는 그대로
//   다른 화면 링크가 state.filters(lib/nav dest())로 필터를 가져오면 주소로 옮긴다
export interface ListQueryOptions<F extends Record<string, string>> {
  // 필터 기본값(키 = 쿼리 이름). 보통 '' = 전체
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

const SORT_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const MAX_VALUE = 200;

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

  const read = (p: URLSearchParams): ListState<F> => {
    const filters = { ...o.filters };
    for (const k of fkeys) {
      const v = p.get(k);
      if (v === null || v.length > MAX_VALUE) continue;
      if (v === '' || (o.validate?.[k]?.(v) ?? true)) (filters as Record<string, string>)[k] = v;
    }
    const sz = Number(p.get('size'));
    const pg = Number(p.get('page'));
    let sort = defSort;
    const raw = p.get('sort');
    if (raw) {
      const [k, d] = raw.split(',');
      if ((o.sortKeys ? o.sortKeys.includes(k) : SORT_RE.test(k)) && (d === 'asc' || d === 'desc')) sort = { key: k, dir: d };
    }
    const idRaw = p.get(idKey);
    const id = idRaw && idRaw.length <= MAX_VALUE && (o.idValid?.(idRaw) ?? true) ? idRaw : null;
    const t = p.get('tab');
    return {
      filters,
      size: sizes.includes(sz) ? sz : defSize,
      page: Number.isInteger(pg) && pg >= 1 && pg <= 1_000_000 ? pg : 1,
      sort,
      id,
      tab: t && tabs.includes(t) ? t : (tabs[0] ?? null),
    };
  };
  // 상태 → 쿼리(목록 키만 고치고 나머지 키는 둔다)
  const build = (prev: URLSearchParams, s: ListState<F>) => {
    const p = new URLSearchParams(prev);
    const put = (k: string, v: string | null) => (v === null ? p.delete(k) : p.set(k, v));
    for (const k of fkeys) put(k, s.filters[k] === o.filters[k] ? null : s.filters[k]);
    put('page', s.page > 1 ? String(s.page) : null);
    put('size', s.size !== defSize ? String(s.size) : null);
    put('sort', s.sort.key && (s.sort.key !== defSort.key || s.sort.dir !== defSort.dir) ? `${s.sort.key},${s.sort.dir}` : !s.sort.key && defSort.key ? '' : null);
    put(idKey, s.id);
    put('tab', s.id && s.tab && s.tab !== tabs[0] ? s.tab : null);
    return p;
  };
  const key = params.toString();
  // eslint-disable-next-line react-hooks/exhaustive-deps -- 쿼리 문자열이 같으면 같은 상태
  const st = useMemo(() => read(params), [key]);

  // 상태 일부를 바꾼다 — 늘 지금 주소 위에서(같은 틱에 두 번 불려도 앞의 것을 잃지 않게 함수형)
  const optsRef = { read, build };
  const write = useCallback(
    (fn: (s: ListState<F>) => ListState<F>) => setParams((prev) => optsRef.build(prev, fn(optsRef.read(prev))), { replace: true }),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- read · build 는 옵션 값만 쓴다
    [setParams, key],
  );

  // 틀린 값 정리 · 다른 화면 링크의 state.filters 를 주소로
  const incoming = (loc.state as NavState | null)?.filters;
  useEffect(() => {
    const cur = new URLSearchParams(loc.search);
    let s = read(cur);
    if (incoming && typeof incoming === 'object') {
      const filters = { ...o.filters };
      for (const k of fkeys) {
        const v = incoming[k];
        if (typeof v === 'string' && v.length <= MAX_VALUE && (v === '' || (o.validate?.[k]?.(v) ?? true))) (filters as Record<string, string>)[k] = v;
      }
      s = { ...s, filters, page: 1 };
    }
    const next = build(cur, s).toString();
    if (next === cur.toString() && !incoming) return;
    const rest = { ...((loc.state as Record<string, unknown> | null) ?? {}) };
    delete rest.filters;
    navigate({ pathname: loc.pathname, search: next ? `?${next}` : '', hash: loc.hash }, { replace: true, state: Object.keys(rest).length ? rest : null });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- 주소가 바뀔 때만 다시 본다
  }, [loc.key, loc.search]);

  const setFilters = useCallback((patch: Partial<F>) => write((s) => ({ ...s, filters: { ...s.filters, ...patch }, page: 1 })), [write]);
  const clearFilters = useCallback(() => write((s) => ({ ...s, filters: { ...o.filters }, page: 1 })), [write, o.filters]);
  const setPage = useCallback((page: number) => write((s) => ({ ...s, page: Math.max(1, Math.floor(page)) })), [write]);
  const setSize = useCallback((size: number) => write((s) => ({ ...s, size, page: 1 })), [write]);
  const setSort = useCallback((sort: SortState) => write((s) => ({ ...s, sort, page: 1 })), [write]);
  const sortBy = useCallback(
    (k: string) => write((s) => ({ ...s, page: 1, sort: s.sort.key === k ? { key: k, dir: s.sort.dir === 'asc' ? 'desc' : 'asc' } : { key: k, dir: 'asc' } })),
    [write],
  );
  // 상세 열기 — 이미 열려 있으면(앞뒤 넘김) 지금 탭을 그대로, 새로 열면 첫 탭
  const open = useCallback((id: string, tab?: string) => write((s) => ({ ...s, id, tab: tab ?? (s.id ? s.tab : (tabs[0] ?? null)) })), [write, tabs]);
  const close = useCallback(() => write((s) => ({ ...s, id: null, tab: tabs[0] ?? null })), [write, tabs]);
  const setTab = useCallback((tab: string) => write((s) => ({ ...s, tab })), [write]);
  const active = fkeys.some((k) => st.filters[k] !== o.filters[k]);
  const table: TableQuery = useMemo(() => ({ sort: st.sort, setSort, page: st.page, setPage, size: st.size, setSize }), [st.sort, setSort, st.page, setPage, st.size, setSize]);

  return { ...st, active, setFilters, clearFilters, setPage, setSize, setSort, sortBy, open, close, setTab, table };
}
export type ListQuery<F extends Record<string, string>> = ReturnType<typeof useListQuery<F>>;
