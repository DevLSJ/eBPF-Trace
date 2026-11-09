import { useCallback, useMemo, useState, type ReactNode } from 'react';

// 표 기반(11/04e 목업 U.tableKit, R1 11/04) — 정렬 · 쪽 나누기 상태. 머리 · 바닥줄 부품은 components/DataTable.tsx
// 11/09 표 도구(선택): grid 를 주면 칸 보이기 · 폭 · 순서를 이 브라우저(localStorage `supplyguard.grid.<id>.v1`)에 기억하고,
//   query 를 주면 정렬 · 쪽 · 쪽 크기를 이 훅 안 대신 그쪽(hooks/useListQuery.ts 의 화면 상태 — 10/21 주소에 남기지 않음)에서 읽고 쓴다.
export interface Column<T> {
  key: string;
  label: ReactNode;
  // 정렬 값(없으면 정렬 안 하는 칸)
  sort?: (row: T) => string | number | null | undefined;
  num?: boolean;
  fill?: boolean;
  short?: boolean;
  // ── 11/09 표 도구(grid 를 줄 때만 쓰인다) ──
  // 칸 고르기 · CSV 머리 이름. 없으면 label 이 글자일 때 그 글자. 이름 없는 칸(체크 칸 · 행 동작 칸)은 늘 보이고 고르기 · 옮기기 · 폭 끌기에서 빠진다
  name?: string;
  // 처음에 숨김(칸 고르기로 켠다)
  hidden?: boolean;
  // 이름이 있어도 늘 보이고 제자리 · 폭 고정
  fixed?: boolean;
  // 기본 폭(px). 없으면 내용 폭
  width?: number;
  // 끌기 범위(기본 48 ~ 900)
  minWidth?: number;
  maxWidth?: number;
  // <GridCells> 로 그릴 때 칸 내용 · <td> class. 이름 있는 칸의 빈 값(null · undefined · '' · false)은 「—」
  cell?: (row: T) => ReactNode;
  cellClass?: string;
  // CSV 값 — 「화면 글 그대로」(11/09 G13): 없으면 cell 이 글자 · 숫자일 때 그 값, 아니면 sort 값. 빈 값은 「—」
  csv?: (row: T) => string | number | null | undefined;
  // 'end' = 줄 끝 조작 칸을 오른쪽에 고정(가로 스크롤이 남았을 때만 왼쪽 그림자 — <TableScroll>)
  stick?: 'end';
}
// 칸 폭 표준(11/09 SPEC-1109 §4 · 참고 제품 G15 권고, px) — 남는 폭은 설명 한 칸(fill)이 갖는다
export const COL_W = { time: 160, user: 110, status: 120, id: 120, num: 80 } as const;
export interface SortState {
  key: string | null;
  dir: 'asc' | 'desc';
}
export const PAGE_SIZES = [20, 50, 100];
export const COL_MIN = 48;
export const COL_MAX = 900;
export const COL_STEP = 16;
// 빈 값 글자(화면 · CSV 같음) — components/list/cells.tsx 의 DASH 와 같은 값
export const EMPTY_TEXT = '—';

// 정렬 · 쪽 상태를 바깥(목록 화면 상태)에 둘 때 — useListQuery(...).table 이 이 모양
export interface TableQuery {
  sort: SortState;
  setSort: (s: SortState) => void;
  page: number;
  setPage: (p: number) => void;
  size: number;
  setSize: (n: number) => void;
}

const cmp = (a: unknown, b: unknown) => {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  return typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b), 'ko', { numeric: true });
};

// ── 칸 설정 저장(11/09) ──
export const gridStorageKey = (id: string) => `supplyguard.grid.${id}.v1`;
interface Saved {
  vis: Record<string, boolean>;
  w: Record<string, number>;
  order: string[];
}
const EMPTY: Saved = { vis: {}, w: {}, order: [] };
// 저장본을 읽는다 — 읽기 실패 · 깨진 JSON · 모양이 다르면 빈 설정(기본값). 없는 칸 키는 버린다
function readSaved(id: string | undefined, keys: Set<string>): Saved {
  if (!id) return EMPTY;
  let raw: unknown;
  try {
    const v = localStorage.getItem(gridStorageKey(id));
    if (v === null) return EMPTY;
    raw = JSON.parse(v);
  } catch {
    return EMPTY;
  }
  if (!raw || typeof raw !== 'object') return EMPTY;
  const r = raw as Partial<Record<keyof Saved, unknown>>;
  const vis: Record<string, boolean> = {};
  const w: Record<string, number> = {};
  if (r.vis && typeof r.vis === 'object') for (const [k, v] of Object.entries(r.vis)) if (keys.has(k) && typeof v === 'boolean') vis[k] = v;
  if (r.w && typeof r.w === 'object') for (const [k, v] of Object.entries(r.w)) if (keys.has(k) && typeof v === 'number' && Number.isFinite(v)) w[k] = v;
  const order = Array.isArray(r.order) ? [...new Set(r.order.filter((k): k is string => typeof k === 'string' && keys.has(k)))] : [];
  return { vis, w, order };
}
function writeSaved(id: string | undefined, s: Saved | null) {
  if (!id) return;
  try {
    if (s === null) localStorage.removeItem(gridStorageKey(id));
    else localStorage.setItem(gridStorageKey(id), JSON.stringify(s));
  } catch {
    /* 저장 차단(사생활 보호 창 등) — 이번 화면에서만 적용 */
  }
}

// 칸 이름(고르기 · CSV) — 이름 없는 칸은 null
export const colName = <T,>(c: Column<T>): string | null => c.name ?? (typeof c.label === 'string' && c.label.trim() ? c.label : null);
// 숨기기 · 옮기기 · 폭 끌기 대상
export const colMovable = <T,>(c: Column<T>) => !c.fixed && colName(c) !== null;
const clampW = <T,>(c: Column<T>, px: number) => Math.round(Math.min(c.maxWidth ?? COL_MAX, Math.max(c.minWidth ?? COL_MIN, px)));

// 저장된 순서 + 새로 생긴 칸(기본 순서의 바로 앞 칸 뒤에) → 고정 칸은 제자리, 옮길 수 있는 칸 자리만 채운다
function arrange<T>(columns: Column<T>[], saved: string[]): Column<T>[] {
  const movable = columns.filter(colMovable);
  const keys = movable.map((c) => c.key);
  const out = saved.filter((k) => keys.includes(k));
  keys.forEach((k, i) => {
    if (out.includes(k)) return;
    const prev = keys.slice(0, i).reverse().find((p) => out.includes(p));
    out.splice(prev ? out.indexOf(prev) + 1 : 0, 0, k);
  });
  const byKey = new Map(movable.map((c) => [c.key, c]));
  let j = 0;
  return columns.map((c) => (colMovable(c) ? byKey.get(out[j++])! : c));
}

export function useTableKit<T>({
  columns,
  sort,
  size = 20,
  grid,
  query,
}: {
  columns: Column<T>[];
  sort?: SortState;
  size?: number;
  // 칸 설정 저장 키(표마다 하나, 예: 'policies' → supplyguard.grid.policies.v1). 없으면 기억하지 않고 기본 칸만
  grid?: string;
  // 정렬 · 쪽을 바깥 상태(useListQuery 의 화면 상태)로
  query?: TableQuery;
}) {
  const [stOwn, setStOwn] = useState<SortState>(sort ?? { key: null, dir: 'asc' });
  const [pageOwn, setPageOwn] = useState(1);
  const [perOwn, setPerOwn] = useState(size);
  const st = query ? query.sort : stOwn;
  const page = query ? query.page : pageOwn;
  const per = query ? query.size : perOwn;
  const qSetSort = query?.setSort;
  const qSetPage = query?.setPage;
  const qSetSize = query?.setSize;
  const setPage = useCallback((p: number) => (qSetPage ? qSetPage(p) : setPageOwn(p)), [qSetPage]);
  const setSize = useCallback((n: number) => (qSetSize ? qSetSize(n) : (setPerOwn(n), setPageOwn(1))), [qSetSize]);
  const sortBy = useCallback(
    (key: string) => {
      const next: SortState = st.key === key ? { key, dir: st.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' };
      if (qSetSort) return qSetSort(next); // 바깥 상태는 정렬이 바뀌면 첫 쪽으로 스스로 돌아간다
      setStOwn(next);
      setPageOwn(1);
    },
    [st, qSetSort],
  );
  const sorted = useCallback(
    (list: T[]) => {
      const c = columns.find((x) => x.key === st.key);
      if (!c?.sort) return list.slice();
      const get = c.sort;
      return list
        .map((r, i) => [get(r), i, r] as const)
        .sort((x, y) => (st.dir === 'asc' ? cmp(x[0], y[0]) : -cmp(x[0], y[0])) || x[1] - y[1])
        .map((x) => x[2]);
    },
    [columns, st],
  );
  // 클라이언트 목록: 정렬 → 지금 쪽만
  const view = useCallback(
    (list: T[]) => {
      const all = sorted(list);
      const pages = Math.max(1, Math.ceil(all.length / per));
      const p = Math.min(page, pages);
      const a = (p - 1) * per;
      const rows = all.slice(a, a + per);
      return { rows, total: all.length, page: p, pages, from: all.length ? a + 1 : 0, to: a + rows.length };
    },
    [sorted, page, per],
  );
  // 고른 행이 보이는 쪽으로(주소 ?id= 로 들어온 경우)
  const reveal = useCallback(
    (list: T[], pred: (r: T) => boolean) => {
      const i = sorted(list).findIndex(pred);
      if (i >= 0) setPage(Math.floor(i / per) + 1);
    },
    [sorted, per, setPage],
  );

  // ── 칸 보이기 · 폭 · 순서(11/09) ──
  const [saved, setSaved] = useState<Saved>(() => readSaved(grid, new Set(columns.map((c) => c.key))));
  // 바뀔 때마다 저장(쓰기 실패는 이번 화면에서만 적용) — 끌기 중 연달아 불려도 앞 값 위에 쌓이게 함수형으로
  const update = useCallback(
    (fn: (s: Saved) => Saved | null) =>
      setSaved((prev) => {
        const next = fn(prev);
        if (next === prev) return prev;
        writeSaved(grid, next);
        return next ?? EMPTY;
      }),
    [grid],
  );
  const ordered = useMemo(() => arrange(columns, saved.order), [columns, saved.order]);
  const isVisible = useCallback((c: Column<T>, s: Saved = saved) => !colMovable(c) || (s.vis[c.key] ?? !c.hidden), [saved]);
  const cols = useMemo(() => ordered.filter((c) => isVisible(c)), [ordered, isVisible]);
  const width = useCallback(
    (key: string): number | undefined => {
      const c = columns.find((x) => x.key === key);
      if (!c) return undefined;
      const w = colMovable(c) ? saved.w[key] : undefined;
      return w !== undefined ? clampW(c, w) : c.width;
    },
    [columns, saved.w],
  );
  // 칸 고르기 목록 — 이름 있고 고정이 아닌 칸만, 지금 순서
  const picks = useMemo(() => ordered.filter(colMovable).map((c) => ({ key: c.key, name: colName(c)!, visible: isVisible(c) })), [ordered, isVisible]);
  const setVisible = useCallback(
    (key: string, on: boolean) => {
      const c = columns.find((x) => x.key === key);
      if (!c || !colMovable(c)) return;
      update((s) => {
        // 마지막 하나 남은 칸은 끌 수 없다
        if (!on && columns.filter((x) => colMovable(x) && isVisible(x, s)).length <= 1) return s;
        return { ...s, vis: { ...s.vis, [key]: on } };
      });
    },
    [columns, isVisible, update],
  );
  const setWidth = useCallback(
    (key: string, px: number | null) => {
      const c = columns.find((x) => x.key === key);
      if (!c || !colMovable(c)) return;
      update((s) => {
        const w = { ...s.w };
        if (px === null) delete w[key];
        else w[key] = clampW(c, px);
        return { ...s, w };
      });
    },
    [columns, update],
  );
  // 옮길 수 있는 칸 사이의 순서를 바꾼다 — to 번째 자리로 · 다른 칸의 앞(before) · 뒤(after)로
  const reorder = useCallback(
    (key: string, place: (keys: string[]) => number) =>
      update((s) => {
        const keys = arrange(columns, s.order).filter(colMovable).map((c) => c.key);
        const from = keys.indexOf(key);
        if (from < 0) return s;
        keys.splice(from, 1);
        const at = Math.max(0, Math.min(keys.length, place(keys)));
        keys.splice(at, 0, key);
        return { ...s, order: keys };
      }),
    [columns, update],
  );
  const move = useCallback((key: string, to: number) => reorder(key, () => to), [reorder]);
  const moveTo = useCallback(
    (key: string, target: string, side: 'before' | 'after') => reorder(key, (keys) => (keys.includes(target) ? keys.indexOf(target) + (side === 'after' ? 1 : 0) : keys.length)),
    [reorder],
  );
  // 보이는 칸 기준 한 칸 왼쪽(-1) · 오른쪽(+1) — 키보드 Alt+←/→. 옮겼으면 true
  const moveBy = useCallback(
    (key: string, delta: -1 | 1) => {
      const vis = cols.filter(colMovable).map((c) => c.key);
      const i = vis.indexOf(key);
      const target = vis[i + delta];
      if (i < 0 || !target) return false;
      moveTo(key, target, delta > 0 ? 'after' : 'before');
      return true;
    },
    [cols, moveTo],
  );
  const isDefault = !Object.keys(saved.vis).length && !Object.keys(saved.w).length && !saved.order.length;
  // 「칸 기본으로」 — 보이기 · 폭 · 순서를 모두 기본값으로(저장본을 지운다)
  const resetColumns = useCallback(() => update(() => null), [update]);
  // CSV(머리 + 행) — 지금 보이는 이름 있는 칸 · 지금 순서 · 화면 글 그대로(빈 값 「—」), 행은 정렬만(쪽 나누기 없음)
  const csv = useCallback(
    (list: T[]) => {
      const out = cols.filter((c) => colName(c) !== null);
      const text = (c: Column<T>, r: T): string | number => {
        let v: unknown;
        if (c.csv) v = c.csv(r);
        else {
          const shown = c.cell?.(r);
          v = typeof shown === 'string' || typeof shown === 'number' ? shown : c.cell && (shown === null || shown === undefined || shown === '' || shown === false) ? null : c.sort?.(r);
        }
        return v === null || v === undefined || v === '' ? EMPTY_TEXT : (v as string | number);
      };
      return [out.map((c) => colName(c)!), ...sorted(list).map((r) => out.map((c) => text(c, r)))];
    },
    [cols, sorted],
  );

  return useMemo(
    () => ({
      sort: st,
      sortBy,
      page,
      setPage,
      size: per,
      setSize,
      sorted,
      view,
      reveal,
      // 11/09 표 도구
      grid,
      cols,
      picks,
      width,
      setVisible,
      setWidth,
      move,
      moveTo,
      moveBy,
      resetColumns,
      isDefault,
      csv,
    }),
    [st, sortBy, page, setPage, per, setSize, sorted, view, reveal, grid, cols, picks, width, setVisible, setWidth, move, moveTo, moveBy, resetColumns, isDefault, csv],
  );
}
export type TableKit<T> = ReturnType<typeof useTableKit<T>>;
