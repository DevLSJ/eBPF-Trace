import { useCallback, useMemo, useState, type ReactNode } from 'react';

// 표 기반(11/04e 목업 U.tableKit, R1 11/04) — 정렬 · 쪽 나누기 상태. 머리 · 바닥줄 부품은 components/DataTable.tsx
export interface Column<T> {
  key: string;
  label: ReactNode;
  // 정렬 값(없으면 정렬 안 하는 칸)
  sort?: (row: T) => string | number | null | undefined;
  num?: boolean;
  fill?: boolean;
  short?: boolean;
}
export interface SortState {
  key: string | null;
  dir: 'asc' | 'desc';
}
export const PAGE_SIZES = [20, 50, 100];

const cmp = (a: unknown, b: unknown) => {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  return typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b), 'ko', { numeric: true });
};

export function useTableKit<T>({ columns, sort, size = 20 }: { columns: Column<T>[]; sort?: SortState; size?: number }) {
  const [st, setSt] = useState<SortState>(sort ?? { key: null, dir: 'asc' });
  const [page, setPage] = useState(1);
  const [per, setPer] = useState(size);
  const sortBy = useCallback((key: string) => {
    setSt((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
    setPage(1);
  }, []);
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
    [sorted, per],
  );
  return useMemo(
    () => ({ sort: st, sortBy, page, setPage, size: per, setSize: (n: number) => (setPer(n), setPage(1)), sorted, view, reveal }),
    [st, sortBy, page, per, sorted, view, reveal],
  );
}

