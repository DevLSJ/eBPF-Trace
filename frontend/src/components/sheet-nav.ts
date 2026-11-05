// 상세 패널 이전/다음(11/05): 보이는 목록(ids)에서 cur 의 앞뒤
export type SheetNav = { pos: number; total: number; prev: (() => void) | null; next: (() => void) | null };

export function sheetNav<T>(ids: T[], cur: T, go: (id: T) => void): SheetNav | undefined {
  const pos = ids.indexOf(cur);
  if (pos < 0) return undefined;
  return { pos, total: ids.length, prev: pos > 0 ? () => go(ids[pos - 1]) : null, next: pos < ids.length - 1 ? () => go(ids[pos + 1]) : null };
}
