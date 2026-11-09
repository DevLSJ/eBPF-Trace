import { ChevronDown, ChevronFirst, ChevronLast, ChevronLeft, ChevronRight, ChevronUp, ChevronsUpDown } from 'lucide-react';
import { useRef, useState, type KeyboardEvent as RKeyboardEvent, type PointerEvent as RPointerEvent, type ReactNode } from 'react';
import { COL_MAX, COL_MIN, COL_STEP, colMovable, colName, PAGE_SIZES, type Column, type SortState, type TableKit } from '../hooks/useTableKit';
import { fmtNum } from '../lib/format';
import { announce } from './popover';
import './table-kit.css';

// 표 기반(11/04e 목업 U.tableKit, R1 11/04) — 표 화면 적용은 R4. 여기에는 바탕만:
//   useTableKit  머리 클릭(키보드 Enter) 정렬(오름 → 내림) · 쪽 나누기(페이지당 20 · 50 · 100) · ?id= 로 들어온 행이 있는 쪽(reveal)
//   SortHead     <thead> — 머리 sticky 42 · 회색 바탕 · 12/600, 정렬되는 칸은 버튼 + 꺾쇠(11/09: 늘 보임 · 정렬 중인 칸만 주 색) + aria-sort
//                kit 을 주면(11/09) 보이는 칸 · 순서 · 폭을 kit 에서 읽고, 머리 경계 끌기(폭) · 머리 끌기(순서)를 켠다
//   GridCells    kit.cols 순서대로 <td> (Column.cell · cellClass · 폭)
//   TablePager   아래 쪽 넘김(참고 대시보드, 11/05) 「총 45건 · 1/3 페이지」 ··· 「20개씩▾ |‹ ‹ 1 2 3 › ›|」(채움 칸 밖에 둔다). total 을 모르면(옛 응답) 「1–20 · 1 페이지」 + 이전/다음만
//   BusyBar      재조회 때 머리 위 2px 진행 띠(이전 행은 그대로 둔다)
//   StatusPill   상태 배지 — 27 · 12.5/750 · 톤 테두리 · 옅은 배경(참고 대시보드)
// 행 48(.sg-table td) · 줄 선 --line-soft · 숫자 칸 오른쪽(num) · 긴 글 칸 하나만 남는 폭 + 말줄임(fill) · 짧은 칸은 내용 폭(short)
// 칸 폭 · 순서 조작(kit 이 있을 때, 이름 있고 고정이 아닌 칸만):
//   폭  머리 오른쪽 경계(role=separator)를 끈다 · 초점 두고 ←/→(Alt+←/→ 도) ±16 · 두 번 누르기 · Enter = 기본 폭. 범위는 칸의 minWidth~maxWidth(기본 48~900)
//   순서 머리를 끌어 다른 칸의 왼쪽/오른쪽 반에 놓는다 · 머리 단추에 초점 두고 Alt+←/→ 한 칸. 고정 칸(체크 · 행 동작)은 제자리
type Dir = 'asc' | 'desc' | 'none';
const dirOf = (sort: SortState, key: string): Dir => (sort.key === key ? sort.dir : 'none');
function SortIco({ dir }: { dir: Dir }) {
  const I = dir === 'asc' ? ChevronUp : dir === 'desc' ? ChevronDown : ChevronsUpDown;
  return (
    <span className="th-sort-ico" data-part="sort-ico" data-dir={dir} aria-hidden>
      <I />
    </span>
  );
}
const cellClass = <T,>(c: Column<T>, sized: boolean, extra?: string) =>
  [c.num && 'num-col', c.fill && 'tk-fill', c.short && 'tk-short', sized && 'tk-sized', extra].filter(Boolean).join(' ') || undefined;
const sizeStyle = (w: number | undefined) => (w === undefined ? undefined : { width: w, minWidth: w, maxWidth: w });

export function SortHead<T>({ columns, sort, onSort, kit }: { columns?: Column<T>[]; sort?: SortState; onSort?: (key: string) => void; kit?: TableKit<T> }) {
  const cols = kit ? kit.cols : (columns ?? []);
  const st = kit ? kit.sort : (sort ?? { key: null, dir: 'asc' });
  const on = kit ? kit.sortBy : (onSort ?? (() => {}));
  const head = useRef<HTMLTableSectionElement>(null);
  const [drop, setDrop] = useState<{ key: string; side: 'before' | 'after' } | null>(null);
  const suppress = useRef(false);

  // 머리 끌어 순서 바꾸기 — 6px 넘게 움직여야 끌기(그 전에 떼면 정렬 클릭 그대로)
  const startMove = (e: RPointerEvent<HTMLElement>, key: string) => {
    if (!kit || e.button !== 0 || (e.target as HTMLElement).closest('[data-part="col-resize"]')) return;
    const x0 = e.clientX;
    let dragging = false;
    let hit: { key: string; side: 'before' | 'after' } | null = null;
    const move = (ev: PointerEvent) => {
      if (!dragging) {
        if (Math.abs(ev.clientX - x0) < 6) return;
        dragging = true;
        document.body.classList.add('tk-dragging');
      }
      ev.preventDefault();
      hit = null;
      for (const th of head.current?.querySelectorAll<HTMLElement>('th.tk-movable') ?? []) {
        const r = th.getBoundingClientRect();
        if (ev.clientX < r.left || ev.clientX >= r.right) continue;
        const k = th.dataset.col!;
        if (k !== key) hit = { key: k, side: ev.clientX < r.left + r.width / 2 ? 'before' : 'after' };
        break;
      }
      setDrop(hit);
    };
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
      document.body.classList.remove('tk-dragging');
      setDrop(null);
      if (!dragging) return;
      // 같은 단추 위에서 떼면 click 이 뒤따른다 — 정렬로 읽지 않게 이번 한 번만 삼킨다
      suppress.current = true;
      window.setTimeout(() => (suppress.current = false), 0);
      if (hit) {
        kit.moveTo(key, hit.key, hit.side);
        announce(`${nameOf(key)} 칸을 옮김`);
      }
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    window.addEventListener('pointercancel', up);
  };
  const nameOf = (key: string) => {
    const c = cols.find((x) => x.key === key);
    return (c && colName(c)) ?? key;
  };
  const keyMove = (key: string) => (e: RKeyboardEvent<HTMLElement>) => {
    if (!kit || !e.altKey || (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight')) return;
    e.preventDefault();
    e.stopPropagation();
    if (!kit.moveBy(key, e.key === 'ArrowLeft' ? -1 : 1)) return;
    announce(`${nameOf(key)} 칸을 ${e.key === 'ArrowLeft' ? '왼쪽' : '오른쪽'}으로 옮김`);
    // 옮긴 머리가 다시 그려진 뒤에도 초점이 그 칸에 남게
    requestAnimationFrame(() => head.current?.querySelector<HTMLElement>(`th[data-col="${key}"] [data-part="th-handle"]`)?.focus());
  };
  // 머리 경계 끌어 폭 바꾸기
  const startResize = (e: RPointerEvent<HTMLElement>, c: Column<T>) => {
    if (!kit || e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    const el = e.currentTarget;
    const start = el.closest('th')!.getBoundingClientRect().width;
    const x0 = e.clientX;
    el.setPointerCapture?.(e.pointerId);
    document.body.classList.add('tk-resizing');
    const move = (ev: PointerEvent) => kit.setWidth(c.key, start + ev.clientX - x0);
    const up = () => {
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerup', up);
      el.removeEventListener('pointercancel', up);
      document.body.classList.remove('tk-resizing');
    };
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerup', up);
    el.addEventListener('pointercancel', up);
  };
  const keyResize = (c: Column<T>) => (e: RKeyboardEvent<HTMLElement>) => {
    if (!kit) return;
    if (e.key === 'Enter') {
      e.preventDefault();
      return kit.setWidth(c.key, null);
    }
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault();
    e.stopPropagation();
    const cur = kit.width(c.key) ?? e.currentTarget.closest('th')!.getBoundingClientRect().width;
    kit.setWidth(c.key, cur + (e.key === 'ArrowRight' ? COL_STEP : -COL_STEP));
  };

  return (
    <thead className="sg-thead" ref={head}>
      <tr>
        {cols.map((c) => {
          const movable = !!kit && colMovable(c);
          const w = kit?.width(c.key);
          const dir = dirOf(st, c.key);
          const help = movable ? 'Alt+←/→ 로 칸 순서 바꾸기' : undefined;
          return (
            <th
              key={c.key}
              scope="col"
              data-col={c.key}
              data-drop={drop?.key === c.key ? drop.side : undefined}
              className={[c.num && 'num-col', c.short && 'tk-short', w !== undefined && 'tk-sized', movable && 'tk-movable'].filter(Boolean).join(' ') || undefined}
              style={sizeStyle(w)}
              aria-sort={c.sort ? (dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none') : undefined}
              onPointerDown={movable ? (e) => startMove(e, c.key) : undefined}
            >
              {c.sort ? (
                <button
                  type="button"
                  className="th-sort"
                  data-ico=""
                  data-part={movable ? 'th-handle' : undefined}
                  title={help}
                  onClick={() => {
                    if (suppress.current) return;
                    on(c.key);
                  }}
                  onKeyDown={movable ? keyMove(c.key) : undefined}
                >
                  <span className="th-text">{c.label}</span>
                  <SortIco dir={dir} />
                </button>
              ) : movable ? (
                <span className="th-label" tabIndex={0} data-part="th-handle" title={help} onKeyDown={keyMove(c.key)}>
                  {c.label}
                </span>
              ) : (
                c.label
              )}
              {movable && (
                <span
                  role="separator"
                  aria-orientation="vertical"
                  aria-label={`${nameOf(c.key)} 칸 폭`}
                  aria-valuenow={w}
                  aria-valuemin={c.minWidth ?? COL_MIN}
                  aria-valuemax={c.maxWidth ?? COL_MAX}
                  tabIndex={0}
                  title="끌어서 폭 바꾸기 · 두 번 누르면 기본 폭"
                  data-part="col-resize"
                  className="tk-resize"
                  onPointerDown={(e) => startResize(e, c)}
                  onDoubleClick={() => kit!.setWidth(c.key, null)}
                  onKeyDown={keyResize(c)}
                  onClick={(e) => e.stopPropagation()}
                />
              )}
            </th>
          );
        })}
      </tr>
    </thead>
  );
}

// kit.cols 순서 · 폭 그대로 행의 칸을 그린다(Column.cell 이 없으면 빈 칸)
export function GridCells<T>({ kit, row }: { kit: TableKit<T>; row: T }) {
  return (
    <>
      {kit.cols.map((c) => {
        const w = kit.width(c.key);
        return (
          <td key={c.key} data-col={c.key} className={cellClass(c, w !== undefined, c.cellClass)} style={sizeStyle(w)}>
            {c.cell?.(row)}
          </td>
        );
      })}
    </>
  );
}

// 쪽 번호: 1 · 지금 ±1 · 끝, 사이는 「…」
function pageNums(p: number, n: number) {
  const out: number[] = [];
  for (const x of [1, p - 1, p, p + 1, n]) if (x >= 1 && x <= n && !out.includes(x)) out.push(x);
  return out.sort((a, b) => a - b);
}

export function TablePager({
  name,
  total,
  from,
  to,
  page,
  size,
  onPage,
  onSize,
  hasPrev,
  hasNext,
}: {
  name: string;
  // 모르면(옛 응답) null — 이전/다음만
  total: number | null;
  from: number;
  to: number;
  page: number;
  size: number;
  onPage: (p: number) => void;
  onSize: (n: number) => void;
  hasPrev?: boolean;
  hasNext?: boolean;
}) {
  const known = total != null;
  const n = known ? Math.max(1, Math.ceil(total / size)) : 0;
  const btn = (label: ReactNode, p: number, o: { key?: string; aria?: string; cur?: boolean; disabled?: boolean } = {}) => (
    <button
      key={o.key ?? String(p)}
      type="button"
      className={`tk-page${o.cur ? ' on' : ''}`}
      data-page={o.key ?? String(p)}
      aria-current={o.cur ? 'page' : undefined}
      aria-label={o.aria ?? `${p}쪽`}
      disabled={o.disabled}
      onClick={() => onPage(p)}
    >
      {label}
    </button>
  );
  return (
    <div className="tk-foot" data-table-foot={name}>
      <div className="tk-pager" data-part="pager">
        <span className="num" data-part="range">
          {known ? `총 ${fmtNum(total)}건 · ${page}/${n} 페이지` : `${fmtNum(from)}–${fmtNum(to)} · ${page} 페이지`}
        </span>
        <div className="tk-pager-right">
          <select className="tk-size" data-part="page-size" aria-label="페이지당 행 수" value={size} onChange={(e) => onSize(Number(e.target.value))}>
            {PAGE_SIZES.map((x) => (
              <option key={x} value={x}>
                {x}개씩
              </option>
            ))}
          </select>
          <nav className="tk-pages" aria-label="쪽">
            {known
              ? [
                  btn(<ChevronFirst aria-hidden />, 1, { key: 'first', aria: '첫 쪽', disabled: page <= 1 }),
                  btn(<ChevronLeft aria-hidden />, page - 1, { key: 'prev', aria: '이전 쪽', disabled: page <= 1 }),
                  ...pageNums(page, n).flatMap((x, i, a) => [
                    ...(i && x - a[i - 1] > 1
                      ? [
                          <span key={`gap${x}`} className="tk-gap" aria-hidden>
                            …
                          </span>,
                        ]
                      : []),
                    btn(String(x), x, { cur: x === page }),
                  ]),
                  btn(<ChevronRight aria-hidden />, page + 1, { key: 'next', aria: '다음 쪽', disabled: page >= n }),
                  btn(<ChevronLast aria-hidden />, n, { key: 'last', aria: '끝 쪽', disabled: page >= n }),
                ]
              : [
                  btn(<ChevronLeft aria-hidden />, page - 1, { key: 'prev', aria: '이전 쪽', disabled: !hasPrev }),
                  btn(<ChevronRight aria-hidden />, page + 1, { key: 'next', aria: '다음 쪽', disabled: !hasNext }),
                ]}
          </nav>
        </div>
      </div>
    </div>
  );
}

export function BusyBar({ on }: { on: boolean }) {
  return (
    <div className="tk-busy" data-part="busy" hidden={!on} aria-hidden>
      <i />
    </div>
  );
}

export type PillTone = 'neutral' | 'accent' | 'info' | 'ok' | 'warn' | 'danger' | 'dark';
export function StatusPill({ tone = 'neutral', children, ...rest }: { tone?: PillTone; children: ReactNode } & Record<`data-${string}`, string | undefined>) {
  return (
    <span className={`sg-pill sg-pill-${tone}`} {...rest}>
      {children}
    </span>
  );
}
