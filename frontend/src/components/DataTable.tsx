import type { ReactNode } from 'react';
import { PAGE_SIZES, type Column, type SortState } from '../hooks/useTableKit';
import { fmtNum } from '../lib/format';

// 표 기반(11/04e 목업 U.tableKit, R1 11/04) — 표 화면 적용은 R4. 여기에는 바탕만:
//   useTableKit  머리 클릭(키보드 Enter) 정렬(오름 → 내림) · 쪽 나누기(페이지당 20 · 50 · 100) · ?id= 로 들어온 행이 있는 쪽(reveal)
//   SortHead     <thead> — 머리 sticky 12/700, 정렬되는 칸은 버튼 + 화살표 + aria-sort
//   TablePager   아래 쪽 번호 바닥줄 「1–20 / 45 · 페이지당 20▾ · ‹ 1 2 3 … 9 ›」(채움 칸 밖에 둔다). total 을 모르면(옛 응답) 이전/다음만
//   BusyBar      재조회 때 머리 위 2px 진행 띠(이전 행은 그대로 둔다)
//   StatusPill   상태 배지 — 11.5/700 + 글자색 1px 테두리 · 옅은 배경
// 행 46(.sg-table td) · 줄 선 --line-soft · 숫자 칸 오른쪽(num) · 긴 글 칸 하나만 남는 폭 + 말줄임(fill) · 짧은 칸은 내용 폭(short)
export function SortHead<T>({ columns, sort, onSort }: { columns: Column<T>[]; sort: SortState; onSort: (key: string) => void }) {
  return (
    <thead className="sg-thead">
      <tr>
        {columns.map((c) => (
          <th
            key={c.key}
            scope="col"
            data-col={c.key}
            className={`${c.num ? 'num-col ' : ''}${c.short ? 'tk-short' : ''}`.trim() || undefined}
            aria-sort={c.sort ? (sort.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none') : undefined}
          >
            {c.sort ? (
              <button type="button" className="th-sort" onClick={() => onSort(c.key)}>
                {c.label}
              </button>
            ) : (
              c.label
            )}
          </th>
        ))}
      </tr>
    </thead>
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
  const btn = (label: string, p: number, o: { key?: string; aria?: string; cur?: boolean; disabled?: boolean } = {}) => (
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
          {known ? (total ? `${fmtNum(from)}–${fmtNum(to)} / ${fmtNum(total)}` : '0건') : `${fmtNum(from)}–${fmtNum(to)}`}
        </span>
        <span className="tk-dot" aria-hidden>
          ·
        </span>
        <label className="tk-size-label">
          페이지당{' '}
          <select className="tk-size" data-part="page-size" aria-label="페이지당 행 수" value={size} onChange={(e) => onSize(Number(e.target.value))}>
            {PAGE_SIZES.map((x) => (
              <option key={x} value={x}>
                {x}
              </option>
            ))}
          </select>
        </label>
        <nav className="tk-pages" aria-label="쪽">
          {known
            ? total
              ? [
                  btn('‹', page - 1, { key: 'prev', aria: '이전 쪽', disabled: page <= 1 }),
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
                  btn('›', page + 1, { key: 'next', aria: '다음 쪽', disabled: page >= n }),
                ]
              : null
            : [btn('‹ 이전', page - 1, { key: 'prev', aria: '이전 쪽', disabled: !hasPrev }), btn('다음 ›', page + 1, { key: 'next', aria: '다음 쪽', disabled: !hasNext })]}
        </nav>
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

export type PillTone = 'neutral' | 'accent' | 'info' | 'ok' | 'warn' | 'danger';
export function StatusPill({ tone = 'neutral', children, ...rest }: { tone?: PillTone; children: ReactNode } & Record<`data-${string}`, string | undefined>) {
  return (
    <span className={`sg-pill sg-pill-${tone}`} {...rest}>
      {children}
    </span>
  );
}
