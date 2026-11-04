import { useEffect, useLayoutEffect, useRef, useState, type MouseEvent, type ReactNode, type RefObject } from 'react';
import { fmtNum, fmtTime } from '../lib/format';
import { reducedMotion } from '../lib/motion';

// SVG 차트 부품(11/04e 목업 U.lineChart · U.stackBars · U.donut, R1 11/04) — 의존성 없이 직접 그린다(Recharts 없음). 대시보드 적용은 R2.
// 공통: 점선 가로 격자만 · y축 선 없음 · 축 글자 12 보조색 · 반전(ink) 툴팁 · 첫 렌더(데이터가 처음 들어온 그리기)에만 그리기 애니메이션
//       — 값 갱신 · 기간 변경 땐 없음, reduced-motion 이면 없음. 길이는 모션 토큰(index.css .draw-in).
// 색: 선은 CSS 변수 이름(--k-exec …), 막대 · 도넛 조각은 클래스(k-killed · dn-passed …, index.css)
export interface Point {
  t: string;
  [k: string]: number | string;
}
type LineKey = [key: string, label: string, colorVar: string];
type ClsKey = [key: string, label: string, cls: string];

// 상자 크기 — ResizeObserver 가 처음 붙을 때도 한 번 알려 준다
function useBox() {
  const ref = useRef<HTMLDivElement>(null);
  const [sz, setSz] = useState({ w: 0, h: 0 });
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSz({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, sz] as const;
}
// 첫 그리기 애니메이션 — 데이터가 있는 첫 그리기에서 한 번만(끝나면 뗀다)
function useDrawIn(has: boolean) {
  const [on, setOn] = useState(() => !reducedMotion());
  useEffect(() => {
    if (!on || !has) return;
    const t = window.setTimeout(() => setOn(false), 900);
    return () => window.clearTimeout(t);
  }, [on, has]);
  return [on && has, () => setOn(false)] as const;
}

// 반전 툴팁(ink 바탕) — 차트 상자 안에서 마우스를 따라가고, 넘치면 반대쪽으로
interface Tip {
  x: number;
  y: number;
  title: string;
  rows: [cls: string | null, text: string][];
}
function TipLayer({ tip, root }: { tip: Tip | null; root: RefObject<HTMLDivElement | null> }) {
  const el = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const t = el.current;
    const r = root.current;
    if (!t || !r || !tip) return;
    const b = r.getBoundingClientRect();
    const w = t.offsetWidth;
    const hh = t.offsetHeight;
    let left = tip.x - b.left + 14;
    if (left + w > b.width) left = Math.max(0, tip.x - b.left - w - 14);
    let top = tip.y - b.top - hh - 10;
    if (top < 0) top = Math.min(b.height - hh, tip.y - b.top + 14);
    t.style.left = `${left}px`;
    t.style.top = `${Math.max(0, top)}px`;
  }, [tip, root]);
  return (
    <div ref={el} className="chart-tip tip-inverse" role="tooltip" data-part="chart-tip" hidden={!tip}>
      {tip && (
        <>
          <div className="tip-title">{tip.title}</div>
          {tip.rows.map(([cls, text], i) => (
            <div key={i} className="tip-row">
              {cls && <i className={`sw ${cls}`} />}
              {text}
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// 눈금: 1 · 2 · 5 × 10^k 로 3칸 안팎
function niceMax(v: number, n = 3) {
  const raw = Math.max(1, v) / n;
  const e = 10 ** Math.floor(Math.log10(raw));
  const f = raw / e;
  const step = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * e;
  return { step, max: Math.max(step, Math.ceil(Math.max(1, v) / step) * step) };
}
const short = (n: number) => (n >= 10000 ? `${Math.round(n / 1000)}k` : n >= 1000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k` : fmtNum(n));
// x 축 글자: 칸 폭으로 몇 칸마다 하나씩 쓸지 — 글자끼리 겹치지 않게
const everyFor = (n: number, iw: number, labelW = 52) => Math.max(1, Math.ceil(n / Math.max(1, Math.floor(iw / labelW))));
const tickText = (t: string, step: number) => {
  const d = new Date(t);
  return step >= 21600 ? `${d.getMonth() + 1}/${d.getDate()}` : fmtTime(t).slice(0, 5);
};
const val = (p: Point | undefined, k: string) => Number(p?.[k] ?? 0) || 0;

// ── 선 차트(추이) — 선 굵기 2 · 점은 hover 때만 · 선 끝 「이름 값」 라벨(겹치면 16px 씩 밀어냄) ──
export function LineChart({ name, label, keys, data, step = 3600 }: { name: string; label: string; keys: LineKey[]; data: Point[]; step?: number }) {
  const root = useRef<HTMLDivElement>(null);
  const [box, { w: bw, h: bh }] = useBox();
  const [tip, setTip] = useState<Tip | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [anim, done] = useDrawIn(data.length > 0);
  const W = bw || 480;
  const H = bh || 160;
  const last = data[data.length - 1];
  const lastVals = keys.map(([k, ko]) => `${ko} ${short(val(last, k))}`);
  const endW = Math.min(120, 16 + Math.max(0, ...lastVals.map((t) => t.length * 7.2)));
  const m = { t: 10, r: endW, b: 24, l: 36 };
  const iw = Math.max(40, W - m.l - m.r);
  const ih = Math.max(40, H - m.t - m.b);
  const top = Math.max(1, ...data.flatMap((d) => keys.map(([k]) => val(d, k))));
  const { step: gs, max } = niceMax(top);
  const x = (i: number) => m.l + (data.length <= 1 ? iw / 2 : (i / (data.length - 1)) * iw);
  const y = (v: number) => m.t + ih - (v / max) * ih;
  const grid: number[] = [];
  for (let v = 0; v <= max + 1e-9; v += gs) grid.push(v);
  const every = everyFor(data.length, iw, 54);
  // 끝 라벨 — 마지막 값 높이에 두고 가까우면 아래로 밀어내고, 넘치면 위로 다시 민다
  const GAP = 16;
  const ends = keys.map(([k, ko, color], j) => ({ k, ko, color, y: y(val(last, k)), text: lastVals[j] })).sort((a, b) => a.y - b.y);
  for (let i = 0; i < ends.length; i++) ends[i].y = Math.max(ends[i].y, i ? ends[i - 1].y + GAP : m.t + 6);
  for (let i = ends.length - 1; i >= 0; i--) ends[i].y = Math.min(ends[i].y, i < ends.length - 1 ? ends[i + 1].y - GAP : m.t + ih);
  const colW = data.length > 1 ? iw / (data.length - 1) : iw;
  const tipFor = (e: MouseEvent, d: Point): Tip => ({
    x: e.clientX,
    y: e.clientY,
    title: tickText(d.t, step),
    rows: keys.map(([k, ko]) => [`k-${k}`, `${ko} ${fmtNum(val(d, k))}`]),
  });
  return (
    <div ref={root} className="chart line-chart" data-chart={name}>
      <div ref={box} className="chart-box">
        <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="chart-svg" role="img" aria-label={label}>
          {grid.map((v) => (
            <g key={v}>
              <line x1={m.l} x2={m.l + iw} y1={y(v)} y2={y(v)} className="grid" strokeDasharray="3 4" />
              <text x={m.l - 8} y={y(v) + 4} textAnchor="end" className="tick tick-y">
                {short(v)}
              </text>
            </g>
          ))}
          {data.map((d, i) =>
            i % every === 0 ? (
              <text key={d.t} x={x(i)} y={H - 6} textAnchor={i === 0 ? 'start' : 'middle'} className="tick tick-x">
                {tickText(d.t, step)}
              </text>
            ) : null,
          )}
          <g className={`lines${anim ? ' draw-in' : ''}`} onAnimationEnd={done}>
            {keys.map(([k, , color]) => (
              <path
                key={k}
                d={data.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(val(p, k)).toFixed(1)}`).join('') || `M${m.l},${y(0)}`}
                className={`line k-line-${k}`}
                data-kind={k}
                style={{ stroke: `var(${color})` }}
                fill="none"
                strokeWidth={2}
                strokeLinejoin="round"
                strokeLinecap="round"
                pathLength={1}
              />
            ))}
          </g>
          {ends.map((e) => (
            <text key={e.k} x={m.l + iw + 8} y={e.y + 4} className="end-label" data-end-label={e.k} style={{ fill: `var(${e.color})` }}>
              {e.text}
            </text>
          ))}
          {hover != null && data[hover] && (
            <g className="hover">
              <line x1={x(hover)} x2={x(hover)} y1={m.t} y2={m.t + ih} className="guide" />
              {keys.map(([k, , color]) => (
                <circle key={k} r={4} cx={x(hover)} cy={y(val(data[hover], k))} className="dot" data-kind={k} style={{ fill: `var(${color})` }} />
              ))}
            </g>
          )}
          <g className="buckets" onMouseLeave={() => (setHover(null), setTip(null))}>
            {data.map((d, i) => (
              <g key={d.t} data-bucket={d.t} onMouseEnter={(e) => (setHover(i), setTip(tipFor(e, d)))} onMouseMove={(e) => setTip(tipFor(e, d))}>
                <rect x={x(i) - colW / 2} y={m.t} width={colW} height={ih} className="hit" />
              </g>
            ))}
          </g>
        </svg>
      </div>
      <TipLayer tip={tip} root={root} />
    </div>
  );
}

// ── 쌓은 막대(위반 추이) — 막대 최대 폭 22 · 맨 위 조각만 위쪽 모서리 3 · 0 칸은 회색 1px 줄 ──
const topRound = (x: number, y0: number, w: number, hh: number, r: number) => {
  const rr = Math.min(r, hh, w / 2);
  return `M${x},${y0 + hh}V${y0 + rr}Q${x},${y0} ${x + rr},${y0}H${x + w - rr}Q${x + w},${y0} ${x + w},${y0 + rr}V${y0 + hh}Z`;
};
export function StackBars({ name, label, keys, data, step = 3600 }: { name: string; label: string; keys: ClsKey[]; data: Point[]; step?: number }) {
  const root = useRef<HTMLDivElement>(null);
  const [box, { w: bw, h: bh }] = useBox();
  const [tip, setTip] = useState<Tip | null>(null);
  const [on, setOn] = useState<number | null>(null);
  const [anim, done] = useDrawIn(data.length > 0);
  const sums = keys.map(([k]) => data.reduce((n, d) => n + val(d, k), 0));
  const W = bw || 320;
  const H = bh || 160;
  const m = { t: 10, r: 6, b: 24, l: 30 };
  const iw = Math.max(40, W - m.l - m.r);
  const ih = Math.max(40, H - m.t - m.b);
  const tot = (d: Point) => keys.reduce((n, [k]) => n + val(d, k), 0);
  const { step: gs, max } = niceMax(Math.max(1, ...data.map(tot)));
  const y = (v: number) => m.t + ih - (v / max) * ih;
  const slot = iw / Math.max(1, data.length);
  const bwid = Math.min(22, Math.max(2, slot * 0.62));
  const grid: number[] = [];
  for (let v = 0; v <= max + 1e-9; v += gs) grid.push(v);
  const every = everyFor(data.length, iw, 54);
  const tipFor = (e: MouseEvent, d: Point): Tip => ({
    x: e.clientX,
    y: e.clientY,
    title: tickText(d.t, step),
    rows: keys.map(([k, ko, cls]) => [cls, `${ko} ${fmtNum(val(d, k))}`]),
  });
  return (
    <div ref={root} className="chart stack-bars" data-chart={name}>
      <div className="chart-legend">
        {keys.map(([k, ko, cls], i) => (
          <span key={k}>
            <i className={`sw ${cls}`} />
            {ko} <b className="num">{fmtNum(sums[i])}</b>
          </span>
        ))}
      </div>
      <div ref={box} className="chart-box">
        <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="chart-svg" role="img" aria-label={label}>
          {grid.map((v) => (
            <g key={v}>
              <line x1={m.l} x2={m.l + iw} y1={y(v)} y2={y(v)} className="grid" strokeDasharray="3 4" />
              <text x={m.l - 6} y={y(v) + 4} textAnchor="end" className="tick tick-y">
                {short(v)}
              </text>
            </g>
          ))}
          <g className={`buckets${anim ? ' draw-in' : ''}`} onAnimationEnd={done}>
            {data.map((d, i) => {
              const x = m.l + i * slot + (slot - bwid) / 2;
              const segs = keys.filter(([k]) => val(d, k));
              let acc = 0;
              return (
                <g
                  key={d.t}
                  data-bucket={d.t}
                  className={on === i ? 'on' : undefined}
                  onMouseEnter={(e) => (setOn(i), setTip(tipFor(e, d)))}
                  onMouseMove={(e) => setTip(tipFor(e, d))}
                  onMouseLeave={() => (setOn(null), setTip(null))}
                >
                  <rect x={m.l + i * slot} y={m.t} width={slot} height={ih} className="hit" />
                  {segs.map(([k, , cls], j) => {
                    const v = val(d, k);
                    const y1 = y(acc + v);
                    const hh = Math.max(1, y(acc) - y1);
                    acc += v;
                    return j === segs.length - 1 ? (
                      <path key={k} d={topRound(x, y1, bwid, hh, 3)} className={`bar seg ${cls}`} data-kind={k} />
                    ) : (
                      <rect key={k} x={x} y={y1} width={bwid} height={hh} className={`bar seg ${cls}`} data-kind={k} />
                    );
                  })}
                  {!segs.length && <rect x={x} y={m.t + ih - 1} width={bwid} height={1} className="bar seg zero" />}
                </g>
              );
            })}
          </g>
          {data.map((d, i) =>
            i % every === 0 ? (
              <text key={d.t} x={m.l + i * slot + slot / 2} y={H - 6} textAnchor={i === 0 ? 'start' : 'middle'} className="tick tick-x">
                {tickText(d.t, step)}
              </text>
            ) : null,
          )}
        </svg>
      </div>
      <TipLayer tip={tip} root={root} />
    </div>
  );
}

// ── 도넛(분포) — 안 58% · 밖 84% · 조각 사이 간격 · 가운데 큰 숫자 · 합 0 이면 회색 고리 ──
export const DONUT_INNER = 0.58;
export const DONUT_OUTER = 0.84;
type Slice = [key: string, label: string, cls: string, value: number];
const arc = (cx: number, cy: number, r0: number, r1: number, a0: number, a1: number) => {
  const p = (r: number, a: number) => [cx + r * Math.sin(a), cy - r * Math.cos(a)];
  const large = a1 - a0 > Math.PI ? 1 : 0;
  const [x0, y0] = p(r1, a0);
  const [x1, y1] = p(r1, a1);
  const [x2, y2] = p(r0, a1);
  const [x3, y3] = p(r0, a0);
  return `M${x0},${y0}A${r1},${r1} 0 ${large} 1 ${x1},${y1}L${x2},${y2}A${r0},${r0} 0 ${large} 0 ${x3},${y3}Z`;
};
export function Donut({ name, label, items, centerLabel, children }: { name: string; label: string; items: Slice[]; centerLabel?: string; children?: ReactNode }) {
  const root = useRef<HTMLDivElement>(null);
  const [box, { w: bw, h: bh }] = useBox();
  const [tip, setTip] = useState<Tip | null>(null);
  const [on, setOn] = useState<string | null>(null);
  const total = items.reduce((n, x) => n + (x[3] || 0), 0);
  const [anim, done] = useDrawIn(total > 0);
  const S = Math.max(80, Math.min(bw || 140, bh || 140));
  const R = S / 2;
  const r1 = R * DONUT_OUTER;
  const r0 = R * DONUT_INNER;
  const live = items.filter((x) => x[3] > 0);
  const pad = live.length > 1 ? 0.035 : 0;
  let a = 0;
  const tipFor = (e: MouseEvent, [, ko, cls, v]: Slice): Tip => ({ x: e.clientX, y: e.clientY, title: ko, rows: [[cls, `${fmtNum(v)}건 · ${Math.round((v / total) * 100)}%`]] });
  return (
    <div ref={root} className="chart donut-chart" data-chart={name} data-inner={String(DONUT_INNER)} data-outer={String(DONUT_OUTER)}>
      <div ref={box} className="chart-box donut-box">
        <svg width={S} height={S} viewBox={`0 0 ${S} ${S}`} className="chart-svg donut-svg" role="img" aria-label={`${label} — ${items.map((x) => `${x[1]} ${x[3]}`).join(', ')}`}>
          <g className={`slices${anim ? ' draw-in' : ''}`} onAnimationEnd={done}>
            {!total ? (
              <circle cx={R} cy={R} r={(r0 + r1) / 2} className="donut-zero" fill="none" strokeWidth={r1 - r0} />
            ) : (
              live.map((it) => {
                const span = (it[3] / total) * Math.PI * 2;
                const a0 = a + pad / 2;
                const a1 = a + span - pad / 2;
                const d =
                  span >= Math.PI * 2 - 1e-6
                    ? `${arc(R, R, r0, r1, 0, Math.PI)}${arc(R, R, r0, r1, Math.PI, Math.PI * 2 - 1e-4)}`
                    : arc(R, R, r0, r1, a0, Math.max(a0 + 0.001, a1));
                a += span;
                return (
                  <path
                    key={it[0]}
                    d={d}
                    className={`slice ${it[2]}${on === it[0] ? ' on' : ''}`}
                    data-slice={it[0]}
                    onMouseEnter={(e) => (setOn(it[0]), setTip(tipFor(e, it)))}
                    onMouseMove={(e) => setTip(tipFor(e, it))}
                    onMouseLeave={() => (setOn(null), setTip(null))}
                  />
                );
              })
            )}
          </g>
          <text x={R} y={R + (centerLabel ? 2 : 8)} textAnchor="middle" className="donut-num" data-part="donut-center">
            {fmtNum(total)}
          </text>
          {centerLabel && (
            <text x={R} y={R + 20} textAnchor="middle" className="donut-label">
              {centerLabel}
            </text>
          )}
        </svg>
      </div>
      {children}
      <TipLayer tip={tip} root={root} />
    </div>
  );
}
