import { useLayoutEffect, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import { fmtNum } from '../../lib/format';
import { COLOR, fitText, niceTicks, type ColorKey, type TipLine } from './scale';

// 평가 화면 차트(11/04, 목업 mock/shared/eval.js 의 SVG 모양 그대로) — 점선 격자 · 아래 축 · 범례 · 행에 마우스 → 툴팁.
// 새 의존성 없이 SVG 로 그린다(package.json 에 차트 라이브러리가 없다). 색은 토큰(Tailwind fill-* · bg-*)만

export interface Seg {
  key: string;
  v: number;
  color: ColorKey;
}
export interface BarRow {
  id: string;
  label: string;
  mono?: boolean;
  strong?: boolean;
  bars: Seg[][]; // 한 행에 막대 bars.length 개, 막대마다 조각을 쌓는다
  value: string;
  tip: TipLine[];
}

// 상자 폭(px) — 다시 그려도 높이는 바뀌지 않는다
function useWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setW(Math.floor(el.clientWidth)));
    ro.observe(el);
    setW(Math.floor(el.clientWidth));
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

interface Tip {
  x: number;
  y: number;
  w: number; // 차트 폭 — 오른쪽 절반이면 툴팁을 마우스 왼쪽에
  lines: TipLine[];
}
// 툴팁(차트 상자 안에서 마우스를 따라간다) — [차트 루트 ref, 상태, 보이기, 숨기기]
function useTip() {
  const root = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<Tip | null>(null);
  const at = (e: MouseEvent, lines: TipLine[]) => {
    const el = root.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setTip({ x: e.clientX - r.left, y: e.clientY - r.top, w: r.width, lines });
  };
  const hide = () => setTip(null);
  return [root, tip, at, hide] as const;
}
function TipView({ tip }: { tip: Tip | null }) {
  if (!tip) return null;
  return (
    <div
      role="tooltip"
      data-part="chart-tip"
      className="pointer-events-none absolute z-10 grid gap-0.5 rounded-[var(--r-sm)] border border-border bg-surface px-2 py-1.5 text-xs whitespace-nowrap text-text-2 shadow-[var(--sh-2)]"
      style={{ top: tip.y + 12, ...(tip.x > tip.w / 2 ? { right: tip.w - tip.x + 12 } : { left: tip.x + 12 }) }}
    >
      {tip.lines.map(([c, t], i) => (
        <div key={i} className={i ? '' : 'font-semibold text-text'}>
          {c && <i className={`mr-1.5 inline-block size-2 rounded-[2px] ${COLOR[c][1]}`} />}
          {t}
        </div>
      ))}
    </div>
  );
}

export function Legend({ items }: { items: [string, ColorKey | 'p50' | 'band' | 'max'][] }) {
  const sw = (c: ColorKey | 'p50' | 'band' | 'max') =>
    c === 'p50' ? 'size-2 rounded-full bg-accent' : c === 'band' ? 'h-2 w-3 rounded-[2px] bg-indigo-300' : c === 'max' ? 'h-2.5 w-0.5 bg-text-2' : `size-2 rounded-[2px] ${COLOR[c][1]}`;
  return (
    <div data-part="legend" className="flex flex-wrap gap-x-2.5 gap-y-1 text-xs text-text-3">
      {items.map(([label, c]) => (
        <span key={label} className="inline-flex items-center gap-1">
          <i className={`inline-block ${sw(c)}`} aria-hidden />
          {label}
        </span>
      ))}
    </div>
  );
}

const AXIS = { t: 4, b: 22 };

function Grid({ ticks, x, H, fmt }: { ticks: number[]; x: (v: number) => number; H: number; fmt: (t: number) => string }) {
  return ticks.map((t) => (
    <g key={t}>
      <line x1={x(t)} x2={x(t)} y1={AXIS.t} y2={H - AXIS.b} className={t ? 'stroke-surface-3' : 'stroke-border'} strokeDasharray={t ? '3 3' : undefined} />
      <text data-part="tick" x={x(t)} y={H - 6} textAnchor="middle" className="fill-text-3 text-xs">
        {fmt(t)}
      </text>
    </g>
  ));
}

// 가로 막대(쌓기 · 묶음). minSeg: 조각 최소 폭(px) — 단계 막대는 0(「판정」 0.1ms 를 부풀리지 않는다)
export function HBars({
  name,
  label,
  rows,
  ticks,
  tickFmt,
  legend,
  labelW = 140,
  valueW = 64,
  minSeg = 1,
}: {
  name: string;
  label: string;
  rows: BarRow[];
  ticks: number[];
  tickFmt: (t: number) => string;
  legend?: [string, ColorKey][];
  labelW?: number;
  valueW?: number;
  minSeg?: number;
}) {
  const [box, W] = useWidth();
  const [root, tip, showTip, hideTip] = useTip();
  const [on, setOn] = useState<string | null>(null);
  const BAR = 10;
  const n = Math.max(1, ...rows.map((r) => r.bars.length));
  const stackH = n * BAR + (n - 1) * 3;
  const rowH = Math.max(30, stackH + 16);
  const H = AXIS.t + rows.length * rowH + AXIS.b;
  const max = ticks[ticks.length - 1] || 1;
  const lw = Math.min(labelW, Math.round(W * 0.36));
  const iw = Math.max(40, W - lw - valueW);
  const x = (v: number) => lw + (Math.min(v, max) / max) * iw;
  return (
    <div ref={root} className="relative grid gap-1.5" data-chart={name}>
      {legend && <Legend items={legend} />}
      <div ref={box} className="relative min-w-0" style={{ height: H }}>
        {W > 0 && (
          <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} className="block">
            <Grid ticks={ticks} x={x} H={H} fmt={tickFmt} />
            {rows.map((r, i) => {
              const y0 = AXIS.t + i * rowH;
              let by = y0 + (rowH - stackH) / 2;
              return (
                <g key={r.id} data-row={r.id}>
                  <rect x={0} y={y0} width={W} height={rowH} className={`fill-surface-2 transition-opacity ${on === r.id ? 'opacity-100' : 'opacity-0'}`} />
                  <text data-part="row-label" x={lw - 8} y={y0 + rowH / 2 + 4} textAnchor="end" className={`text-xs ${r.strong ? 'fill-text font-semibold' : 'fill-text-2'} ${r.mono ? 'font-mono' : ''}`}>
                    {fitText(r.label, lw - 10, r.mono)}
                  </text>
                  {r.bars.map((segs, bi) => {
                    const live = segs.filter((s) => s.v > 0);
                    const yb = by;
                    by += BAR + 3;
                    let acc = 0;
                    if (!live.length) return <rect key={bi} data-key="zero" data-v={0} x={lw} y={yb} width={2} height={BAR} className="fill-surface-3" />;
                    return live.map((s, j) => {
                      const x0 = x(acc);
                      acc += s.v;
                      const x1 = x(acc);
                      return <rect key={`${bi}-${s.key}`} data-key={s.key} data-v={s.v} x={x0} y={yb} width={Math.max(minSeg, x1 - x0 - (j < live.length - 1 ? 2 : 0))} height={BAR} rx={2} className={COLOR[s.color][0]} />;
                    });
                  })}
                  <text data-part="row-value" x={W - valueW + 8} y={y0 + rowH / 2 + 4} className="num fill-text-2 text-xs">
                    {r.value}
                  </text>
                  <rect
                    data-hit=""
                    x={0}
                    y={y0}
                    width={W}
                    height={rowH}
                    fill="transparent"
                    onMouseEnter={(e) => {
                      setOn(r.id);
                      showTip(e, r.tip);
                    }}
                    onMouseMove={(e) => showTip(e, r.tip)}
                    onMouseLeave={() => {
                      setOn(null);
                      hideTip();
                    }}
                  />
                </g>
              );
            })}
          </svg>
        )}
      </div>
      <TipView tip={tip} />
    </div>
  );
}

export interface RangeRow {
  id: string;
  label: string;
  lat: { p50: number; p95: number; max?: number };
  tip: TipLine[];
}
// 지연 범위: 행마다 0~max 선 · p50~p95 띠 · p50 점 · max 눈금
export function RangeChart({ name, label, rows }: { name: string; label: string; rows: RangeRow[] }) {
  const [box, W] = useWidth();
  const [root, tip, showTip, hideTip] = useTip();
  const [on, setOn] = useState<string | null>(null);
  const rowH = 30;
  const valueW = 64;
  const H = AXIS.t + rows.length * rowH + AXIS.b;
  const ticks = niceTicks(Math.max(1, ...rows.map((r) => r.lat.max ?? r.lat.p95)));
  const max = ticks[ticks.length - 1];
  const lw = Math.min(150, Math.round(W * 0.36));
  const iw = Math.max(40, W - lw - valueW);
  const x = (v: number) => lw + (Math.min(v, max) / max) * iw;
  return (
    <div ref={root} className="relative grid gap-1.5" data-chart={name}>
      <Legend items={[['p50', 'p50'], ['p50 ~ p95', 'band'], ['max', 'max']]} />
      <div ref={box} className="relative min-w-0" style={{ height: H }}>
        {W > 0 && (
          <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} className="block">
            <Grid ticks={ticks} x={x} H={H} fmt={(t) => fmtNum(t)} />
            {rows.map((r, i) => {
              const y0 = AXIS.t + i * rowH;
              const cy = y0 + rowH / 2;
              const L = r.lat;
              const mx = L.max ?? L.p95;
              return (
                <g key={r.id} data-row={r.id} data-p50={L.p50} data-p95={L.p95} data-max={mx}>
                  <rect x={0} y={y0} width={W} height={rowH} className={`fill-surface-2 transition-opacity ${on === r.id ? 'opacity-100' : 'opacity-0'}`} />
                  <text data-part="row-label" x={lw - 8} y={cy + 4} textAnchor="end" className="fill-text-2 text-xs">
                    {fitText(r.label, lw - 10)}
                  </text>
                  <line x1={x(0)} x2={x(mx)} y1={cy} y2={cy} className="stroke-border-strong" />
                  <rect x={x(L.p50)} y={cy - 4} width={Math.max(2, x(L.p95) - x(L.p50))} height={8} rx={2} className="fill-indigo-300" />
                  <line x1={x(mx)} x2={x(mx)} y1={cy - 6} y2={cy + 6} strokeWidth={2} className="stroke-text-2" />
                  <circle cx={x(L.p50)} cy={cy} r={4.5} strokeWidth={2} className="fill-accent stroke-surface" />
                  <text data-part="row-value" x={W - valueW + 8} y={cy + 4} className="num fill-text-2 text-xs">
                    p95 {fmtNum(L.p95)}
                  </text>
                  <rect
                    data-hit=""
                    x={0}
                    y={y0}
                    width={W}
                    height={rowH}
                    fill="transparent"
                    onMouseEnter={(e) => {
                      setOn(r.id);
                      showTip(e, r.tip);
                    }}
                    onMouseMove={(e) => showTip(e, r.tip)}
                    onMouseLeave={() => {
                      setOn(null);
                      hideTip();
                    }}
                  />
                </g>
              );
            })}
          </svg>
        )}
      </div>
      <TipView tip={tip} />
    </div>
  );
}

export function ChartNote({ children, part }: { children: ReactNode; part?: string }) {
  return (
    <p data-part={part} className="text-xs text-text-3">
      {children}
    </p>
  );
}
