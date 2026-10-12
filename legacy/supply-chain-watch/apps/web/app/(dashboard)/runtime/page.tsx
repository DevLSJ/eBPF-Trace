'use client';
import { useCallback, useEffect, useState } from 'react';
import type { WsEnvelope, RuntimeIncident } from '@scw/shared-types';
import { useWebSocket } from '@/lib/ws';
import {
  getIncidents,
  getSummary,
  getTopology,
  purlShort,
  RULE_LABEL,
  type RuntimeSummary,
  type Topology,
} from '@/lib/runtime';
import { cn } from '@/lib/utils';
import { RuntimeConfirm, type RuntimeAction } from '@/components/runtime-confirm';

const POS: Record<string, { x: number; y: number }> = {
  edge: { x: 30, y: 188 },
  image: { x: 250, y: 60 },
  pay: { x: 250, y: 316 },
  postgres: { x: 470, y: 80 },
  redis: { x: 470, y: 222 },
  c2: { x: 470, y: 360 },
};
const W = 150;
const H = 56;
const center = (k: string) => ({ cx: POS[k].x + W / 2, cy: POS[k].y + H / 2 });

export default function RuntimePage() {
  const [summary, setSummary] = useState<RuntimeSummary | null>(null);
  const [topo, setTopo] = useState<Topology | null>(null);
  const [incidents, setIncidents] = useState<RuntimeIncident[]>([]);
  const [pending, setPending] = useState<{ key: string; action: RuntimeAction } | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; message: string } | null>(null);

  const load = useCallback(() => {
    void getSummary().then(setSummary).catch(() => {});
    void getTopology().then(setTopo).catch(() => {});
    void getIncidents().then(setIncidents).catch(() => {});
  }, []);
  useEffect(load, [load]);

  const onEvent = useCallback((e: WsEnvelope) => {
    if (e.type === 'runtime.topology') {
      setTopo(e.payload as Topology);
      void getSummary().then(setSummary).catch(() => {});
    } else if (e.type === 'runtime.incident') {
      const inc = e.payload as RuntimeIncident;
      setIncidents((prev) => {
        const rest = prev.filter((p) => p.incidentKey !== inc.incidentKey);
        return [inc, ...rest].slice(0, 50);
      });
    }
  }, []);
  const wsState = useWebSocket(onEvent);

  const nodes = topo?.nodes ?? [];
  const edges = topo?.edges ?? [];
  const c2 = topo?.c2Visible ?? false;

  return (
    <section className="flex flex-col gap-3 lg:h-full">
      <div className="flex items-center justify-between gap-3">
        <h1 className="text-[20px] font-semibold tracking-tight">런타임 추적·차단</h1>
        <div className="flex items-center gap-2 text-[12px]">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 text-fg-2">
            <span className={cn('h-1.5 w-1.5 rounded-full', wsState === 'open' ? 'bg-good' : 'bg-warn')} />
            서버 {summary?.tracked ?? 0}대 추적 중
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3.5 lg:min-h-0 lg:flex-1 lg:grid-cols-[7fr_3fr]">
        {/* 서비스 연결도 */}
        <div className="flex min-h-0 flex-col rounded-2xl border border-line bg-surface">
          <div className="flex items-center justify-between border-b border-line px-4 py-3">
            <h2 className="text-[14px] font-bold">서비스 연결도</h2>
            <span className="text-[12px] text-fg-3">노드가 빨갛게 점멸하면 감염 의심</span>
          </div>
          <div className="relative min-h-[360px] flex-1">
            <svg viewBox="0 0 680 440" preserveAspectRatio="xMidYMid meet" className="h-full w-full">
              {edges.map(([a, b], i) => {
                const p = center(a);
                const q = center(b);
                return (
                  <path
                    key={i}
                    d={`M${p.cx} ${p.cy} C ${(p.cx + q.cx) / 2} ${p.cy}, ${(p.cx + q.cx) / 2} ${q.cy}, ${q.cx} ${q.cy}`}
                    fill="none"
                    stroke="var(--line-strong)"
                    strokeWidth={2}
                  />
                );
              })}
              {c2 &&
                nodes.filter((n) => n.infected).map((n) => {
                  const p = center(n.key);
                  const q = center('c2');
                  return (
                    <path
                      key={`c2-${n.key}`}
                      d={`M${p.cx} ${p.cy} C ${(p.cx + q.cx) / 2} ${p.cy}, ${(p.cx + q.cx) / 2} ${q.cy}, ${q.cx} ${q.cy}`}
                      fill="none"
                      stroke="var(--crit)"
                      strokeWidth={2.5}
                      strokeDasharray="6 5"
                    >
                      <animate attributeName="stroke-dashoffset" from="22" to="0" dur="0.6s" repeatCount="indefinite" />
                    </path>
                  );
                })}
              {nodes.map((n) => (
                <g key={n.key} transform={`translate(${POS[n.key].x},${POS[n.key].y})`}>
                  <rect
                    width={W}
                    height={H}
                    rx={12}
                    fill={n.infected ? 'var(--crit-soft)' : 'var(--surface)'}
                    stroke={n.infected ? 'var(--crit)' : 'var(--line-strong)'}
                    strokeWidth={1.5}
                  >
                    {n.infected && <animate attributeName="opacity" values="1;0.55;1" dur="1.1s" repeatCount="indefinite" />}
                  </rect>
                  <text x={16} y={26} className="fill-fg text-[12px] font-bold">{n.name}</text>
                  <text x={16} y={43} className="fill-fg-3 text-[9.5px]">{n.role}</text>
                </g>
              ))}
              {c2 && (
                <g transform={`translate(${POS.c2.x},${POS.c2.y})`}>
                  <rect width={W} height={H} rx={12} fill="#2a3038" stroke="var(--crit)" strokeWidth={1.5} />
                  <text x={16} y={26} className="text-[12px] font-bold" fill="#fff">수상한 외부 서버</text>
                  <text x={16} y={43} className="text-[9.5px]" fill="#c9ccd1">허용 목록에 없음</text>
                </g>
              )}
            </svg>
            <div className="absolute bottom-3 left-3.5 flex gap-3.5 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[11.5px] text-fg-2">
              <span><i className="mr-1 inline-block h-2 w-2 rounded-full align-middle" style={{ background: 'var(--good)' }} />정상</span>
              <span><i className="mr-1 inline-block h-2 w-2 rounded-full align-middle" style={{ background: 'var(--crit)' }} />감염·의심</span>
            </div>
          </div>
        </div>

        {/* 오른쪽: 요약 + 실시간 경보 */}
        <div className="flex min-h-0 flex-col gap-3.5">
          <div className="grid grid-cols-2 gap-2.5">
            <SummaryCard label="연결된 감시" value={summary?.agentsOnline ?? 0} />
            <SummaryCard label="추적 중인 서버" value={summary?.tracked ?? 0} />
            <SummaryCard label="처리 안 된 경보" value={summary?.openIncidents ?? 0} danger={!!summary?.openIncidents} />
            <SummaryCard label="오늘 차단" value={summary?.blockedToday ?? 0} />
          </div>
          <div className="flex min-h-0 flex-1 flex-col rounded-2xl border border-line bg-surface">
            <div className="flex items-center justify-between border-b border-line px-4 py-3">
              <h2 className="text-[14px] font-bold">실시간 경보</h2>
              <span className="rounded-md bg-surface-2 px-2 py-0.5 text-[11.5px] text-fg-2">{incidents.length}</span>
            </div>
            <div className="min-h-0 flex-1 overflow-auto p-2">
              {incidents.length === 0 ? (
                <p className="p-3 text-[12.5px] text-fg-3">
                  아직 경보가 없습니다. 공격 시연에서 시나리오를 실행하면 여기에 표시됩니다.
                </p>
              ) : (
                incidents.map((i) => (
                  <IncidentCard key={i.incidentKey} inc={i} onAction={(action) => setPending({ key: i.incidentKey, action })} />
                ))
              )}
            </div>
          </div>
        </div>
      </div>
      {notice && (
        <div
          role="status"
          aria-live="polite"
          className={cn('fixed bottom-5 right-5 z-40 rounded-lg px-4 py-2.5 text-[13px] font-semibold shadow-card', notice.ok ? 'bg-good-soft text-good-ink' : 'bg-crit-soft text-crit-ink')}
        >
          {notice.message}
        </div>
      )}
      {pending && (
        <RuntimeConfirm
          incidentKey={pending.key}
          action={pending.action}
          onClose={(r) => {
            setPending(null);
            if (r) {
              setNotice(r);
              setTimeout(() => setNotice(null), 5000);
              load();
            }
          }}
        />
      )}
    </section>
  );
}

function SummaryCard({ label, value, danger }: { label: string; value: number; danger?: boolean }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-3">
      <div className={cn('text-[22px] font-extrabold tabular-nums', danger && 'text-crit')}>{value}</div>
      <div className="text-[11.5px] text-fg-2">{label}</div>
    </div>
  );
}

function IncidentCard({ inc, onAction }: { inc: RuntimeIncident; onAction: (a: RuntimeAction) => void }) {
  return (
    <div
      className={cn(
        'mb-2 rounded-xl border bg-surface p-3',
        inc.blocked ? 'border-line opacity-80' : 'border-crit shadow-[0_0_0_3px_var(--crit-soft)]',
      )}
    >
      <div className="flex items-center justify-between">
        <span
          className={cn(
            'rounded-md px-2 py-0.5 text-[11.5px] font-bold',
            inc.blocked ? 'bg-good-soft text-good-ink' : 'bg-crit-soft text-crit-ink',
          )}
        >
          {inc.blocked ? '✓ 차단됨' : `▲ 위험 ${inc.score}`}
        </span>
        <span className="font-mono text-[11px] text-fg-3">{new Date(inc.lastAt).toLocaleTimeString('ko-KR', { hour12: false })}</span>
      </div>
      <div className="mt-1 text-[13px] font-semibold">{inc.container} · 외부 서버 접속 시도</div>
      <div className="mt-0.5 text-[12px] text-fg-2">
        {inc.rules.map((r) => RULE_LABEL[r] ?? r).join(' · ')}
      </div>
      {inc.purl && <div className="mt-0.5 font-mono text-[11px] text-fg-3">원인 패키지 {purlShort(inc.purl)}</div>}
      {!inc.blocked && (
        <div className="mt-2 flex gap-2">
          <button
            onClick={() => onAction('kill')}
            className="flex-1 rounded-lg bg-crit px-3 py-1.5 text-[12px] font-bold text-white"
          >
            공격 프로그램 종료
          </button>
          <button
            onClick={() => onAction('block')}
            className="flex-1 rounded-lg border border-line-strong bg-surface px-3 py-1.5 text-[12px] font-bold"
          >
            접속 차단
          </button>
        </div>
      )}
      {inc.blocked && <div className="mt-2 text-[12px] text-good-ink">✓ 공격 프로그램 종료됨 · 서비스는 정상 동작</div>}
    </div>
  );
}
