import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node, type NodeMouseHandler } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Box, Cpu, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Empty, Panel } from '../../components/Panel';
import { LevelBadge } from '../../components/VerdictBadge';
import { useStream } from '../../hooks/stream-context';
import { fmtNum, fmtTime } from '../../lib/format';
import { attackChains, severity, type Chain, type NodeType, type TopoEdge, type TopoNode } from '../../lib/topology';
import { LEVEL_LABEL, type Kind, type Level } from '../../lib/types';

// 3열 고정 레이아웃: 컨테이너 → 프로세스 → 파일/목적지. 위치가 결정적이라 실시간 갱신에도 흔들리지 않는다.
// 엣지 위에는 글자를 두지 않는다(화살표와 겹침) — 종류는 말단 노드의 kind 칩, 횟수는 ×N 으로 보인다. (mock/ 에서 확정한 설계)
const COL_X: Record<NodeType, number> = { container: 0, process: 330, file: 690, dest: 690 };
const ROW_H = 56;
const NODE_W = 240;
const LEAF_W = 290;

// React Flow 기본 노드 스타일을 이기도록 색은 인라인 style로 준다
const nodeStyle: Record<Level, CSSProperties> = {
  normal: { background: '#ffffff', borderColor: '#cbd5e1', color: '#334155' },
  alert: { background: '#fffbeb', borderColor: '#f59e0b', color: '#78350f' },
  held: { background: '#fef2f2', borderColor: '#f87171', color: '#991b1b', borderStyle: 'dashed' },
  killed: { background: '#dc2626', borderColor: '#b91c1c', color: '#ffffff' },
};
const edgeColor: Record<Level, string> = { normal: '#cbd5e1', alert: '#f59e0b', held: '#ef4444', killed: '#dc2626' };
const chipStyle: Record<'open' | 'connect', string> = { open: 'bg-sky-100 text-sky-800', connect: 'bg-teal-100 text-teal-800' };
const statusChip: Record<Level, string> = {
  normal: '',
  alert: 'bg-amber-200 text-amber-900',
  held: 'bg-red-200 text-red-900',
  killed: 'bg-white/25 text-white',
};

const isLeaf = (t: NodeType) => t === 'file' || t === 'dest';
// 긴 경로는 가운데를 줄여 앞(디렉터리)과 끝(파일명)을 함께 보인다. 전체는 툴팁.
const ellipsize = (t: string, max: number) => {
  if (t.length <= max) return t;
  const head = Math.max(4, Math.floor(max * 0.35));
  return `${t.slice(0, head)}…${t.slice(-(max - head - 1))}`;
};
const bySeverity = (a: TopoNode, b: TopoNode) => severity[b.level] - severity[a.level] || a.label.localeCompare(b.label);

function NodeLabel({ n }: { n: TopoNode }) {
  const chipTone = n.level === 'killed' ? 'bg-white/25 text-white' : undefined;
  return (
    <div className="flex items-center gap-2 text-left" title={`${n.label}\n${n.count}회${n.violations ? ` · 위반 ${n.violations}` : ''}${n.reason ? `\n${n.reason}` : ''}`}>
      {isLeaf(n.type) ? (
        <span className={`w-14 shrink-0 rounded px-1 text-center font-mono text-[10.5px] font-semibold ${chipTone ?? chipStyle[n.type === 'file' ? 'open' : 'connect']}`}>
          {n.type === 'file' ? 'open' : 'connect'}
        </span>
      ) : n.type === 'container' ? (
        <Box className="size-3.5 shrink-0" aria-hidden />
      ) : (
        <Cpu className="size-3.5 shrink-0" aria-hidden />
      )}
      <span className={`min-w-0 flex-1 truncate ${isLeaf(n.type) ? 'font-mono text-[11px]' : 'font-medium'}`}>
        {isLeaf(n.type) ? ellipsize(n.label, 30) : n.label}
      </span>
      {n.type === 'container' && n.level !== 'normal' && (
        <span className={`shrink-0 rounded-full px-2 text-[10.5px] font-semibold ${statusChip[n.level]}`}>{LEVEL_LABEL[n.level]}</span>
      )}
      {n.count > 1 && <span className="num shrink-0 font-mono text-[11px] opacity-75">×{fmtNum(n.count)}</span>}
    </div>
  );
}

function layout(nodes: TopoNode[], edges: TopoEdge[], selectedId: string | null): { nodes: Node[]; edges: Edge[] } {
  const children = new Map<string, string[]>();
  for (const e of edges) children.set(e.source, [...(children.get(e.source) ?? []), e.target]);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const pos = new Map<string, { x: number; y: number }>();
  let row = 0;
  const containers = nodes.filter((n) => n.type === 'container').sort(bySeverity);
  for (const c of containers) {
    const start = row;
    const procs = (children.get(c.id) ?? []).map((id) => byId.get(id)).filter((n): n is TopoNode => !!n).sort(bySeverity);
    for (const p of procs) {
      const pStart = row;
      const leaves = (children.get(p.id) ?? [])
        .map((id) => byId.get(id))
        .filter((n): n is TopoNode => !!n)
        .sort((a, b) => severity[b.level] - severity[a.level] || (a.type === b.type ? a.label.localeCompare(b.label) : a.type === 'file' ? -1 : 1));
      for (const l of leaves) pos.set(l.id, { x: COL_X[l.type], y: row++ * ROW_H });
      if (leaves.length === 0) row++;
      pos.set(p.id, { x: COL_X.process, y: ((pStart + row - 1) / 2) * ROW_H });
    }
    if (row === start) row++;
    pos.set(c.id, { x: COL_X.container, y: ((start + row - 1) / 2) * ROW_H });
    row++; // 컨테이너 간 여백
  }

  return {
    nodes: nodes
      .filter((n) => pos.has(n.id))
      .map(
        (n) =>
          ({
            id: n.id,
            position: pos.get(n.id)!,
            draggable: false,
            connectable: false,
            data: { label: <NodeLabel n={n} /> },
            style: {
              ...nodeStyle[n.level],
              width: isLeaf(n.type) ? LEAF_W : NODE_W,
              borderWidth: n.id === selectedId ? 2 : 1,
              borderColor: n.id === selectedId ? '#4f46e5' : nodeStyle[n.level].borderColor,
              borderRadius: 6,
              padding: '6px 10px',
              fontSize: 12,
              boxShadow: 'none',
              cursor: 'pointer',
            },
            sourcePosition: 'right',
            targetPosition: 'left',
          }) as Node,
      ),
    edges: edges.map((e) => {
      const touches = selectedId !== null && (e.source === selectedId || e.target === selectedId);
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: e.level !== 'normal',
        style: {
          stroke: edgeColor[e.level],
          strokeWidth: e.level === 'normal' ? 1.25 : 2.25,
          opacity: selectedId === null || touches ? 1 : 0.18,
          transition: 'opacity .15s',
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor[e.level] },
      };
    }),
  };
}

const WINDOWS = [1, 5, 15];
const KIND_STEP: Record<Kind, string> = { exec: '1 실행', open: '2 파일', connect: '3 통신' };
const stepTone: Record<Kind, string> = { exec: 'bg-violet-50 text-violet-700', open: 'bg-sky-50 text-sky-700', connect: 'bg-teal-50 text-teal-700' };
const TYPE_LABEL: Record<NodeType, string> = { container: '컨테이너', process: '프로세스', file: '파일', dest: '외부 목적지' };

export function TopologyPage() {
  const { topology } = useStream();
  const [params, setParams] = useSearchParams();
  const container = params.get('container') ?? '';
  const [windowMin, setWindowMin] = useState(5);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  // 스트림은 250ms마다 갱신되지만 그래프는 1초마다 다시 그린다
  useEffect(() => {
    const t = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, []);

  const snap = useMemo(() => {
    const s = topology.snapshot(windowMin * 60_000, container || undefined);
    return { ...s, containers: topology.containers(), chains: attackChains(s.nodes), tick };
  }, [topology, windowMin, container, tick]);

  // 선택한 노드가 창 밖으로 사라졌으면 선택이 없는 것으로 본다 (effect 로 setState 하지 않고 파생값으로)
  const selected = selectedId ? snap.nodes.find((n) => n.id === selectedId) ?? null : null;
  const effectiveId = selected?.id ?? null;
  const graph = useMemo(() => layout(snap.nodes, snap.edges, effectiveId), [snap, effectiveId]);
  const risky = snap.nodes.filter((n) => n.level !== 'normal').length;
  const toggle = useCallback((id: string) => setSelectedId((cur) => (cur === id ? null : id)), []);
  const onNodeClick: NodeMouseHandler = useCallback((_, node) => toggle(node.id), [toggle]);

  return (
    <div className="flex h-full min-h-[560px] gap-4">
      <Panel
        className="min-w-0 flex-1"
        title={
          <span>
            보안 토폴로지 <span className="num ml-1 font-normal text-slate-400">노드 {snap.nodes.length} · 위험 {risky}</span>
          </span>
        }
        actions={
          <div className="flex items-center gap-4 text-sm">
            <select
              className="h-8 rounded-md border border-slate-300 bg-white px-2 text-sm"
              value={container}
              onChange={(e) => {
                const next = new URLSearchParams(params);
                if (e.target.value) next.set('container', e.target.value);
                else next.delete('container');
                setParams(next, { replace: true });
                setSelectedId(null);
              }}
            >
              <option value="">모든 컨테이너</option>
              {snap.containers.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
            <label className="flex items-center gap-2 text-slate-500">
              최근
              <input
                type="range"
                min={0}
                max={WINDOWS.length - 1}
                value={WINDOWS.indexOf(windowMin)}
                onChange={(e) => setWindowMin(WINDOWS[Number(e.target.value)])}
                className="w-24 accent-indigo-600"
              />
              <span className="num w-10 text-slate-700">{windowMin}분</span>
            </label>
          </div>
        }
      >
        <div className="flex h-full flex-col">
          <Legend />
          <div className="relative min-h-0 flex-1">
            {graph.nodes.length === 0 ? (
              <Empty>표시할 활동 없음 — 이벤트가 들어오면 그래프가 그려집니다</Empty>
            ) : (
              <ReactFlow
                key={container}
                nodes={graph.nodes}
                edges={graph.edges}
                onNodeClick={onNodeClick}
                onPaneClick={() => setSelectedId(null)}
                fitView
                fitViewOptions={{ padding: 0.12, maxZoom: 1.1 }}
                minZoom={0.2}
                nodesDraggable={false}
                nodesConnectable={false}
              >
                <Background color="#e2e8f0" gap={24} />
                <Controls showInteractive={false} />
              </ReactFlow>
            )}
          </div>
        </div>
      </Panel>

      <aside className="flex w-[340px] shrink-0 flex-col gap-4">
        {selected && <NodeDetail n={selected} onClose={() => setSelectedId(null)} />}
        <ChainPanel chains={snap.chains} windowMin={windowMin} selectedId={effectiveId} onSelect={toggle} />
      </aside>
    </div>
  );
}

function Legend() {
  const items: [Level, string][] = [
    ['normal', '정상'],
    ['alert', '경고'],
    ['held', '격리 대상'],
    ['killed', '격리됨'],
  ];
  return (
    <div className="flex shrink-0 flex-wrap gap-3.5 border-b border-slate-100 px-4 py-2 text-xs text-slate-600">
      {items.map(([l, label]) => (
        <span key={l} className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm border" style={nodeStyle[l]} />
          {label}
        </span>
      ))}
      <span className="flex items-center gap-1.5 text-slate-400">
        <span className="h-0.5 w-4 rounded bg-slate-400" /> 굵은 선 = 위반 · 노드를 누르면 연결선만 강조
      </span>
    </div>
  );
}

function NodeDetail({ n, onClose }: { n: TopoNode; onClose: () => void }) {
  const rules = [...n.rules.entries()].sort((a, b) => b[1] - a[1]);
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4 text-sm">
      <div className="mb-2 flex items-center justify-between">
        <b>선택한 노드</b>
        <button type="button" onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700" aria-label="선택 해제">
          <X className="size-4" />
        </button>
      </div>
      <dl className="grid grid-cols-[4rem_1fr] gap-x-2.5 gap-y-1 text-[13px]">
        <dt className="text-slate-500">종류</dt>
        <dd>{TYPE_LABEL[n.type]}</dd>
        <dt className="text-slate-500">이름</dt>
        <dd className={`break-all ${isLeaf(n.type) ? 'font-mono text-xs' : ''}`}>{n.label}</dd>
        <dt className="text-slate-500">컨테이너</dt>
        <dd>{n.container}</dd>
        <dt className="text-slate-500">판정</dt>
        <dd>
          <LevelBadge level={n.level} />
        </dd>
        <dt className="text-slate-500">횟수</dt>
        <dd className="num">
          {fmtNum(n.count)}회 · 위반 {fmtNum(n.violations)}회
        </dd>
        <dt className="text-slate-500">마지막</dt>
        <dd className="num">{fmtTime(new Date(n.lastSeen).toISOString())}</dd>
      </dl>
      {rules.length > 0 && (
        <div className="mt-3">
          <div className="text-xs font-medium text-slate-700">걸린 규칙</div>
          <ul className="mt-1.5 flex flex-wrap gap-1.5">
            {rules.map(([id, cnt]) => (
              <li key={id}>
                <Link to={`/policies?id=${encodeURIComponent(id)}`} className="rounded-full bg-indigo-50 px-2 py-0.5 font-mono text-[11px] text-indigo-700 hover:underline">
                  {id} ×{cnt}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
      {n.reason && <p className="mt-2 text-xs text-slate-500">{n.reason}</p>}
      <Link
        to={`/events?container=${encodeURIComponent(n.container)}${n.level !== 'normal' ? '&verdict=violation' : ''}`}
        className="mt-3 inline-block rounded-md px-2 py-1 text-xs text-indigo-600 hover:bg-indigo-50"
      >
        이벤트에서 보기 →
      </Link>
    </section>
  );
}

// 공격 체인: 컨테이너별 위반 노드를 데모 시나리오 순서(1 실행 → 2 파일 → 3 통신)로. 누르면 그래프에서 강조.
function ChainPanel({ chains, windowMin, selectedId, onSelect }: { chains: Chain[]; windowMin: number; selectedId: string | null; onSelect: (id: string) => void }) {
  return (
    <section className="flex min-h-0 flex-1 flex-col rounded-lg border border-slate-200 bg-white">
      <header className="flex h-11 shrink-0 items-center justify-between border-b border-slate-100 px-4">
        <h2 className="text-sm font-semibold text-slate-800">공격 체인</h2>
        <span className="num text-xs text-slate-400">
          최근 {windowMin}분 · {chains.length}개 컨테이너
        </span>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {chains.length === 0 ? (
          <Empty>이 창에 위반 없음</Empty>
        ) : (
          chains.map(({ container: c, steps }) => (
            <div key={c.id} className="border-t border-slate-100 pt-2 first:border-t-0 first:pt-0">
              <button
                type="button"
                onClick={() => onSelect(c.id)}
                className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-indigo-50 ${selectedId === c.id ? 'bg-indigo-50' : ''}`}
              >
                <span className="font-medium text-slate-800">{c.label}</span>
                <LevelBadge level={c.level} />
              </button>
              <ol className="grid gap-1 py-1">
                {steps.map((st) => (
                  <li key={`${st.kind}:${st.node.id}`}>
                    <button
                      type="button"
                      onClick={() => onSelect(st.node.id)}
                      title={`${st.node.label}\n${st.rules.join(', ')}`}
                      className={`grid w-full grid-cols-[3.25rem_minmax(0,1fr)_auto_auto] items-center gap-2 rounded-md border px-2 py-1 text-left text-xs hover:bg-slate-50 ${
                        selectedId === st.node.id ? 'border-indigo-500 bg-indigo-50' : 'border-transparent'
                      }`}
                    >
                      <span className={`rounded py-0.5 text-center text-[11px] font-semibold ${stepTone[st.kind]}`}>{KIND_STEP[st.kind]}</span>
                      <span className="truncate font-mono text-slate-700">{st.node.label}</span>
                      <span className="max-w-24 truncate text-slate-500">{st.rules[0] ?? ''}</span>
                      <LevelBadge level={st.level} />
                    </button>
                  </li>
                ))}
              </ol>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
