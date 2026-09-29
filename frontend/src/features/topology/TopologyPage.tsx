import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Box, Cpu, FileText, Globe } from 'lucide-react';
import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Empty, Panel } from '../../components/Panel';
import { useStream } from '../../hooks/stream-context';
import type { NodeType, TopoEdge, TopoNode } from '../../lib/topology';
import type { Level } from '../../lib/types';

const COL_X: Record<NodeType, number> = { container: 0, process: 280, file: 580, dest: 580 };
const ROW_H = 52;
const NODE_W = 230;

// React Flow 기본 노드 스타일을 이기도록 색은 인라인 style로 준다
const nodeStyle: Record<Level, CSSProperties> = {
  normal: { background: '#ffffff', borderColor: '#cbd5e1', color: '#334155' },
  alert: { background: '#fffbeb', borderColor: '#f59e0b', color: '#78350f' },
  held: { background: '#fef2f2', borderColor: '#f87171', color: '#991b1b', borderStyle: 'dashed' },
  killed: { background: '#dc2626', borderColor: '#b91c1c', color: '#ffffff' },
};
const edgeColor: Record<Level, string> = { normal: '#cbd5e1', alert: '#f59e0b', held: '#ef4444', killed: '#dc2626' };
const icons = { container: Box, process: Cpu, file: FileText, dest: Globe };

// 컨테이너 → 프로세스 → 파일/목적지 3열 레이아웃. 위치가 결정적이라 실시간 갱신에도 흔들리지 않는다.
function layout(nodes: TopoNode[], edges: TopoEdge[]): { nodes: Node[]; edges: Edge[] } {
  const children = new Map<string, string[]>();
  for (const e of edges) children.set(e.source, [...(children.get(e.source) ?? []), e.target]);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const pos = new Map<string, { x: number; y: number }>();
  let row = 0;
  const containers = nodes.filter((n) => n.type === 'container').sort((a, b) => a.label.localeCompare(b.label));
  for (const c of containers) {
    const start = row;
    const procs = (children.get(c.id) ?? []).map((id) => byId.get(id)).filter((n): n is TopoNode => !!n);
    procs.sort((a, b) => a.label.localeCompare(b.label));
    for (const p of procs) {
      const pStart = row;
      const leaves = (children.get(p.id) ?? []).map((id) => byId.get(id)).filter((n): n is TopoNode => !!n);
      leaves.sort((a, b) => (a.level === b.level ? a.label.localeCompare(b.label) : a.level === 'normal' ? 1 : -1));
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
      .map((n) => {
        const Icon = icons[n.type];
        return {
          id: n.id,
          position: pos.get(n.id)!,
          draggable: false,
          connectable: false,
          data: {
            label: (
              <div className="flex items-center gap-2 text-left" title={`${n.label} · ${n.count}회`}>
                <Icon className="size-3.5 shrink-0" aria-hidden />
                <span className={`truncate ${n.type === 'file' || n.type === 'dest' ? 'font-mono text-[11px]' : 'font-medium'}`}>
                  {n.label}
                </span>
              </div>
            ),
          },
          style: { ...nodeStyle[n.level], width: NODE_W, borderWidth: 1, borderRadius: 6, padding: '6px 10px', fontSize: 12, boxShadow: 'none' },
          sourcePosition: 'right',
          targetPosition: 'left',
        } as Node;
      }),
    edges: edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.kind === 'exec' ? undefined : e.kind,
      labelStyle: { fontSize: 10, fill: '#64748b' },
      animated: e.level !== 'normal',
      style: { stroke: edgeColor[e.level], strokeWidth: e.level === 'normal' ? 1 : 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor[e.level] },
    })),
  };
}

const WINDOWS = [1, 5, 15];

export function TopologyPage() {
  const { topology } = useStream();
  const [params, setParams] = useSearchParams();
  const container = params.get('container') ?? '';
  const [windowMin, setWindowMin] = useState(5);
  const [tick, setTick] = useState(0);

  // 스트림은 250ms마다 갱신되지만 그래프는 1초마다 다시 그린다
  useEffect(() => {
    const t = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, []);

  const graph = useMemo(() => {
    const snap = topology.snapshot(windowMin * 60_000, container || undefined);
    const risky = snap.nodes.filter((n) => n.level !== 'normal').length;
    return { ...layout(snap.nodes, snap.edges), containers: topology.containers(), risky, tick };
  }, [topology, windowMin, container, tick]);

  const risky = graph.risky;

  return (
    <Panel
      className="h-full min-h-[560px]"
      title={
        <span>
          보안 토폴로지 <span className="num ml-1 font-normal text-slate-400">노드 {graph.nodes.length} · 위험 {risky}</span>
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
            }}
          >
            <option value="">모든 컨테이너</option>
            {graph.containers.map((c) => (
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
      {graph.nodes.length === 0 ? (
        <Empty>표시할 활동 없음 — 이벤트가 들어오면 그래프가 그려집니다</Empty>
      ) : (
        <div className="relative h-full">
          <ReactFlow
            key={container}
            nodes={graph.nodes}
            edges={graph.edges}
            fitView
            fitViewOptions={{ padding: 0.15, maxZoom: 1.1 }}
            minZoom={0.2}
            nodesDraggable={false}
            nodesConnectable={false}
          >
            <Background color="#e2e8f0" gap={24} />
            <Controls showInteractive={false} />
          </ReactFlow>
          <Legend />
        </div>
      )}
    </Panel>
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
    <div className="absolute top-3 right-3 flex gap-3 rounded-md border border-slate-200 bg-white/90 px-3 py-1.5 text-xs text-slate-600">
      {items.map(([l, label]) => (
        <span key={l} className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm border" style={nodeStyle[l]} />
          {label}
        </span>
      ))}
    </div>
  );
}
