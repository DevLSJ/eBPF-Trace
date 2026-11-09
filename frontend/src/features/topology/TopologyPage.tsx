import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node, type NodeMouseHandler } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Box, Cpu, FileSearch, FileText } from 'lucide-react';
import { startTransition, useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { AttackChain } from '../../components/AttackChain';
import { DecisionBadge } from '../../components/Badges';
import { DecisionBox } from '../../components/DecisionBox';
import { PageActions } from '../../components/PageActions';
import { Empty, Panel } from '../../components/Panel';
import { Section, Sheet } from '../../components/Sheet';
import { TimelineBar } from '../../components/TimelineBar';
import { LevelBadge } from '../../components/VerdictBadge';
import { useCases } from '../../hooks/cases-context';
import { useStream } from '../../hooks/stream-context';
import { useFilters } from '../../hooks/useFilters';
import { evidenceDest } from '../../lib/evidence';
import { fmtNum, fmtTime } from '../../lib/format';
import { dest } from '../../lib/nav';
import { attackChains, severity, type Chain, type NodeType, type TopoEdge, type TopoNode } from '../../lib/topology';
import { LEVEL_LABEL, type Case, type Level } from '../../lib/types';

// 3열 고정 레이아웃: 컨테이너 → 프로세스 → 파일/목적지. 위치가 결정적이라 실시간 갱신에도 흔들리지 않는다.
// 엣지 위에는 글자를 두지 않는다(화살표와 겹침) — 종류는 말단 노드의 kind 칩, 횟수는 ×N 으로 보인다. (mock/ 에서 확정한 설계)
const COL_X: Record<NodeType, number> = { container: 0, process: 330, file: 690, dest: 690 };
const ROW_H = 56;
const NODE_W = 240;
const LEAF_W = 290;

// React Flow 기본 노드 스타일을 이기도록 색은 인라인 style로 준다 — 값은 토큰(10/30, 다크 모드도 따라온다)
const nodeStyle: Record<Level, CSSProperties> = {
  normal: { background: 'var(--surface)', borderColor: 'var(--border-strong)', color: 'var(--text-2)' },
  alert: { background: 'var(--warn-soft)', borderColor: 'var(--warn)', color: 'var(--warn-text)' },
  held: { background: 'var(--danger-soft)', borderColor: 'var(--danger)', color: 'var(--danger-text)', borderStyle: 'dashed' },
  killed: { background: 'var(--danger)', borderColor: 'var(--danger)', color: 'var(--text-inverse)' },
};
const edgeColor: Record<Level, string> = { normal: 'var(--border-strong)', alert: 'var(--warn)', held: 'var(--danger)', killed: 'var(--danger)' };
const chipStyle: Record<'open' | 'connect' | 'dns', string> = { open: 'bg-sky-100 text-sky-800', connect: 'bg-teal-100 text-teal-800', dns: 'bg-amber-100 text-amber-900' };
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

// 말단 노드 칩: 파일 open · 목적지 connect · 질의 이름 dns(10/30)
const leafKind = (n: TopoNode): 'open' | 'connect' | 'dns' => (n.type === 'file' ? 'open' : n.kind === 'dns' ? 'dns' : 'connect');

function NodeLabel({ n }: { n: TopoNode }) {
  const chipTone = n.level === 'killed' ? 'bg-white/25 text-white' : undefined;
  return (
    <div className="flex items-center gap-2 text-left" title={`${n.label}\n${n.count}회${n.violations ? ` · 위반 ${n.violations}` : ''}${n.reason ? `\n${n.reason}` : ''}`}>
      {isLeaf(n.type) ? (
        <span className={`w-14 shrink-0 rounded px-1 text-center font-mono text-xs font-semibold ${chipTone ?? chipStyle[leafKind(n)]}`}>
          {leafKind(n)}
        </span>
      ) : n.type === 'container' ? (
        <Box className="size-3.5 shrink-0" aria-hidden />
      ) : (
        <Cpu className="size-3.5 shrink-0" aria-hidden />
      )}
      <span className={`min-w-0 flex-1 truncate ${isLeaf(n.type) ? 'font-mono text-xs' : 'font-medium'}`}>
        {isLeaf(n.type) ? ellipsize(n.label, 30) : n.label}
      </span>
      {n.type === 'container' && n.level !== 'normal' && (
        <span className={`shrink-0 rounded-full px-2 text-xs font-semibold ${statusChip[n.level]}`}>{LEVEL_LABEL[n.level]}</span>
      )}
      {n.count > 1 && <span className="num shrink-0 font-mono text-xs opacity-75">×{fmtNum(n.count)}</span>}
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
              borderColor: n.id === selectedId ? 'var(--accent)' : nodeStyle[n.level].borderColor,
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
const TYPE_LABEL: Record<NodeType, string> = { container: '컨테이너', process: '프로세스', file: '파일', dest: '외부 목적지' };

// 토폴로지 — 질문 하나: 「이 컨테이너는 어디까지 손댔나?」 런타임 컨테이너만(sg-install-* 제외)
export function TopologyPage() {
  const { topology } = useStream();
  const { cases } = useCases();
  // 컨테이너 필터는 화면 상태로만. 노드는 컨테이너 노드(c:)만 링크로 주소에, 파일 · 도메인 · IP · 프로세스 노드는 화면 상태로만(10/21)
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useFilters('/topology');
  const { container } = filters;
  const urlNode = params.get('node');
  const selectedId = (urlNode?.startsWith('c:') ? urlNode : null) || filters.node || null;
  const [windowMin, setWindowMin] = useState(5);
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
  const effectiveId = selectedId && snap.nodes.some((n) => n.id === selectedId) ? selectedId : null;
  const graph = useMemo(() => layout(snap.nodes, snap.edges, effectiveId), [snap, effectiveId]);
  const selected = effectiveId ? (snap.nodes.find((n) => n.id === effectiveId) ?? null) : null;
  const risky = snap.nodes.filter((n) => n.level !== 'normal').length;

  const setNode = useCallback(
    (id: string | null) => {
      const link = !!id && id.startsWith('c:');
      startTransition(() => setFilters({ node: link ? '' : (id ?? '') })); // 주소 변경과 한 번에 그린다
      setParams(
        (cur) => {
          const next = new URLSearchParams(cur);
          if (link) next.set('node', id);
          else next.delete('node');
          return next;
        },
        { replace: true },
      );
    },
    [setParams, setFilters],
  );
  const toggle = useCallback((id: string) => setNode(id === selectedId ? null : id), [setNode, selectedId]);
  const onNodeClick: NodeMouseHandler = useCallback((_, node) => toggle(node.id), [toggle]);

  // 런타임 건: 컨테이너 이름 → 아직 닫히지 않은 건(없으면 가장 최근 건)
  const caseFor = useCallback(
    (name: string): Case | undefined => {
      const mine = (cases ?? []).filter((c) => c.source === 'runtime' && c.container === name).sort((a, b) => b.openedAt.localeCompare(a.openedAt));
      return mine.find((c) => c.state !== 'closed') ?? mine[0];
    },
    [cases],
  );
  const selectedContainer = selected ? selected.container : null;
  const selectedCase = selectedContainer ? caseFor(selectedContainer) : undefined;

  return (
    <div data-fill="" className="flex h-full min-h-0 gap-4 max-md:flex-col max-md:overflow-y-auto">
      <PageActions>
        <label className="flex items-center gap-1.5 text-sm text-slate-500">
          컨테이너
          <select
            className="h-8 rounded-[var(--r-md)] border border-slate-300 bg-field px-2 text-sm"
            value={container}
            onChange={(e) => {
              setFilters({ container: e.target.value });
              setNode(null);
            }}
          >
            <option value="">모든 런타임 컨테이너</option>
            {snap.containers.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-500">
          최근
          <input
            type="range"
            min={0}
            max={WINDOWS.length - 1}
            value={WINDOWS.indexOf(windowMin)}
            onChange={(e) => setWindowMin(WINDOWS[Number(e.target.value)])}
            className="w-24 accent-indigo-600"
            aria-valuetext={`${windowMin}분`}
          />
          <span className="num w-10 text-slate-700">{windowMin}분</span>
        </label>
      </PageActions>
      <Panel
        className="min-w-0 flex-1 max-md:min-h-[22rem] max-md:shrink-0"
        testId="topology"
        title={
          <span>
            런타임 관계 <span className="num ml-1 font-normal text-slate-400">노드 {snap.nodes.length} · 위험 {risky}</span>
          </span>
        }
      >
        <div className="flex h-full flex-col">
          <Legend />
          <div className="relative min-h-0 flex-1">
            {graph.nodes.length === 0 ? (
              <Empty>표시할 활동 없음 — 런타임 컨테이너 이벤트가 들어오면 그래프가 그려집니다</Empty>
            ) : (
              <ReactFlow
                key={container}
                nodes={graph.nodes}
                edges={graph.edges}
                onNodeClick={onNodeClick}
                onPaneClick={() => setNode(null)}
                fitView
                fitViewOptions={{ padding: 0.12, maxZoom: 1.1 }}
                minZoom={0.2}
                nodesDraggable={false}
                nodesConnectable={false}
              >
                <Background color="var(--border-strong)" gap={24} />
                <Controls showInteractive={false} />
              </ReactFlow>
            )}
          </div>
        </div>
      </Panel>

      {/* [11/05] 고른 노드 · 판정은 슬라이드 패널(720) — 오른쪽 칸에는 공격 체인만 */}
      {selected && (
        <Sheet kind="topo" title={`${TYPE_LABEL[selected.type]} · ${selected.label}`} onClose={() => setNode(null)}>
          {selectedCase && (selected.type === 'container' || selectedCase.state !== 'closed') && (
            <Section title={<>판정 · {selectedCase.container} {selectedCase.decision === 'pending' && <DecisionBadge decision="pending" />}</>} testId="topology-decision">
              <div>
                <DecisionBox caseId={selectedCase.id} />
                {/* 격리 타임라인(10/30) — 런타임 격리 건 */}
                {selectedCase.isolation?.timeline && (
                  <div className="mt-3">
                    <TimelineBar timeline={selectedCase.isolation.timeline} />
                  </div>
                )}
                <div className="mt-2 flex flex-wrap gap-3">
                  {selectedCase.level === 'killed' && (
                    <Link {...evidenceDest(selectedCase.container)} className="inline-flex items-center gap-1.5 text-xs text-accent-text hover:underline">
                      <FileSearch className="size-3.5" aria-hidden /> 증거 보기
                    </Link>
                  )}
                  <Link to={`/report?case=${encodeURIComponent(selectedCase.id)}`} data-action="report" className="inline-flex items-center gap-1.5 text-xs text-accent-text hover:underline">
                    <FileText className="size-3.5" aria-hidden /> 보고서
                  </Link>
                </div>
              </div>
            </Section>
          )}
          <NodeDetail n={selected} />
        </Sheet>
      )}
      <aside className="flex min-h-0 shrink-0 flex-col gap-4 max-md:w-full md:w-[340px]">
        <ChainPanel chains={snap.chains} windowMin={windowMin} selectedId={effectiveId} onSelect={toggle} caseFor={caseFor} />
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

function NodeDetail({ n }: { n: TopoNode }) {
  const rules = [...n.rules.entries()].sort((a, b) => b[1] - a[1]);
  return (
    <Section title="선택한 노드" testId="node-detail">
      <div>
      <dl className="grid grid-cols-[4rem_1fr] gap-x-2.5 gap-y-1 text-[13px]">
        <dt className="text-slate-500">종류</dt>
        <dd>{TYPE_LABEL[n.type]}</dd>
        <dt className="text-slate-500">이름</dt>
        <dd className={`break-all ${isLeaf(n.type) ? 'font-mono text-xs' : ''}`}>{n.label}</dd>
        <dt className="text-slate-500">컨테이너</dt>
        <dd>{n.container}</dd>
        <dt className="text-slate-500">탐지 결과</dt>
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
          <h4 className="text-[13px] font-semibold text-text-2">걸린 규칙</h4>
          <ul className="mt-1.5 flex flex-wrap gap-1.5">
            {rules.map(([id, cnt]) => (
              <li key={id}>
                <Link to={`/policies?id=${encodeURIComponent(id)}`} className="rounded-full bg-indigo-50 px-2 py-0.5 font-mono text-xs text-accent-text hover:underline">
                  {id} ×{cnt}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
      {n.reason && <p className="mt-2 text-xs text-slate-500">{n.reason}</p>}
      <Link
        {...dest('/events', { container: n.container, normal: n.level === 'normal' ? '1' : '' })}
        className="mt-3 inline-block rounded-md px-2 py-1 text-xs text-indigo-600 hover:bg-indigo-50"
      >
        이벤트에서 보기 →
      </Link>
      </div>
    </Section>
  );
}

// 공격 체인: 컨테이너별 위반 노드를 1 실행 → 2 파일 → 3 통신 순서로. 설치 검사 시트와 같은 부품(AttackChain). 누르면 그래프에서 강조.
function ChainPanel({
  chains,
  windowMin,
  selectedId,
  onSelect,
  caseFor,
}: {
  chains: Chain[];
  windowMin: number;
  selectedId: string | null;
  onSelect: (id: string) => void;
  caseFor: (name: string) => Case | undefined;
}) {
  return (
    <section className="sg-card flex min-h-0 flex-1 flex-col overflow-hidden" data-testid="chains">
      <header className="flex h-11 shrink-0 items-center justify-between border-b border-border px-4">
        <h2 className="text-sm font-semibold text-slate-800">공격 체인</h2>
        <span className="num text-xs text-slate-400">
          최근 {windowMin}분 · {chains.length}개 컨테이너
        </span>
      </header>
      <div data-fill="" className="min-h-0 flex-1 overflow-y-auto p-3">
        {chains.length === 0 ? (
          <Empty>이 창에 위반 없음</Empty>
        ) : (
          chains.map(({ container: c, steps }) => {
            const k = caseFor(c.label);
            return (
              <div key={c.id} className="border-t border-slate-100 pt-2 first:border-t-0 first:pt-0" data-chain={c.label}>
                <button
                  type="button"
                  onClick={() => onSelect(c.id)}
                  className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-indigo-50 ${selectedId === c.id ? 'bg-indigo-50' : ''}`}
                >
                  <span className="min-w-0 flex-1 truncate font-medium text-slate-800">{c.label}</span>
                  {k && <DecisionBadge decision={k.decision} />}
                  <LevelBadge level={c.level} />
                </button>
                <div className="py-1">
                  <AttackChain
                    steps={steps.map((st) => ({ id: st.node.id, kind: st.kind, label: st.node.label, rule: st.rules[0], level: st.level }))}
                    selectedId={selectedId}
                    onSelect={onSelect}
                  />
                </div>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
