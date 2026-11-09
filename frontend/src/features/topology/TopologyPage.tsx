import {
  Background,
  ControlButton,
  Controls,
  MarkerType,
  Position,
  ReactFlow,
  useOnViewportChange,
  useReactFlow,
  useStore,
  type Edge,
  type Node,
  type NodeMouseHandler,
  type ReactFlowState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Box, Cpu, FileSearch, FileText } from 'lucide-react';
import { startTransition, useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { AttackChain } from '../../components/AttackChain';
import { DecisionBadge } from '../../components/Badges';
import { DecisionBox } from '../../components/DecisionBox';
import { PageActions } from '../../components/PageActions';
import { ScreenHead } from '../../components/ScreenHead';
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
import { attackChains, severity, type Chain, type ContainerTotals, type NodeType, type TopoEdge, type TopoNode } from '../../lib/topology';
import { LEVEL_LABEL, type Case, type Level } from '../../lib/types';

// 3열 고정 레이아웃: 컨테이너 → 프로세스 → 파일/목적지. 위치가 결정적이라 실시간 갱신에도 흔들리지 않는다.
// 엣지 위에는 글자를 두지 않는다(화살표와 겹침) — 종류는 말단 노드의 kind 칩, 횟수는 ×N 으로 보인다. (mock/ 에서 확정한 설계)
// [11/09] 열 사이를 좁혀 전체 너비 850 — 1440 화면의 그래프 칸(약 800)에 0.75배 이상으로 들어간다(옛 980 은 0.76배에 걸림)
const COL_X: Record<NodeType, number> = { container: 0, process: 290, file: 560, dest: 560 };
const ROW_H = 56;
const NODE_W = 220; // 컨테이너
const PROC_W = 190; // 프로세스(comm 은 15자 이하)
const LEAF_W = 290;
// [11/09] 위반 없는 컨테이너는 한 줄로 접는다 — 컨테이너 · 프로세스 두 열 너비. 누르거나 Enter 로 펼치고 다시 누르면 접는다
const FOLD_W = COL_X.process + PROC_W;
// [11/09] 화면 맞춤 하한: 노드 글자 12px × 0.75 = 9px 아래로 줄이지 않는다. 다 안 들어가면 위 · 왼쪽(위험 컨테이너가 위)부터 보이고 나머지는 이동 · 축소로
const READABLE_ZOOM = 0.75;
const MAX_FIT_ZOOM = 1.1;
const FIT_PAD = 24;

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

function NodeLabel({ n, hint }: { n: TopoNode; hint?: string }) {
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
      {hint && <span className="shrink-0 text-xs text-text-3">{hint}</span>}
    </div>
  );
}

const EMPTY_TOTALS: ContainerTotals = { procs: 0, files: 0, connects: 0, queries: 0 };
const foldSummary = (t: ContainerTotals) => `파일 ${fmtNum(t.files)} · 연결 ${fmtNum(t.connects)}${t.queries ? ` · 조회 ${fmtNum(t.queries)}` : ''}`;

// 접힌 컨테이너(위반 없음): 이름 + 「파일 N · 연결 M」 한 줄. 수는 창 안의 전체(정상 말단 상한 전)
function FoldedLabel({ name, t }: { name: string; t: ContainerTotals }) {
  const sum = foldSummary(t);
  return (
    <div className="flex items-center gap-2 text-left" title={`${name}\n위반 없음 · 프로세스 ${t.procs} · ${sum}\n누르면 펼침`}>
      <Box className="size-3.5 shrink-0" aria-hidden />
      <span data-part="fold-name" className="min-w-0 flex-1 truncate font-medium text-text">
        {name}
      </span>
      <span data-part="fold-summary" className="num shrink-0 text-text-3">
        {sum}
      </span>
      <span className="shrink-0 text-xs text-text-3">펼치기</span>
    </div>
  );
}

interface Fold {
  foldable: Set<string>; // 접을 수 있는 컨테이너(위반 없음 · 컨테이너를 고르지 않았을 때)
  folded: Set<string>; // 지금 접힌 컨테이너
  totals: Map<string, ContainerTotals>;
}

function layout(nodes: TopoNode[], edges: TopoEdge[], selectedId: string | null, fold: Fold): { nodes: Node[]; edges: Edge[] } {
  const children = new Map<string, string[]>();
  for (const e of edges) children.set(e.source, [...(children.get(e.source) ?? []), e.target]);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const pos = new Map<string, { x: number; y: number }>();
  let row = 0;
  let prevFolded = false;
  const containers = nodes.filter((n) => n.type === 'container').sort(bySeverity);
  for (const c of containers) {
    // 접힌 컨테이너는 한 줄 — 연속한 접힌 줄 사이에는 여백 줄을 두지 않는다
    if (fold.folded.has(c.id)) {
      pos.set(c.id, { x: COL_X.container, y: row++ * ROW_H });
      prevFolded = true;
      continue;
    }
    if (prevFolded) row += 0.5;
    prevFolded = false;
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

  const border = (n: TopoNode, base: CSSProperties) => ({
    borderWidth: n.id === selectedId ? 2 : 1,
    borderColor: n.id === selectedId ? 'var(--accent)' : base.borderColor,
    borderRadius: 6,
    padding: '6px 10px',
    fontSize: 12,
    boxShadow: 'none',
    cursor: 'pointer',
  });
  const toNode = (n: TopoNode): Node => {
    const base = { id: n.id, position: pos.get(n.id)!, draggable: false, connectable: false, sourcePosition: Position.Right, targetPosition: Position.Left };
    if (fold.folded.has(n.id)) {
      const t = fold.totals.get(n.label) ?? EMPTY_TOTALS;
      return {
        ...base,
        data: { label: <FoldedLabel name={n.label} t={t} />, container: n.container },
        ariaRole: 'button',
        ariaLabel: `${n.label}(위반 없음 · ${foldSummary(t)})`,
        domAttributes: { 'aria-expanded': false, 'data-fold': 'folded' } as Node['domAttributes'],
        style: { ...nodeStyle.normal, background: 'var(--surface-2)', width: FOLD_W, ...border(n, nodeStyle.normal) },
      };
    }
    const open = fold.foldable.has(n.id); // 펼친 정상 컨테이너 — 다시 누르면 접힌다
    return {
      ...base,
      data: { label: <NodeLabel n={n} hint={open ? '접기' : undefined} />, container: n.container },
      ...(open && {
        ariaRole: 'button' as const,
        ariaLabel: `${n.label}(위반 없음)`,
        domAttributes: { 'aria-expanded': true, 'data-fold': 'open' } as Node['domAttributes'],
      }),
      style: { ...nodeStyle[n.level], width: isLeaf(n.type) ? LEAF_W : n.type === 'process' ? PROC_W : NODE_W, ...border(n, nodeStyle[n.level]) },
    };
  };

  return {
    nodes: nodes.filter((n) => pos.has(n.id)).map(toNode),
    edges: edges
      .filter((e) => pos.has(e.source) && pos.has(e.target))
      .map((e) => {
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
  const selected = effectiveId ? (snap.nodes.find((n) => n.id === effectiveId) ?? null) : null;
  const risky = snap.nodes.filter((n) => n.level !== 'normal').length;

  // [11/09] 위반 없는 컨테이너는 접는다 — 사용자가 펼친 것(opened) · 고른 파일 · 목적지가 속한 컨테이너는 펼친다.
  // 컨테이너를 하나 고르면(select) 접지 않는다. 위반이 생기면 level 이 바뀌어 접을 수 있는 목록에서 빠진다(자동으로 펼침)
  const [opened, setOpened] = useState<ReadonlySet<string>>(() => new Set());
  const [foldAct, setFoldAct] = useState<FoldAct | null>(null);
  const fold = useMemo<Fold>(() => {
    const foldable = new Set(container ? [] : snap.nodes.filter((n) => n.type === 'container' && n.level === 'normal').map((n) => n.id));
    const keepOpen = selected && selected.type !== 'container' ? `c:${selected.container}` : null;
    const folded = new Set([...foldable].filter((id) => !opened.has(id) && id !== keepOpen));
    return { foldable, folded, totals: snap.totals };
  }, [snap, container, opened, selected]);
  const graph = useMemo(() => layout(snap.nodes, snap.edges, effectiveId, fold), [snap, effectiveId, fold]);

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
  // 접을 수 있는 컨테이너는 누르면 접기 · 펼치기(상세 패널은 열지 않는다), 그 밖의 노드는 선택(상세 패널)
  const activate = useCallback(
    (id: string) => {
      if (!fold.foldable.has(id)) return toggle(id);
      const name = id.slice(2);
      if (fold.folded.has(id)) {
        setOpened((cur) => new Set(cur).add(id));
        setFoldAct((a) => ({ name, open: true, seq: (a?.seq ?? 0) + 1 }));
        return;
      }
      setOpened((cur) => {
        const next = new Set(cur);
        next.delete(id);
        return next;
      });
      setFoldAct((a) => ({ name, open: false, seq: (a?.seq ?? 0) + 1 }));
      if (selected && selected.type !== 'container' && selected.container === name) setNode(null); // 접는 컨테이너 안의 선택은 푼다
    },
    [fold, toggle, selected, setNode],
  );
  const onNodeClick: NodeMouseHandler = useCallback((_, node) => activate(node.id), [activate]);
  // 노드에 초점을 두고 Enter = 누르기와 같음(React Flow 는 Enter 로 내부 선택만 바꾼다)
  const onGraphKey = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      if (e.key !== 'Enter') return;
      const id = (e.target as HTMLElement).closest<HTMLElement>('.react-flow__node')?.dataset.id;
      if (!id) return;
      e.preventDefault();
      activate(id);
    },
    [activate],
  );

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
    <div className="flex h-full min-h-0 flex-col gap-3">
      <ScreenHead screen="topology" />
    <div data-fill="" className="flex min-h-0 flex-1 gap-4 max-md:flex-col max-md:overflow-y-auto">
      <PageActions>
        <label className="flex items-center gap-1.5 text-sm text-slate-500">
          컨테이너
          <select
            className="h-8 rounded-[var(--r-md)] border border-slate-300 bg-field px-2"
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
            런타임 관계{' '}
            <span className="num ml-1 font-normal text-slate-400">
              노드 {snap.nodes.length} · 위험 {risky}
              {fold.folded.size > 0 && ` · 접힘 ${fold.folded.size}`}
            </span>
          </span>
        }
      >
        <div className="flex h-full flex-col">
          <Legend />
          <div className="relative min-h-0 flex-1" onKeyDown={onGraphKey}>
            {graph.nodes.length === 0 ? (
              <Empty>표시할 활동이 없습니다. 런타임 컨테이너 이벤트가 들어오면 그래프가 그려집니다.</Empty>
            ) : (
              <ReactFlow
                key={container}
                nodes={graph.nodes}
                edges={graph.edges}
                onNodeClick={onNodeClick}
                onPaneClick={() => setNode(null)}
                defaultViewport={{ x: FIT_PAD, y: FIT_PAD, zoom: READABLE_ZOOM }}
                minZoom={0.2}
                nodesDraggable={false}
                nodesConnectable={false}
              >
                <Background color="var(--border-strong)" gap={24} />
                <ReadableFit act={foldAct} />
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
      <span className="text-slate-400">위반 없는 컨테이너는 접힘 · 누르면 펼침</span>
    </div>
  );
}

// 접기 · 펼치기 조작(누른 컨테이너 이름 · 펼쳤는지 · 순번)
interface FoldAct {
  name: string;
  open: boolean;
  seq: number;
}

// 그래프 모양 = 노드 수 · 경계. 모든 노드가 재어졌을 때만 값이 있고 아니면 ''(useNodesInitialized 는 제어 모드에서 사용자 노드에 크기가 안 붙어 늘 false)
const shapeOf = (s: ReactFlowState): string => {
  let [x0, y0, x1, y1] = [Infinity, Infinity, -Infinity, -Infinity];
  for (const n of s.nodeLookup.values()) {
    const { width = 0, height = 0 } = n.measured;
    if (!width || !height) return '';
    const { x, y } = n.internals.positionAbsolute;
    [x0, y0, x1, y1] = [Math.min(x0, x), Math.min(y0, y), Math.max(x1, x + width), Math.max(y1, y + height)];
  }
  return s.nodeLookup.size ? [s.nodeLookup.size, x0, y0, x1, y1].map(Math.round).join(':') : '';
};

// [11/09] 화면 맞춤 — 글자가 읽히는 배율(READABLE_ZOOM) 아래로 줄이지 않는다. 다 들어가면 가운데, 넘치면 위 · 왼쪽부터(위험 컨테이너가 맨 위).
// [11/09 2차] 실시간 이벤트로 그래프가 자라므로 처음 한 번이 아니라, 사용자가 화면을 움직이기 전까지 모양이 바뀔 때마다 다시 맞춘다.
// 이동 · 확대 · 축소 · 접기/펼치기를 하면 멈추고(보던 곳이 튀지 않게), 「화면 맞춤」 버튼은 맞춘 뒤 다시 따라간다. 펼친 묶음은 배율을 두고 화면 안으로 옮긴다
function ReadableFit({ act }: { act: FoldAct | null }) {
  const rf = useReactFlow();
  const shape = useStore(shapeOf);
  const width = useStore((s) => s.width);
  const height = useStore((s) => s.height);
  const follow = useRef(true);
  const fitting = useRef(false);
  // 시점 변경 시작 — 이 컴포넌트의 맞춤이 아니면(끌기 · 휠 · 확대 축소 버튼 · 초점 이동) 사용자 조작
  const onStart = useCallback(() => {
    if (!fitting.current) follow.current = false;
  }, []);
  useOnViewportChange({ onStart });

  const fit = useCallback(() => {
    const nodes = rf.getNodes();
    if (!nodes.length || !width || !height) return;
    const b = rf.getNodesBounds(nodes);
    const w = width - 2 * FIT_PAD;
    const h = height - 2 * FIT_PAD;
    const zoom = Math.min(MAX_FIT_ZOOM, Math.max(READABLE_ZOOM, Math.min(w / b.width, h / b.height)));
    const x = b.width * zoom <= w ? (width - b.width * zoom) / 2 - b.x * zoom : FIT_PAD - b.x * zoom;
    const y = b.height * zoom <= h ? (height - b.height * zoom) / 2 - b.y * zoom : FIT_PAD - b.y * zoom;
    fitting.current = true; // 시간 0 의 setViewport 는 시작 이벤트를 이 안에서 바로 낸다
    void rf.setViewport({ x, y, zoom });
    fitting.current = false;
  }, [rf, width, height]);

  // 접기 · 펼치기 = 사용자 조작. 이 그래프(컨테이너를 바꾸면 새로 만든다)를 만들기 전의 조작은 무시
  const lastAct = useRef(act?.seq ?? 0);
  const reveal = useRef<string | null>(null);
  useEffect(() => {
    if (!act || act.seq === lastAct.current) return;
    lastAct.current = act.seq;
    follow.current = false;
    reveal.current = act.open ? act.name : null;
  }, [act]);

  // 모양이 바뀌면(모든 노드가 재어진 뒤): 따라가는 중이면 다시 맞춤, 아니면 방금 펼친 묶음만 화면 안으로
  useEffect(() => {
    if (!shape || !width || !height) return;
    if (follow.current) {
      fit();
      return;
    }
    const name = reveal.current;
    if (!name) return;
    const mine = rf.getNodes().filter((n) => (n.data as { container?: string }).container === name);
    if (mine.length < 2) return; // 펼친 노드가 아직 안 들어옴 — 다음 모양에서
    reveal.current = null;
    const vp = rf.getViewport();
    const b = rf.getNodesBounds(mine);
    const nudge = (start: number, end: number, view: number) => {
      if (end > view - FIT_PAD) return Math.max(view - FIT_PAD - end, FIT_PAD - start);
      return start < FIT_PAD ? FIT_PAD - start : 0;
    };
    const dx = nudge(vp.x + b.x * vp.zoom, vp.x + (b.x + b.width) * vp.zoom, width);
    const dy = nudge(vp.y + b.y * vp.zoom, vp.y + (b.y + b.height) * vp.zoom, height);
    if (!dx && !dy) return;
    const still = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    void rf.setViewport({ x: vp.x + dx, y: vp.y + dy, zoom: vp.zoom }, { duration: still ? 0 : 200 });
  }, [shape, width, height, fit, rf]);

  return (
    <Controls showInteractive={false} showFitView={false}>
      <ControlButton
        className="react-flow__controls-fitview"
        onClick={() => {
          follow.current = true;
          fit();
        }}
        title="화면 맞춤"
        aria-label="화면 맞춤"
      >
        <FitGlyph />
      </ControlButton>
    </Controls>
  );
}

// React Flow 기본 「화면 맞춤」 버튼과 같은 모양(그 버튼을 같은 자리에서 대신한다 — 패키지가 아이콘을 내보내지 않음)
function FitGlyph() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 30" aria-hidden>
      <path d="M3.692 4.63c0-.53.4-.938.939-.938h5.215V0H4.708C2.13 0 0 2.054 0 4.63v5.216h3.692V4.631zM27.354 0h-5.2v3.692h5.17c.53 0 .984.4.984.939v5.215H32V4.631A4.624 4.624 0 0027.354 0zm.954 24.83c0 .532-.4.94-.939.94h-5.215v3.768h5.215c2.577 0 4.631-2.13 4.631-4.707v-5.139h-3.692v5.139zm-23.677.94c-.531 0-.939-.4-.939-.94v-5.138H0v5.139c0 2.577 2.13 4.707 4.708 4.707h5.138V25.77H4.631z" />
    </svg>
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
          <Empty>최근 {windowMin}분 동안 위반이 없습니다.</Empty>
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
