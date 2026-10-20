import { levelOf, type Kind, type Level, type Verdict } from './types';

// 토폴로지: 컨테이너 → 프로세스 → (파일 | 외부 목적지)
export type NodeType = 'container' | 'process' | 'file' | 'dest';

// 노드·엣지가 공유하는 누적치. 위반은 kind 별로도 따로 기록해 "공격 체인"(1 exec → 2 open → 3 connect)을 만든다.
export interface TopoStats {
  level: Level; // 이 노드/엣지가 유발한 가장 심각한 판정
  count: number;
  violations: number;
  lastSeen: number;
  rules: Map<string, number>; // 규칙 id → 위반 횟수
  ruleKinds: Map<string, Kind>; // 규칙 id → 그 규칙의 kind
  byKind: Partial<Record<Kind, Level>>; // kind 별 최악 판정
  reason?: string; // 가장 심각한 위반의 사유
  lastViolation?: number;
}

export interface TopoNode extends TopoStats {
  id: string;
  type: NodeType;
  label: string;
  container: string;
}

export interface TopoEdge extends TopoStats {
  id: string;
  source: string;
  target: string;
  kind: Kind;
}

const RETAIN_MS = 15 * 60_000;
const MAX_NORMAL_LEAVES = 6; // 컨테이너당 정상 파일/목적지 노드 상한 (위험 노드는 전부 표시)

export const isInstallContainer = (name: string) => name.startsWith('sg-install-');

export const severity: Record<Level, number> = { normal: 0, alert: 1, held: 2, killed: 3 };
const worse = (a: Level, b: Level) => (severity[b] > severity[a] ? b : a);

const blank = (now: number): TopoStats => ({
  level: 'normal', count: 0, violations: 0, lastSeen: now, rules: new Map(), ruleKinds: new Map(), byKind: {},
});

export class TopologyStore {
  private nodes = new Map<string, TopoNode>();
  private edges = new Map<string, TopoEdge>();

  ingest(v: Verdict) {
    const e = v.event;
    // 토폴로지는 런타임 컨테이너만 — 설치 검사 컨테이너(sg-install-*)는 「설치 검사」 화면이 다룬다
    if (!e.containerName || isInstallContainer(e.containerName)) return;
    const now = new Date(e.timestamp).getTime() || Date.now();
    const c = this.touch(`c:${e.containerName}`, 'container', e.containerName, e.containerName, now, v);
    const p = this.touch(`p:${e.containerName}:${e.comm}`, 'process', e.comm, e.containerName, now, v);
    this.link(c.id, p.id, 'exec', now, v);
    if (e.kind === 'open' && e.path) {
      const f = this.touch(`f:${e.containerName}:${e.path}`, 'file', e.path, e.containerName, now, v);
      this.link(p.id, f.id, 'open', now, v);
    } else if (e.kind === 'connect') {
      // 목적지 노드는 IP:포트 단위로 모으고, 도메인을 알면 라벨을 "host:port" 로 보인다
      const key = `${e.dstIp}:${e.dstPort}`;
      const dst = e.dstHost ? `${e.dstHost}:${e.dstPort}` : key;
      const d = this.touch(`d:${e.containerName}:${key}`, 'dest', dst, e.containerName, now, v);
      if (e.dstHost) d.label = dst;
      this.link(p.id, d.id, 'connect', now, v);
    }
  }

  private mark(x: TopoStats, now: number, v: Verdict) {
    const level = levelOf(v);
    x.count++;
    x.level = worse(x.level, level);
    x.lastSeen = Math.max(x.lastSeen, now);
    if (!v.matched || !v.ruleId) return;
    const k = v.event.kind;
    x.violations++;
    x.rules.set(v.ruleId, (x.rules.get(v.ruleId) ?? 0) + 1);
    x.ruleKinds.set(v.ruleId, k);
    x.byKind[k] = worse(x.byKind[k] ?? 'normal', level);
    if (severity[level] >= severity[x.level] || x.reason === undefined) {
      x.reason = v.reason;
      x.lastViolation = now;
    }
  }

  private touch(id: string, type: NodeType, label: string, container: string, now: number, v: Verdict) {
    let n = this.nodes.get(id);
    if (!n) {
      n = { id, type, label, container, ...blank(now) };
      this.nodes.set(id, n);
    }
    this.mark(n, now, v);
    return n;
  }

  private link(source: string, target: string, kind: Kind, now: number, v: Verdict) {
    const id = `${source}->${target}`;
    let ed = this.edges.get(id);
    if (!ed) {
      ed = { id, source, target, kind, ...blank(now) };
      this.edges.set(id, ed);
    }
    this.mark(ed, now, v);
  }

  // windowMs 안에 보인 노드만, 컨테이너별 정상 말단 노드는 상한까지
  snapshot(windowMs: number, container?: string): { nodes: TopoNode[]; edges: TopoEdge[] } {
    const now = Date.now();
    this.prune(now);
    const cut = now - windowMs;
    const leavesPer = new Map<string, TopoNode[]>();
    const keep = new Set<string>();
    for (const n of this.nodes.values()) {
      if (n.lastSeen < cut || (container && n.container !== container)) continue;
      if ((n.type === 'file' || n.type === 'dest') && n.level === 'normal') {
        const arr = leavesPer.get(n.container) ?? [];
        arr.push(n);
        leavesPer.set(n.container, arr);
        continue;
      }
      keep.add(n.id);
    }
    for (const arr of leavesPer.values()) {
      arr.sort((a, b) => b.count - a.count);
      arr.slice(0, MAX_NORMAL_LEAVES).forEach((n) => keep.add(n.id));
    }
    const edges = [...this.edges.values()].filter(
      (e) => e.lastSeen >= cut && keep.has(e.source) && keep.has(e.target),
    );
    // 연결이 모두 잘린 프로세스 노드는 숨긴다
    const linked = new Set(edges.flatMap((e) => [e.source, e.target]));
    const nodes = [...keep]
      .map((id) => this.nodes.get(id)!)
      .filter((n) => n.type === 'container' || linked.has(n.id));
    return { nodes, edges };
  }

  containers(): string[] {
    return [...this.nodes.values()].filter((n) => n.type === 'container').map((n) => n.label).sort();
  }

  private prune(now: number) {
    for (const [id, n] of this.nodes) if (now - n.lastSeen > RETAIN_MS) this.nodes.delete(id);
    for (const [id, e] of this.edges) if (now - e.lastSeen > RETAIN_MS) this.edges.delete(id);
  }
}

// 공격 체인: 컨테이너별로 위반을 일으킨 노드를 데모 시나리오 순서로 — 1 실행(exec) → 2 파일(open) → 3 통신(connect)
export interface ChainStep {
  kind: Kind;
  node: TopoNode;
  level: Level;
  rules: string[];
  at: number;
}
export interface Chain {
  container: TopoNode;
  steps: ChainStep[];
}

const KIND_ORDER: Record<Kind, number> = { exec: 1, open: 2, connect: 3 };

const BLOCKED_IMAGE = 'blocked-image';

export function attackChains(nodes: TopoNode[]): Chain[] {
  const step = (kind: Kind, node: TopoNode): ChainStep => ({
    kind,
    node,
    level: node.byKind[kind] ?? 'normal',
    rules: [...node.rules.entries()]
      .filter(([id]) => node.ruleKinds.get(id) === kind && id !== BLOCKED_IMAGE)
      .sort((a, b) => b[1] - a[1])
      .map(([id]) => id),
    at: node.lastViolation ?? node.lastSeen,
  });
  const out: Chain[] = [];
  const containers = nodes.filter((n) => n.type === 'container').sort((a, b) => severity[b.level] - severity[a.level]);
  for (const c of containers) {
    const steps: ChainStep[] = [];
    for (const n of nodes) {
      if (n.container !== c.label) continue;
      // 차단 이미지 재기동(blocked-image)은 공격 행동이 아니라 기동 즉시 격리 — 체인 단계 · 규칙에서 뺀다 (10/16 sg-vm 실측)
      if (n.type === 'process' && n.byKind.exec) {
        const s = step('exec', n);
        if (s.rules.length || !n.rules.has(BLOCKED_IMAGE)) steps.push(s);
      }
      if (n.type === 'file' && n.byKind.open) steps.push(step('open', n));
      if (n.type === 'dest' && n.byKind.connect) steps.push(step('connect', n));
    }
    if (!steps.length) continue;
    steps.sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || severity[b.level] - severity[a.level] || a.at - b.at);
    out.push({ container: c, steps });
  }
  return out;
}
