import { detailOf, levelOf, type Level, type Verdict } from './types';

// 토폴로지: 컨테이너 → 프로세스 → (파일 | 외부 목적지)
export type NodeType = 'container' | 'process' | 'file' | 'dest';

export interface TopoNode {
  id: string;
  type: NodeType;
  label: string;
  container: string;
  level: Level; // 이 노드가 유발한 가장 심각한 판정
  count: number;
  lastSeen: number;
}

export interface TopoEdge {
  id: string;
  source: string;
  target: string;
  kind: 'exec' | 'open' | 'connect';
  level: Level;
  count: number;
  lastSeen: number;
}

const RETAIN_MS = 15 * 60_000;
const MAX_NORMAL_LEAVES = 6; // 컨테이너당 정상 파일/목적지 노드 상한 (위험 노드는 전부 표시)

const severity: Record<Level, number> = { normal: 0, alert: 1, held: 2, killed: 3 };
const worse = (a: Level, b: Level) => (severity[b] > severity[a] ? b : a);

export class TopologyStore {
  private nodes = new Map<string, TopoNode>();
  private edges = new Map<string, TopoEdge>();

  ingest(v: Verdict) {
    const e = v.event;
    if (!e.containerName) return;
    const now = new Date(e.timestamp).getTime() || Date.now();
    const level = levelOf(v);
    const c = this.touch(`c:${e.containerName}`, 'container', e.containerName, e.containerName, level, now);
    const p = this.touch(`p:${e.containerName}:${e.comm}`, 'process', e.comm, e.containerName, level, now);
    this.link(c.id, p.id, 'exec', level, now);
    if (e.kind === 'open' && e.path) {
      const f = this.touch(`f:${e.containerName}:${e.path}`, 'file', e.path, e.containerName, level, now);
      this.link(p.id, f.id, 'open', level, now);
    } else if (e.kind === 'connect') {
      const dst = detailOf(e);
      const d = this.touch(`d:${e.containerName}:${dst}`, 'dest', dst, e.containerName, level, now);
      this.link(p.id, d.id, 'connect', level, now);
    }
  }

  private touch(id: string, type: NodeType, label: string, container: string, level: Level, now: number) {
    let n = this.nodes.get(id);
    if (!n) {
      n = { id, type, label, container, level, count: 0, lastSeen: now };
      this.nodes.set(id, n);
    }
    n.count++;
    n.level = worse(n.level, level);
    n.lastSeen = Math.max(n.lastSeen, now);
    return n;
  }

  private link(source: string, target: string, kind: TopoEdge['kind'], level: Level, now: number) {
    const id = `${source}->${target}`;
    let ed = this.edges.get(id);
    if (!ed) {
      ed = { id, source, target, kind, level, count: 0, lastSeen: now };
      this.edges.set(id, ed);
    }
    ed.count++;
    ed.level = worse(ed.level, level);
    ed.lastSeen = Math.max(ed.lastSeen, now);
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
