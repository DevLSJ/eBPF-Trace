// 런타임 축 조회·집계 (docs/13 §4, §9). 이벤트 원장 → 인시던트 집계, 토폴로지, 요약.
import { pool } from '../db/pool.js';
import type { RiskLevel, RuntimeIncident, RuntimeRuleId, SbomComponent } from '@scw/shared-types';

const RISK_RANK = `CASE risk_level WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END`;
const SCORE: Record<RiskLevel, number> = { HIGH: 92, MEDIUM: 55, LOW: 10 };

interface IncidentRow {
  incident_key: string;
  container: string;
  image: string | null;
  risk_level: RiskLevel;
  rules: string[];
  purl: string | null;
  commit_sha: string | null;
  first_at: string;
  last_at: string;
  event_count: string;
  blocked: boolean;
}

function toIncident(r: IncidentRow): RuntimeIncident {
  return {
    incidentKey: r.incident_key,
    container: r.container,
    image: r.image ?? undefined,
    riskLevel: r.risk_level,
    score: SCORE[r.risk_level],
    rules: r.rules as RuntimeRuleId[],
    purl: r.purl ?? undefined,
    commitSha: r.commit_sha ?? undefined,
    blocked: r.blocked,
    firstAt: r.first_at,
    lastAt: r.last_at,
    eventCount: Number(r.event_count),
  };
}

const INCIDENT_SELECT = `
  SELECT e.incident_key,
         e.container,
         max(e.image)                                   AS image,
         (array_agg(e.risk_level ORDER BY ${RISK_RANK} DESC))[1] AS risk_level,
         array_agg(DISTINCT e.rule_id)                  AS rules,
         max(e.purl)                                    AS purl,
         max(e.commit_sha)                              AS commit_sha,
         min(e.created_at)                              AS first_at,
         max(e.created_at)                              AS last_at,
         count(*)                                       AS event_count,
         EXISTS (SELECT 1 FROM runtime_actions a
                  WHERE a.incident_key = e.incident_key
                    AND a.action = 'KILL_PROCESS' AND a.status = 'DONE') AS blocked
    FROM runtime_events e`;

export async function aggregateIncident(incidentKey: string): Promise<RuntimeIncident | null> {
  const { rows } = await pool.query<IncidentRow>(
    `${INCIDENT_SELECT} WHERE e.incident_key = $1 GROUP BY e.incident_key, e.container`,
    [incidentKey],
  );
  return rows.length ? toIncident(rows[0]) : null;
}

export async function listIncidents(limit = 50): Promise<RuntimeIncident[]> {
  const { rows } = await pool.query<IncidentRow>(
    `${INCIDENT_SELECT} GROUP BY e.incident_key, e.container ORDER BY max(e.created_at) DESC LIMIT $1`,
    [limit],
  );
  return rows.map(toIncident);
}

export async function listIncidentEvents(incidentKey: string) {
  const { rows } = await pool.query(
    `SELECT id, kind, pid, ppid, comm, filename, host(dest_ip) AS dest_ip, dest_port,
            rule_id, risk_level, created_at
       FROM runtime_events WHERE incident_key = $1 ORDER BY id`,
    [incidentKey],
  );
  return rows;
}

// 토폴로지 노드(고정) + DB에서 감염 상태 계산. c2는 미차단 인시던트가 있으면 노출.
const NODES = [
  { key: 'edge', name: '입구 서버', role: '요청을 나눠 보냄', container: 'carrot-edge' },
  { key: 'image', name: '이미지 서비스', role: '사진 올리기', container: 'carrot-image-service' },
  { key: 'pay', name: '결제 서비스', role: '안전결제 처리', container: 'carrot-pay-service' },
  { key: 'postgres', name: '주문 DB', role: '주문·회원 저장', container: 'carrot-postgres' },
  { key: 'redis', name: '캐시', role: '로그인 정보 저장', container: 'carrot-redis' },
];
const EDGES = [
  ['edge', 'image'], ['edge', 'pay'], ['image', 'postgres'],
  ['pay', 'postgres'], ['pay', 'redis'],
];

export async function topology() {
  const { rows } = await pool.query<{ container: string }>(
    `SELECT DISTINCT e.container FROM runtime_events e
       WHERE e.risk_level = 'HIGH'
         AND NOT EXISTS (SELECT 1 FROM runtime_actions a
                          WHERE a.incident_key = e.incident_key
                            AND a.action = 'KILL_PROCESS' AND a.status = 'DONE')`,
  );
  const infected = new Set(rows.map((r) => r.container));
  const nodes = NODES.map((n) => ({ ...n, infected: infected.has(n.container) }));
  return { nodes, edges: EDGES, c2Visible: infected.size > 0 };
}

export async function runtimeSummary() {
  const [agents, incidents, actions] = await Promise.all([
    pool.query<{ online: string; tracked: string }>(
      `SELECT count(*) FILTER (WHERE status='ONLINE') AS online, COALESCE(sum(tracked),0) AS tracked FROM runtime_agents`,
    ),
    pool.query<{ open: string }>(
      `SELECT count(DISTINCT e.incident_key) AS open FROM runtime_events e
         WHERE e.risk_level='HIGH'
           AND NOT EXISTS (SELECT 1 FROM runtime_actions a
                            WHERE a.incident_key=e.incident_key AND a.action='KILL_PROCESS' AND a.status='DONE')`,
    ),
    pool.query<{ blocked: string }>(
      `SELECT count(*) AS blocked FROM runtime_actions WHERE status='DONE' AND created_at::date = now()::date`,
    ),
  ]);
  return {
    agentsOnline: Number(agents.rows[0].online),
    tracked: Number(agents.rows[0].tracked),
    openIncidents: Number(incidents.rows[0].open),
    blockedToday: Number(actions.rows[0].blocked),
  };
}

export async function listAgents() {
  const { rows } = await pool.query(
    `SELECT agent_uid, hostname, status, tracked, started_at, last_seen_at FROM runtime_agents ORDER BY last_seen_at DESC`,
  );
  return rows;
}

export async function listSbom(container?: string): Promise<SbomComponent[]> {
  const { rows } = await pool.query<SbomComponent & { container: string }>(
    container
      ? `SELECT DISTINCT purl, name, version, ecosystem FROM sbom_components WHERE container=$1 ORDER BY purl`
      : `SELECT DISTINCT purl, name, version, ecosystem FROM sbom_components ORDER BY purl`,
    container ? [container] : [],
  );
  return rows;
}
