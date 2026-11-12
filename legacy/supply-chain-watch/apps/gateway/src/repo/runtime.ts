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
// ip = infra/docker-compose.runtime.yml의 carrot-net 고정 주소 (차단 미리보기에서 내부 서비스 판별용)
const NODES = [
  { key: 'edge', name: '입구 서버', role: '요청을 나눠 보냄', container: 'carrot-edge', ip: '10.77.0.2' },
  { key: 'image', name: '이미지 서비스', role: '사진 올리기', container: 'carrot-image-service', ip: '10.77.0.12' },
  { key: 'pay', name: '결제 서비스', role: '안전결제 처리', container: 'carrot-pay-service', ip: '10.77.0.11' },
  { key: 'postgres', name: '주문 DB', role: '주문·회원 저장', container: 'carrot-postgres', ip: '10.77.0.10' },
  { key: 'redis', name: '캐시', role: '로그인 정보 저장', container: 'carrot-redis', ip: '10.77.0.13' },
];
const serviceName = (container: string) => NODES.find((n) => n.container === container)?.name ?? container;
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
  const nodes = NODES.map(({ ip: _ip, ...n }) => ({ ...n, infected: infected.has(n.container) }));
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

// 인시던트의 차단 대상 정보: 컨테이너·담당 에이전트·외부 목적지 IP.
export async function incidentTarget(
  incidentKey: string,
): Promise<{ container: string; agentUid: string | null; destIp: string | null } | null> {
  const { rows } = await pool.query<{ container: string; agent_uid: string | null; dest_ip: string | null }>(
    `SELECT e.container,
            (SELECT a.agent_uid FROM runtime_agents a WHERE a.id = max(e.agent_id)) AS agent_uid,
            (array_remove(array_agg(host(e.dest_ip)) FILTER (WHERE e.rule_id='NET_UNALLOWED_CONNECT'), NULL))[1] AS dest_ip
       FROM runtime_events e WHERE e.incident_key = $1 GROUP BY e.container`,
    [incidentKey],
  );
  if (!rows.length) return null;
  return { container: rows[0].container, agentUid: rows[0].agent_uid, destIp: rows[0].dest_ip };
}

// 종료·차단 실행 전 예상 결과 (ADR-020 U3). 실제 실행은 하지 않고 DB 기록만으로 계산한다.
export interface IncidentPreview {
  container: string;
  service: string;
  agentOnline: boolean;
  kill: {
    loops: { ppid: number; tools: string[]; runs: number }[]; // 반복 실행 중인 부모 프로세스 → 실행한 도구
    keeps: string;
  };
  block: {
    destIp: string | null;
    ports: number[];
    destLabel: string;
    internalService: string | null; // 막으면 서비스가 멈추는 내부 주소
    affected: string[]; // 최근 24시간 이 주소로 접속한 서비스 (차단은 모사 서비스 전체에 적용)
    undo: string;
  };
}

export async function incidentPreview(incidentKey: string): Promise<IncidentPreview | null> {
  const t = await incidentTarget(incidentKey);
  if (!t) return null;
  const [loops, ports, affected, agent] = await Promise.all([
    pool.query<{ ppid: number; tools: string[]; runs: number }>(
      `SELECT ppid, array_agg(DISTINCT coalesce(filename, comm)) AS tools, count(*)::int AS runs
         FROM runtime_events WHERE incident_key = $1 AND kind = 'EXECVE' AND ppid IS NOT NULL
        GROUP BY ppid ORDER BY runs DESC LIMIT 5`,
      [incidentKey],
    ),
    t.destIp
      ? pool.query<{ port: number }>(
          `SELECT DISTINCT dest_port AS port FROM runtime_events
            WHERE incident_key = $1 AND host(dest_ip) = $2 AND dest_port IS NOT NULL ORDER BY 1`,
          [incidentKey, t.destIp],
        )
      : Promise.resolve({ rows: [] as { port: number }[] }),
    t.destIp
      ? pool.query<{ container: string }>(
          `SELECT DISTINCT container FROM runtime_events
            WHERE host(dest_ip) = $1 AND created_at > now() - interval '24 hours' ORDER BY 1`,
          [t.destIp],
        )
      : Promise.resolve({ rows: [] as { container: string }[] }),
    t.agentUid
      ? pool.query<{ status: string }>(`SELECT status FROM runtime_agents WHERE agent_uid = $1`, [t.agentUid])
      : Promise.resolve({ rows: [] as { status: string }[] }),
  ]);
  const internal = t.destIp ? NODES.find((n) => n.ip === t.destIp) : undefined;
  return {
    container: t.container,
    service: serviceName(t.container),
    agentOnline: agent.rows[0]?.status === 'ONLINE',
    kill: {
      loops: loops.rows.map((r) => ({ ppid: Number(r.ppid), tools: r.tools, runs: r.runs })),
      keeps: `${serviceName(t.container)} 본체(컨테이너의 첫 프로세스)는 그대로 두므로 서비스는 계속 동작합니다`,
    },
    block: {
      destIp: t.destIp,
      ports: ports.rows.map((r) => r.port),
      destLabel: internal ? `내부 서비스 · ${internal.name}` : '허용 목록에 없는 외부 서버',
      internalService: internal?.name ?? null,
      affected: affected.rows.map((r) => serviceName(r.container)),
      undo: '해제 버튼은 아직 없습니다. 런타임 에이전트를 다시 시작하면 풀립니다',
    },
  };
}
