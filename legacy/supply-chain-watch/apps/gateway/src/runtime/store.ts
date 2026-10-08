// 런타임 축 DB 저장 (docs/13 §4). 에이전트 업링크 → 점수화 → runtime_* 테이블.
import { pool } from '../db/pool.js';
import { logger } from '../logger.js';
import { incidentKeyFor, riskForRule } from './scoring.js';

export interface HelloContainer {
  name: string;
  image?: string;
  sbom?: { purl: string }[];
}

export async function upsertAgent(agentUid: string, hostname: string | undefined, tracked: number): Promise<number> {
  const { rows } = await pool.query<{ id: number }>(
    `INSERT INTO runtime_agents (agent_uid, hostname, status, tracked, last_seen_at)
       VALUES ($1, $2, 'ONLINE', $3, now())
     ON CONFLICT (agent_uid) DO UPDATE
       SET status='ONLINE', hostname=EXCLUDED.hostname, tracked=EXCLUDED.tracked,
           last_seen_at=now(), started_at=now()
     RETURNING id`,
    [agentUid, hostname ?? null, tracked],
  );
  return rows[0].id;
}

export async function touchAgent(agentUid: string, tracked: number): Promise<void> {
  await pool.query(
    `UPDATE runtime_agents SET last_seen_at=now(), status='ONLINE', tracked=$2 WHERE agent_uid=$1`,
    [agentUid, tracked],
  );
}

export async function markAgentOffline(agentUid: string): Promise<void> {
  await pool.query(`UPDATE runtime_agents SET status='OFFLINE' WHERE agent_uid=$1`, [agentUid]);
}

function parsePurl(purl: string): { name?: string; version?: string; ecosystem?: string } {
  const m = /^pkg:([^/]+)\/(.+?)@(.*)$/.exec(purl); // 버전은 비어 있을 수 있음(로컬 vendor)
  if (!m) return {};
  return { ecosystem: m[1], name: m[2], version: m[3] };
}

export async function storeSbom(agentId: number, containers: HelloContainer[]): Promise<void> {
  for (const c of containers) {
    for (const comp of c.sbom ?? []) {
      const { name, version, ecosystem } = parsePurl(comp.purl);
      await pool.query(
        `INSERT INTO sbom_components (agent_id, container, purl, name, version, ecosystem, source_file)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (agent_id, container, purl) DO NOTHING`,
        [agentId, c.name, comp.purl, name ?? null, version ?? null, ecosystem ?? null, null],
      );
    }
  }
}

// 컨테이너별 "의심(오염) 패키지" purl 캐시 — 데모 패키지(*-demo)를 커밋 축 연결 후보로 본다.
const suspectPurl = new Map<string, string>();

export function rememberSuspects(containers: HelloContainer[]): void {
  for (const c of containers) {
    for (const comp of c.sbom ?? []) {
      const { name } = parsePurl(comp.purl);
      if (name && /-demo$/.test(name)) suspectPurl.set(c.name, comp.purl);
    }
  }
}

export interface IncomingEvent {
  container: string;
  image?: string;
  kind: 'exec' | 'connect';
  pid?: number;
  ppid?: number;
  comm?: string;
  file?: string;
  dstIp?: string;
  dstPort?: number;
  rule: string;
  ts?: string;
}

export interface StoredEvent {
  id: number;
  incidentKey: string;
  riskLevel: string;
  purl: string | null;
}

export async function storeEvent(agentId: number, e: IncomingEvent): Promise<StoredEvent> {
  const risk = riskForRule(e.rule);
  const at = e.ts ? Date.parse(e.ts) : Date.now();
  const incidentKey = incidentKeyFor(e.container, Number.isFinite(at) ? at : Date.now());
  const purl = suspectPurl.get(e.container) ?? null;
  const kind = e.kind === 'exec' ? 'EXECVE' : 'CONNECT';
  const { rows } = await pool.query<{ id: number }>(
    `INSERT INTO runtime_events
       (agent_id, incident_key, container, image, kind, pid, ppid, comm, filename, dest_ip, dest_port, rule_id, risk_level, purl)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING id`,
    [
      agentId, incidentKey, e.container, e.image ?? null, kind,
      e.pid ?? null, e.ppid ?? null, e.comm ?? null, e.file ?? null,
      e.dstIp ?? null, e.dstPort ?? null, e.rule, risk, purl,
    ],
  );
  logger.debug({ container: e.container, rule: e.rule, risk, incidentKey }, 'runtime event stored');
  return { id: rows[0].id, incidentKey, riskLevel: risk, purl };
}
