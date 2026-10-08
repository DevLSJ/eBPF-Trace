// 에이전트 ↔ gateway WebSocket (docs/13 §5). 경로 /agent-ws, AGENT_TOKEN 인증.
// 업링크: agent.hello / agent.heartbeat / runtime.event / action.result.
// 다운링크: cmd.kill / cmd.block / cmd.whitelist_update (sendToAgent).
import type { IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer, type WebSocket } from 'ws';
import { env } from '../env.js';
import { logger } from '../logger.js';
import { broadcast } from '../ws.js';
import {
  markAgentOffline,
  rememberSuspects,
  storeEvent,
  storeSbom,
  touchAgent,
  upsertAgent,
  resolveAction,
  createAction,
  type HelloContainer,
} from './store.js';
import { aggregateIncident, topology } from '../repo/runtime.js';
import { getAutoBlock } from './config.js';

const autoBlocked = new Set<string>(); // 자동 차단 1회 보장(인시던트별)

interface AgentConn {
  ws: WebSocket;
  agentUid: string;
  dbId: number;
}

const agents = new Map<string, AgentConn>();

function tokenFromReq(req: IncomingMessage): string | undefined {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) return auth.slice(7).trim();
  const url = new URL(req.url ?? '', 'http://localhost');
  return url.searchParams.get('token') ?? undefined;
}

// noServer 모드. 업그레이드 라우팅·인증은 handleAgentUpgrade에서.
const wss = new WebSocketServer({ noServer: true });

export function handleAgentUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
  if (!env.AGENT_TOKEN) {
    logger.warn('AGENT_TOKEN 미설정 — /agent-ws 연결을 거부합니다');
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  if (tokenFromReq(req) !== env.AGENT_TOKEN) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
}

export function attachAgentWs(): void {
  wss.on('connection', (ws: WebSocket) => {
    let uid = '';
    logger.info('[agent-ws] agent connected');

    ws.on('message', (raw) => {
      void handleMessage(ws, raw.toString(), (u) => (uid = u)).catch((err) =>
        logger.error({ err: (err as Error).message }, '[agent-ws] handle failed'),
      );
    });
    ws.on('close', () => {
      logger.info({ uid }, '[agent-ws] agent disconnected');
      if (uid) {
        agents.delete(uid);
        void markAgentOffline(uid).catch(() => {});
      }
    });
    ws.on('error', (e) => logger.warn({ err: e.message }, '[agent-ws] socket error'));
  });
  logger.info('[agent-ws] ready on /agent-ws');
}

async function handleMessage(ws: WebSocket, text: string, setUid: (u: string) => void): Promise<void> {
  let msg: Record<string, unknown>;
  try {
    msg = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return;
  }
  const type = String(msg.type ?? '');
  switch (type) {
    case 'agent.hello': {
      const uid = String(msg.agentUid ?? '');
      if (!uid) return;
      const containers = (msg.containers as HelloContainer[]) ?? [];
      const dbId = await upsertAgent(uid, msg.hostname as string | undefined, Number(msg.tracked ?? containers.length));
      await storeSbom(dbId, containers);
      rememberSuspects(containers);
      agents.set(uid, { ws, agentUid: uid, dbId });
      setUid(uid);
      logger.info({ uid, containers: containers.length }, '[agent-ws] hello stored');
      break;
    }
    case 'agent.heartbeat': {
      const uid = String(msg.agentUid ?? '');
      if (uid) await touchAgent(uid, Number(msg.tracked ?? 0));
      break;
    }
    case 'runtime.event': {
      const uid = String(msg.agentUid ?? '');
      const conn = agents.get(uid);
      if (!conn) return; // hello 전 이벤트는 무시
      const stored = await storeEvent(conn.dbId, {
        container: String(msg.container ?? ''),
        image: msg.image as string | undefined,
        kind: (msg.kind as 'exec' | 'connect') ?? 'exec',
        pid: msg.pid as number | undefined,
        ppid: msg.ppid as number | undefined,
        comm: msg.comm as string | undefined,
        file: msg.file as string | undefined,
        dstIp: msg.dst_ip as string | undefined,
        dstPort: msg.dst_port as number | undefined,
        rule: String(msg.rule ?? ''),
        ts: msg.ts as string | undefined,
      });
      // web 실시간 피드: 집계된 인시던트 + 토폴로지 갱신 브로드캐스트 (docs/13 §9)
      const incident = await aggregateIncident(stored.incidentKey);
      if (incident) broadcast('runtime.incident', incident);
      broadcast('runtime.topology', await topology());

      // 자동 차단(설정): HIGH 외부 접속이면 인시던트당 1회 자동으로 목적지 차단
      if (getAutoBlock() && stored.riskLevel === 'HIGH' && String(msg.rule) === 'NET_UNALLOWED_CONNECT') {
        if (!autoBlocked.has(stored.incidentKey)) {
          autoBlocked.add(stored.incidentKey);
          const destIp = msg.dst_ip as string | undefined;
          if (destIp) {
            const actionId = await createAction(stored.incidentKey, String(msg.container ?? ''), 'BLOCK_DEST', destIp, 'auto');
            sendToAgent(uid, { type: 'cmd.block', actionId, destIp });
            logger.info({ incidentKey: stored.incidentKey, destIp }, '[agent-ws] auto-block issued');
          }
        }
      }
      break;
    }
    case 'action.result': {
      const actionId = Number(msg.actionId ?? 0);
      if (!actionId) break;
      const status = (msg.status as 'DONE' | 'FAILED') ?? 'DONE';
      const resolved = await resolveAction(actionId, status, String(msg.result ?? ''));
      logger.info({ actionId, status, result: msg.result }, '[agent-ws] action result');
      if (resolved) {
        const incident = await aggregateIncident(resolved.incidentKey);
        if (incident) broadcast('runtime.incident', incident);
        broadcast('runtime.topology', await topology());
        broadcast('runtime.action', { incidentKey: resolved.incidentKey, status, result: String(msg.result ?? '') });
      }
      break;
    }
    default:
      logger.debug({ type }, '[agent-ws] unknown message');
  }
}

// 다운링크: 특정 에이전트에 명령 전송 (R-10 kill/block, R-12 whitelist_update).
export function sendToAgent(agentUid: string, payload: Record<string, unknown>): boolean {
  const conn = agents.get(agentUid);
  if (!conn || conn.ws.readyState !== conn.ws.OPEN) return false;
  conn.ws.send(JSON.stringify(payload));
  return true;
}

// 모든 연결 에이전트에 전송 (화이트리스트 동적 갱신 등).
export function broadcastToAgents(payload: Record<string, unknown>): number {
  let n = 0;
  for (const uid of agents.keys()) if (sendToAgent(uid, payload)) n++;
  return n;
}

export function connectedAgents(): string[] {
  return [...agents.keys()];
}
