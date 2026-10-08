// 런타임 축 REST (docs/13 §9). web /runtime·/demoshop 화면이 소비한다.
import { Router } from 'express';
import { env } from '../env.js';
import { logger } from '../logger.js';
import { pool } from '../db/pool.js';
import {
  aggregateIncident,
  incidentTarget,
  listAgents,
  listIncidentEvents,
  listIncidents,
  listSbom,
  runtimeSummary,
  topology,
} from '../repo/runtime.js';
import { createAction } from '../runtime/store.js';
import { broadcastToAgents, sendToAgent } from '../runtime/agentWs.js';
import { getAutoBlock, getWhitelist, setAutoBlock, setWhitelist } from '../runtime/config.js';

export const runtimeRouter: Router = Router();

// 2x2 유효 PNG — 공격 시연 이미지 업로드 트리거용 최소 이미지.
const TINY_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAADklEQVR42mOoBwMGCAUAKboF9Qqcp0wAAAAASUVORK5CYII=',
  'base64',
);

// 공격 시연 트리거 (docs/13 §9). web "공격 시연" 제어 패널이 호출 → 모사 스택 edge를 두드려
// 오염 패키지 비콘을 유발한다. gateway가 서버측에서 호출(브라우저 CORS 회피).
runtimeRouter.post('/simulate', async (req, res) => {
  const scenario = String((req.body as { scenario?: string } | undefined)?.scenario ?? '');
  const edge = env.RUNTIME_EDGE_URL;
  const check = (r: Response) => {
    if (!r.ok) throw new Error(`edge ${r.status}`);
    return r;
  };
  try {
    if (scenario === 'pay') {
      check(await fetch(`${edge}/api/pay/pay`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ itemId: 'headphones', amount: 89000 }),
      }));
    } else if (scenario === 'image') {
      const form = new FormData();
      form.append('file', new Blob([TINY_PNG], { type: 'image/png' }), 'demo.png');
      check(await fetch(`${edge}/api/image/upload`, { method: 'POST', body: form }));
    } else if (scenario === 'normal') {
      check(await fetch(`${edge}/api/pay/health`)); // 비콘 없는 정상 트래픽
    } else if (scenario === 'reset') {
      await pool.query('DELETE FROM runtime_actions');
      await pool.query('DELETE FROM runtime_events');
    } else {
      res.status(400).json({ ok: false, error: { code: 'BAD_SCENARIO', message: 'pay|image|normal|reset' } });
      return;
    }
    res.json({ ok: true, data: { scenario } });
  } catch (err) {
    logger.warn({ err: (err as Error).message, scenario }, '[runtime] simulate failed');
    res.status(502).json({ ok: false, error: { code: 'EDGE_UNREACHABLE', message: '모사 스택(edge)에 연결할 수 없습니다' } });
  }
});

runtimeRouter.get('/summary', async (_req, res) => {
  res.json({ ok: true, data: await runtimeSummary() });
});

runtimeRouter.get('/incidents', async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  res.json({ ok: true, data: await listIncidents(limit) });
});

runtimeRouter.get('/incidents/:key', async (req, res) => {
  const incident = await aggregateIncident(req.params.key);
  if (!incident) {
    res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'incident not found' } });
    return;
  }
  const events = await listIncidentEvents(req.params.key);
  res.json({ ok: true, data: { incident, events } });
});

// 역방향 차단 (docs/13 §7): 종료=악성 프로세스 SIGKILL, 차단=목적지 eBPF 차단.
runtimeRouter.post('/incidents/:key/kill', async (req, res) => {
  const t = await incidentTarget(req.params.key);
  if (!t) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'incident not found' } });
  const actionId = await createAction(req.params.key, t.container, 'KILL_PROCESS', null);
  const sent = t.agentUid ? sendToAgent(t.agentUid, { type: 'cmd.kill', actionId, container: t.container }) : false;
  res.status(sent ? 202 : 503).json({ ok: sent, data: { actionId, sent } });
});

runtimeRouter.post('/incidents/:key/block', async (req, res) => {
  const t = await incidentTarget(req.params.key);
  if (!t) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'incident not found' } });
  if (!t.destIp) return res.status(400).json({ ok: false, error: { code: 'NO_DEST', message: '차단할 목적지가 없습니다' } });
  const actionId = await createAction(req.params.key, t.container, 'BLOCK_DEST', t.destIp);
  const sent = t.agentUid ? sendToAgent(t.agentUid, { type: 'cmd.block', actionId, destIp: t.destIp }) : false;
  res.status(sent ? 202 : 503).json({ ok: sent, data: { actionId, destIp: t.destIp, sent } });
});

runtimeRouter.get('/topology', async (_req, res) => {
  res.json({ ok: true, data: await topology() });
});

runtimeRouter.get('/agents', async (_req, res) => {
  res.json({ ok: true, data: await listAgents() });
});

// 운영 설정 (docs/13 §12 "런타임" 탭)
runtimeRouter.get('/config', (_req, res) => {
  res.json({ ok: true, data: { autoBlock: getAutoBlock(), whitelist: getWhitelist() } });
});

runtimeRouter.post('/config', (req, res) => {
  const body = (req.body ?? {}) as { autoBlock?: boolean };
  if (typeof body.autoBlock === 'boolean') setAutoBlock(body.autoBlock);
  res.json({ ok: true, data: { autoBlock: getAutoBlock() } });
});

// 화이트리스트 동적 갱신 → 모든 에이전트에 cmd.whitelist_update 푸시
runtimeRouter.post('/whitelist', (req, res) => {
  const wl = (req.body as { whitelist?: unknown } | undefined)?.whitelist;
  if (wl == null || typeof wl !== 'object') {
    return res.status(400).json({ ok: false, error: { code: 'BAD_WHITELIST', message: 'whitelist 객체가 필요합니다' } });
  }
  setWhitelist(wl);
  const pushed = broadcastToAgents({ type: 'cmd.whitelist_update', whitelist: wl });
  res.json({ ok: true, data: { pushed } });
});

runtimeRouter.get('/sbom', async (req, res) => {
  const container = typeof req.query.container === 'string' ? req.query.container : undefined;
  res.json({ ok: true, data: await listSbom(container) });
});
