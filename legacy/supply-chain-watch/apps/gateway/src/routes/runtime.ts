// 런타임 축 REST (docs/13 §9). web /runtime·/demoshop 화면이 소비한다.
import { Router } from 'express';
import {
  aggregateIncident,
  listAgents,
  listIncidentEvents,
  listIncidents,
  listSbom,
  runtimeSummary,
  topology,
} from '../repo/runtime.js';

export const runtimeRouter: Router = Router();

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

runtimeRouter.get('/topology', async (_req, res) => {
  res.json({ ok: true, data: await topology() });
});

runtimeRouter.get('/agents', async (_req, res) => {
  res.json({ ok: true, data: await listAgents() });
});

runtimeRouter.get('/sbom', async (req, res) => {
  const container = typeof req.query.container === 'string' ? req.query.container : undefined;
  res.json({ ok: true, data: await listSbom(container) });
});
