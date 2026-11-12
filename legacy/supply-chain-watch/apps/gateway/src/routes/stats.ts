import { Router, type Router as ExpressRouter } from 'express';
import { pool } from '../db/pool.js';
import { env } from '../env.js';
import { request } from 'undici';

export const statsRouter: ExpressRouter = Router();


statsRouter.get('/overview', async (_req, res) => {
  const repos = await pool.query(
    `SELECT count(*)::int total,
            count(*) FILTER (WHERE status='ACTIVE')::int active,
            count(*) FILTER (WHERE status='RATE_LIMITED')::int rate_limited,
            count(*) FILTER (WHERE status='PAUSED')::int paused
     FROM repositories`,
  );
  const today = await pool.query(
    `SELECT count(*)::int commits,
            count(*) FILTER (WHERE a.risk_level='HIGH')::int high,
            count(*) FILTER (WHERE a.risk_level='MEDIUM')::int medium,
            count(*) FILTER (WHERE a.risk_level='LOW')::int low,
            count(*) FILTER (WHERE a.llm_status IN ('OK','CACHED'))::int llm_calls
     FROM commits c LEFT JOIN LATERAL (
       SELECT risk_level, llm_status FROM analyses WHERE commit_id=c.id ORDER BY attempt DESC LIMIT 1
     ) a ON true
     WHERE c.received_at >= date_trunc('day', now())`,
  );
  let engine: { healthy: boolean; model?: string } = { healthy: false };
  try {
    const r = await request(`${env.ENGINE_URL}/health`, { method: 'GET', headersTimeout: 3000, bodyTimeout: 3000 });
    if (r.statusCode === 200) {
      const d = (await r.body.json()) as { model?: string };
      engine = { healthy: true, model: d.model };
    } else await r.body.dump();
  } catch { /* engine down */ }

  res.json({
    ok: true,
    data: { repos: repos.rows[0], today: today.rows[0], engine },
  });
});
