import { request } from 'undici';
import type { HealthReport } from '@scw/shared-types';
import { pool } from './db/pool.js';
import { redis } from './db/redis.js';
import { env } from './env.js';

type Check = HealthReport['checks'][string];

async function timed(fn: () => Promise<void>): Promise<Check> {
  const t = Date.now();
  try {
    await fn();
    return { ok: true, latencyMs: Date.now() - t };
  } catch (err) {
    const e = err as Error & { code?: string };
    return { ok: false, detail: e.message || e.code || '연결 실패', latencyMs: Date.now() - t };
  }
}

export async function healthReport(): Promise<HealthReport> {
  const [db, cache, engine, analyzer] = await Promise.all([
    timed(async () => {
      await pool.query('SELECT 1');
    }),
    timed(async () => {
      if (redis.status === 'wait' || redis.status === 'end') await redis.connect();
      await redis.ping();
    }),
    timed(async () => {
      const res = await request(`${env.ENGINE_URL}/health`, { method: 'GET' });
      if (res.statusCode !== 200) throw new Error(`engine status ${res.statusCode}`);
      await res.body.dump();
    }),
    timed(async () => {
      const res = await request(`${env.ANALYZER_URL}/health`, { method: 'GET', headersTimeout: 3000, bodyTimeout: 3000 });
      await res.body.dump();
      if (res.statusCode !== 200) throw new Error(`analyzer status ${res.statusCode}`);
    }),
  ]);
  const checks = { db, redis: cache, engine, analyzer };
  return {
    ok: Object.values(checks).every((c) => c.ok),
    service: 'gateway',
    checks,
    ts: new Date().toISOString(),
  };
}
