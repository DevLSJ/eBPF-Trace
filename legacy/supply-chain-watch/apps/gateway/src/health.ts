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
    return { ok: false, detail: (err as Error).message, latencyMs: Date.now() - t };
  }
}

export async function healthReport(): Promise<HealthReport> {
  const [db, cache, engine] = await Promise.all([
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
  ]);
  const checks = { db, redis: cache, engine };
  return {
    ok: Object.values(checks).every((c) => c.ok),
    service: 'gateway',
    checks,
    ts: new Date().toISOString(),
  };
}
