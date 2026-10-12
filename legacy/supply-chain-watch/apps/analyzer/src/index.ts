// analyzer — 분석 처리 전용 서비스 (ADR-020 U5). 큐 소비 → engine 호출 → 결과 저장 → 이벤트 발행.
// 브라우저·GitHub과는 연결하지 않는다. 상태 확인용 HTTP는 /health 하나만 연다.
import { createServer } from 'node:http';
import { request } from 'undici';
import { env } from './env.js';
import { logger } from './logger.js';
import { pool } from './db.js';
import { closeEvents } from './events.js';
import { AnalysisQueue } from './queue.js';
import { processCommit } from './worker.js';

const queue = new AnalysisQueue(env.AGENT_CONCURRENCY, (commitId, onStep) => processCommit(commitId, onStep));

async function check(fn: () => Promise<void>): Promise<{ ok: boolean; latencyMs: number; detail?: string }> {
  const t = Date.now();
  try {
    await fn();
    return { ok: true, latencyMs: Date.now() - t };
  } catch (err) {
    return { ok: false, latencyMs: Date.now() - t, detail: (err as Error).message };
  }
}

const server = createServer((req, res) => {
  if (req.method !== 'GET' || req.url !== '/health') {
    res.writeHead(404).end();
    return;
  }
  void (async () => {
    const [db, engine, q] = await Promise.all([
      check(async () => { await pool.query('SELECT 1'); }),
      check(async () => {
        const r = await request(`${env.ENGINE_URL}/health`, { headersTimeout: 3000, bodyTimeout: 3000 });
        await r.body.dump();
        if (r.statusCode !== 200) throw new Error(`engine status ${r.statusCode}`);
      }),
      queue.stats(),
    ]);
    const redis = { ok: q.waiting >= 0, latencyMs: 0 };
    const checks = { db, redis, engine };
    const body = { ok: Object.values(checks).every((c) => c.ok), service: 'analyzer', checks, queue: q, ts: new Date().toISOString() };
    res.writeHead(body.ok ? 200 : 503, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  })();
});

server.listen(env.ANALYZER_PORT, () => {
  logger.info(`[analyzer] listening on :${env.ANALYZER_PORT} (/health, engine ${env.ENGINE_URL})`);
  void queue.start();
});

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    logger.info(`[analyzer] ${sig} received, shutting down`);
    void queue.stop();
    closeEvents();
    server.close(() => process.exit(0));
  });
}
