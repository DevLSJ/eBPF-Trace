import { createServer } from 'node:http';
import express from 'express';
import { pinoHttp } from 'pino-http';
import { env } from './env.js';
import { logger } from './logger.js';
import { healthReport } from './health.js';
import { handleWebUpgrade } from './ws.js';
import { attachAgentWs, handleAgentUpgrade } from './runtime/agentWs.js';
import { login, logout, me, requireAuth } from './auth.js';
import { reposRouter } from './routes/repos.js';
import { commitsRouter } from './routes/commits.js';
import { statsRouter } from './routes/stats.js';
import { runtimeRouter } from './routes/runtime.js';
import { githubWebhook } from './collector/webhook.js';
import { PollingScheduler } from './collector/polling.js';
import { handleNewCommit } from './collector/handle.js';
import { startEventRelay, stopEventRelay } from './analysis/relay.js';

const app = express();
app.use(pinoHttp({ logger }));

// 로컬 개발: web(3000) ↔ gateway(4000) 교차 출처 + 쿠키 허용
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'content-type');
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});
app.use(express.json({ verify: (req, _res, buf) => { (req as express.Request & { rawBody?: Buffer }).rawBody = buf; } }));

// GitHub Webhook (공개, 서명 검증). /api 프리픽스 없음
app.post('/webhooks/github', githubWebhook);

// 인증 (docs/05 §1.5)
app.post('/api/auth/login', login);
app.post('/api/auth/logout', logout);
app.get('/api/auth/me', me);

// 보호 API (docs/05 §1)
app.use('/api/repos', requireAuth, reposRouter);
app.use('/api/commits', requireAuth, commitsRouter);
app.use('/api/stats', requireAuth, statsRouter);
app.use('/api/runtime', requireAuth, runtimeRouter);

app.get('/health', async (_req, res) => {
  const report = await healthReport();
  res.status(report.ok ? 200 : 503).json(report);
});

app.get('/api/health', async (_req, res) => {
  const report = await healthReport();
  res.json({ ok: report.ok, data: report });
});

const server = createServer(app);
attachAgentWs();

// WS 업그레이드 경로 라우팅: /ws(web) · /agent-ws(에이전트). 그 외는 거절.
server.on('upgrade', (req, socket, head) => {
  const pathname = new URL(req.url ?? '', 'http://localhost').pathname;
  if (pathname === '/ws') handleWebUpgrade(req, socket, head);
  else if (pathname === '/agent-ws') handleAgentUpgrade(req, socket, head);
  else socket.destroy();
});

const scheduler = new PollingScheduler((repo, sha, branch) =>
  handleNewCommit(repo, sha, branch, 'polling_events'),
);

server.listen(env.GATEWAY_PORT, () => {
  logger.info(`[gateway] listening on :${env.GATEWAY_PORT} (ws /ws, engine ${env.ENGINE_URL})`);
  scheduler.start();
  void startEventRelay().catch((err: Error) => logger.error({ err: err.message }, '[relay] subscribe failed'));
});

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    logger.info(`[gateway] ${sig} received, shutting down`);
    scheduler.stop();
    stopEventRelay();
    server.close(() => process.exit(0));
  });
}
