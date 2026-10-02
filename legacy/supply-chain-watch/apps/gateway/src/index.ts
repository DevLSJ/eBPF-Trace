import { createServer } from 'node:http';
import express from 'express';
import { pinoHttp } from 'pino-http';
import { env } from './env.js';
import { logger } from './logger.js';
import { healthReport } from './health.js';
import { attachWs } from './ws.js';

const app = express();
app.use(pinoHttp({ logger }));
app.use(express.json());

app.get('/health', async (_req, res) => {
  const report = await healthReport();
  res.status(report.ok ? 200 : 503).json(report);
});

app.get('/api/health', async (_req, res) => {
  const report = await healthReport();
  res.json({ ok: report.ok, data: report });
});

const server = createServer(app);
attachWs(server);

server.listen(env.GATEWAY_PORT, () => {
  logger.info(`[gateway] listening on :${env.GATEWAY_PORT} (ws /ws, engine ${env.ENGINE_URL})`);
});

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    logger.info(`[gateway] ${sig} received, shutting down`);
    server.close(() => process.exit(0));
  });
}
