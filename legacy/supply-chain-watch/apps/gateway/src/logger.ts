import { pino } from 'pino';
import { env } from './env.js';

export const logger = pino({
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',
  // 비밀값 마스킹 (CLAUDE.md §5)
  redact: {
    paths: ['req.headers.authorization', 'req.headers["x-hub-signature-256"]', '*.token', '*.apiKey'],
    censor: '[redacted]',
  },
  transport:
    env.NODE_ENV === 'production'
      ? undefined
      : { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' } },
});
