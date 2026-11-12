// 루트 .env를 모든 앱이 공유한다 (docs/10 §4). gateway의 env 로딩·검증 지점.
import { config } from 'dotenv';
import { resolve } from 'node:path';
import { z } from 'zod';

config({ path: resolve(process.cwd(), '../../.env') });

const schema = z.object({
  GATEWAY_PORT: z.coerce.number().default(4000),
  ENGINE_URL: z.string().url().default('http://localhost:8000'),
  ANALYZER_URL: z.string().url().default('http://localhost:4100'), // 분석 처리 서비스 (ADR-020 U5)
  DATABASE_URL: z.string().default('postgresql://capstone:capstone@localhost:5433/capstone'),
  REDIS_URL: z.string().default('redis://localhost:6379/0'),
  GITHUB_TOKEN: z.string().optional(),
  GITHUB_WEBHOOK_SECRET: z.string().optional(),
  ADMIN_PASSWORD: z.string().optional(),
  SESSION_SECRET: z.string().default('dev-secret-change-me'),
  AGENT_TOKEN: z.string().optional(), // 런타임 에이전트 /agent-ws 인증 (docs/13 §3.2)
  RUNTIME_EDGE_URL: z.string().url().default('http://localhost:8088'), // 모사 스택 입구(공격 시연 트리거)
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

export const env = schema.parse(process.env);
export type Env = typeof env;
