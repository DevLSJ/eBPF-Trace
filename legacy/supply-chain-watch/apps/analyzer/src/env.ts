// 루트 .env를 모든 앱이 공유한다 (docs/10 §4). analyzer의 env 로딩·검증 지점.
import { config } from 'dotenv';
import { resolve } from 'node:path';
import { z } from 'zod';

config({ path: resolve(process.cwd(), '../../.env') });

const schema = z.object({
  ANALYZER_PORT: z.coerce.number().default(4100),
  ENGINE_URL: z.string().url().default('http://localhost:8000'),
  DATABASE_URL: z.string().default('postgresql://capstone:capstone@localhost:5433/capstone'),
  REDIS_URL: z.string().default('redis://localhost:6379/0'),
  AGENT_CONCURRENCY: z.coerce.number().int().min(1).max(32).default(6), // 검사 에이전트(워커) 수, ADR-015 상한
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

export const env = schema.parse(process.env);
