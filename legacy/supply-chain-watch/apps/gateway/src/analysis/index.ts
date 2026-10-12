// 분석 큐 생산자 (ADR-020 U5). 분석 처리는 apps/analyzer가 한다 — gateway는 큐에 넣기만 한다.
import { ANALYSIS_QUEUE_KEY, type AnalysisJob } from '@scw/shared-types';
import { redis } from '../db/redis.js';

export const analysisQueue = {
  async enqueue(job: Omit<AnalysisJob, 'attempt'>): Promise<void> {
    // forceLlm 등 선택 필드는 그대로 실어 보낸다
    if (redis.status === 'wait' || redis.status === 'end') await redis.connect();
    await redis.lpush(ANALYSIS_QUEUE_KEY, JSON.stringify({ attempt: 1, ...job } satisfies AnalysisJob));
  },
};
