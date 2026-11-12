// 분석 큐 소비자 (docs/01 §2, docs/04 Redis, ADR-005 → ADR-020 U5에서 gateway에서 분리).
// Redis List를 워커 N(=검사 에이전트 상한)이 BRPOP으로 꺼낸다. 재시도·inflight 복구·agent.tick 발행.
import { Redis } from 'ioredis';
import { ANALYSIS_INFLIGHT_KEY, ANALYSIS_QUEUE_KEY, type AnalysisJob } from '@scw/shared-types';
import { env } from './env.js';
import { logger } from './logger.js';
import { publish } from './events.js';
import { setCommitStatus } from './store.js';

const MAX_ATTEMPTS = 5;

export interface AgentState {
  id: number;
  repoFullName: string | null;
  step: string;
  sha: string | null;
  idle: boolean;
}

type ProcessFn = (commitId: number, onStep: (step: string) => void, forceLlm?: boolean) => Promise<void>;

export class AnalysisQueue {
  private cmd: Redis;
  private blocking: Redis;
  readonly agents: AgentState[];
  private running = false;
  private tickTimer: ReturnType<typeof setInterval> | null = null;
  private processed = 0;
  private failed = 0;

  constructor(
    private concurrency: number,
    private processFn: ProcessFn,
  ) {
    this.cmd = new Redis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: null });
    this.blocking = new Redis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: null });
    this.agents = Array.from({ length: concurrency }, (_, i) => ({
      id: i + 1, repoFullName: null, step: '유휴', sha: null, idle: true,
    }));
  }

  async start(): Promise<void> {
    await this.cmd.connect().catch(() => {});
    await this.blocking.connect().catch(() => {});
    await this.recoverInflight();
    this.running = true;
    this.tickTimer = setInterval(() => this.publishAgents(), 1500);
    for (let i = 0; i < this.concurrency; i++) void this.workerLoop(i);
    logger.info({ concurrency: this.concurrency }, '[queue] workers started');
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.tickTimer) clearInterval(this.tickTimer);
    this.blocking.disconnect();
    this.cmd.disconnect();
  }

  async stats(): Promise<{ waiting: number; busy: number; workers: number; processed: number; failed: number }> {
    const waiting = await this.cmd.llen(ANALYSIS_QUEUE_KEY).catch(() => -1);
    return {
      waiting, busy: this.agents.filter((a) => !a.idle).length, workers: this.concurrency,
      processed: this.processed, failed: this.failed,
    };
  }

  // 이전 프로세스가 처리 중에 죽었으면 그 작업을 큐로 되돌린다.
  // 주의: analyzer는 1개만 띄운다는 전제(여러 개면 서로의 처리 중 작업을 되돌릴 수 있음).
  private async recoverInflight(): Promise<void> {
    const entries = await this.cmd.hgetall(ANALYSIS_INFLIGHT_KEY);
    const ids = Object.keys(entries);
    if (!ids.length) return;
    for (const field of ids) {
      await this.cmd.lpush(ANALYSIS_QUEUE_KEY, entries[field]!);
      await this.cmd.hdel(ANALYSIS_INFLIGHT_KEY, field);
    }
    logger.warn({ recovered: ids.length }, '[queue] recovered inflight jobs');
  }

  private async workerLoop(slot: number): Promise<void> {
    const agent = this.agents[slot]!;
    while (this.running) {
      let raw: [string, string] | null = null;
      try {
        raw = await this.blocking.brpop(ANALYSIS_QUEUE_KEY, 5);
      } catch {
        if (!this.running) break;
        await sleep(500);
        continue;
      }
      if (!raw) continue;
      const job = JSON.parse(raw[1]) as AnalysisJob;
      const field = `${slot}:${job.commitId}`;
      await this.cmd.hset(ANALYSIS_INFLIGHT_KEY, field, raw[1]);
      agent.idle = false;
      agent.repoFullName = job.repoFullName;
      agent.sha = job.sha.slice(0, 7);
      agent.step = '분석 시작';
      this.publishAgents();
      try {
        await this.processFn(job.commitId, (step) => {
          agent.step = step;
        }, job.forceLlm ?? false);
        this.processed++;
      } catch (err) {
        await this.onFailure(job, err as Error);
      } finally {
        await this.cmd.hdel(ANALYSIS_INFLIGHT_KEY, field);
        agent.idle = true;
        agent.repoFullName = null;
        agent.sha = null;
        agent.step = '유휴';
      }
    }
  }

  private async onFailure(job: AnalysisJob, err: Error): Promise<void> {
    logger.warn({ sha: job.sha.slice(0, 7), attempt: job.attempt, err: err.message }, '[queue] job failed');
    if (job.attempt < MAX_ATTEMPTS) {
      const next = { ...job, attempt: job.attempt + 1 };
      await sleep(Math.min(1000 * 2 ** job.attempt, 15000));
      await this.cmd.lpush(ANALYSIS_QUEUE_KEY, JSON.stringify(next));
    } else {
      this.failed++;
      await setCommitStatus(job.commitId, 'FAILED');
      publish('analysis.failed', { commitId: job.commitId, reason: err.message });
    }
  }

  private publishAgents(): void {
    publish('agent.tick', this.agents.map((a) => ({
      id: a.id, repoFullName: a.repoFullName, step: a.step, sha: a.sha, idle: a.idle,
    })));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
