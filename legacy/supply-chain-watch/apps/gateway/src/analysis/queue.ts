// 분석 큐 (docs/01 §2, docs/04 Redis, ADR-005). Redis List + 워커 N(=에이전트 상한),
// 재시도, inflight 복구, agent.tick 브로드캐스트.
import { Redis } from 'ioredis';
import { env } from '../env.js';
import { logger } from '../logger.js';
import { setCommitStatus } from '../repo/commits.js';
import { broadcast } from '../ws.js';

const QUEUE = 'analysis:queue';
const INFLIGHT = 'analysis:inflight';
const MAX_ATTEMPTS = 5;

export interface Job {
  commitId: number;
  repoFullName: string;
  sha: string;
  attempt: number;
}

export interface AgentState {
  id: number;
  repoFullName: string | null;
  step: string;
  sha: string | null;
  idle: boolean;
}

type ProcessFn = (commitId: number, onStep: (step: string) => void) => Promise<void>;

export class AnalysisQueue {
  private pub: Redis;
  private blocking: Redis;
  private agents: AgentState[];
  private running = false;
  private tickTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private concurrency: number,
    private processFn: ProcessFn,
  ) {
    this.pub = new Redis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: null });
    this.blocking = new Redis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: null });
    this.agents = Array.from({ length: concurrency }, (_, i) => ({
      id: i + 1, repoFullName: null, step: '유휴', sha: null, idle: true,
    }));
  }

  async enqueue(job: Omit<Job, 'attempt'> & { attempt?: number }): Promise<void> {
    await this.pub.connect().catch(() => {});
    await this.pub.lpush(QUEUE, JSON.stringify({ attempt: 1, ...job }));
  }

  async start(): Promise<void> {
    await this.pub.connect().catch(() => {});
    await this.blocking.connect().catch(() => {});
    await this.recoverInflight();
    this.running = true;
    this.tickTimer = setInterval(() => this.broadcastAgents(), 1500);
    for (let i = 0; i < this.concurrency; i++) void this.workerLoop(i);
    logger.info({ concurrency: this.concurrency }, '[queue] workers started');
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.tickTimer) clearInterval(this.tickTimer);
    this.blocking.disconnect();
    this.pub.disconnect();
  }

  private async recoverInflight(): Promise<void> {
    const entries = await this.pub.hgetall(INFLIGHT);
    const ids = Object.keys(entries);
    if (!ids.length) return;
    for (const field of ids) {
      await this.pub.lpush(QUEUE, entries[field]!);
      await this.pub.hdel(INFLIGHT, field);
    }
    logger.warn({ recovered: ids.length }, '[queue] recovered inflight jobs');
  }

  private async workerLoop(slot: number): Promise<void> {
    const agent = this.agents[slot]!;
    while (this.running) {
      let raw: [string, string] | null = null;
      try {
        raw = await this.blocking.brpop(QUEUE, 5);
      } catch {
        if (!this.running) break;
        await sleep(500);
        continue;
      }
      if (!raw) continue;
      const job = JSON.parse(raw[1]) as Job;
      const field = `${slot}:${job.commitId}`;
      await this.pub.hset(INFLIGHT, field, raw[1]);
      agent.idle = false;
      agent.repoFullName = job.repoFullName;
      agent.sha = job.sha.slice(0, 7);
      agent.step = '분석 시작';
      this.broadcastAgents();
      try {
        await this.processFn(job.commitId, (step) => {
          agent.step = step;
        });
      } catch (err) {
        await this.onFailure(job, err as Error);
      } finally {
        await this.pub.hdel(INFLIGHT, field);
        agent.idle = true;
        agent.repoFullName = null;
        agent.sha = null;
        agent.step = '유휴';
      }
    }
  }

  private async onFailure(job: Job, err: Error): Promise<void> {
    logger.warn({ sha: job.sha.slice(0, 7), attempt: job.attempt, err: err.message }, '[queue] job failed');
    if (job.attempt < MAX_ATTEMPTS) {
      const next = { ...job, attempt: job.attempt + 1 };
      await sleep(Math.min(1000 * 2 ** job.attempt, 15000));
      await this.pub.lpush(QUEUE, JSON.stringify(next));
    } else {
      await setCommitStatus(job.commitId, 'FAILED');
      broadcast('analysis.failed', { commitId: job.commitId, reason: err.message });
    }
  }

  private broadcastAgents(): void {
    broadcast('agent.tick', this.agents.map((a) => ({
      id: a.id, repoFullName: a.repoFullName, step: a.step, sha: a.sha, idle: a.idle,
    })));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
