// 레포별 폴링 스케줄러 (docs/02 §3, skill). 레포 단위 next_poll_at, p-limit 동시성, X-Poll-Interval.
import pLimit from 'p-limit';
import { github, GitHubError } from '../github/client.js';
import { logger } from '../logger.js';
import { activeRepos, updateSyncState, type RepoRow } from '../repo/repos.js';
import { broadcast } from '../ws.js';
import { extractNewCommits } from './events.js';

const LIMIT = pLimit(4);
const TICK_MS = 5_000;

type OnNewCommit = (repo: RepoRow, sha: string, branch: string) => Promise<void>;

export class PollingScheduler {
  private timer: ReturnType<typeof setInterval> | null = null;
  constructor(private onNewCommit: OnNewCommit) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), TICK_MS);
    logger.info('[polling] scheduler started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private async tick(): Promise<void> {
    let repos: RepoRow[];
    try {
      repos = await activeRepos('polling');
    } catch (err) {
      logger.error({ err: (err as Error).message }, '[polling] load repos failed');
      return;
    }
    const now = Date.now();
    const due = repos.filter((r) => !r.next_poll_at || new Date(r.next_poll_at).getTime() <= now);
    await Promise.all(due.map((r) => LIMIT(() => this.pollRepo(r))));
  }

  async pollRepo(repo: RepoRow): Promise<void> {
    try {
      const res = await github.getEvents(repo.owner, repo.name, repo.etag ?? undefined);
      const remaining = res.rateLimit?.remaining ?? null;

      // 간격 보정: X-Poll-Interval, 쿼터 부족 시 2배
      let intervalS = repo.poll_interval_s;
      if (res.pollInterval && res.pollInterval > intervalS) intervalS = res.pollInterval;
      if (remaining !== null && remaining < 100) intervalS *= 2;
      const nextPollAt = new Date(Date.now() + intervalS * 1000);

      if (res.status === 304) {
        await updateSyncState(repo.id, { status: 'ACTIVE', rateLimitRemaining: remaining, nextPollAt, lastError: null });
        return;
      }

      const { commits, maxEventId } = extractNewCommits(res.data ?? [], repo.last_event_id);
      for (const c of commits) {
        await this.onNewCommit(repo, c.sha, c.branch);
      }
      await updateSyncState(repo.id, {
        etag: res.etag ?? null, lastEventId: maxEventId, status: 'ACTIVE',
        rateLimitRemaining: remaining, nextPollAt, lastError: null,
      });
      broadcast('repo.status', {
        repoId: repo.id, status: 'ACTIVE', lastSyncAt: new Date().toISOString(), rateLimitRemaining: remaining,
      });
      if (commits.length) logger.info({ repo: repo.full_name, newCommits: commits.length }, '[polling] new commits');
    } catch (err) {
      if (err instanceof GitHubError && err.rateLimited) {
        const resetMs = (err.resetAt ?? Math.floor(Date.now() / 1000) + 60) * 1000;
        await updateSyncState(repo.id, { status: 'RATE_LIMITED', nextPollAt: new Date(resetMs), lastError: 'rate limited' });
        broadcast('repo.status', { repoId: repo.id, status: 'RATE_LIMITED', lastError: 'rate limited' });
        return;
      }
      const status = err instanceof GitHubError && err.status === 404 ? 'NOT_FOUND' : 'ERROR';
      await updateSyncState(repo.id, {
        status, nextPollAt: new Date(Date.now() + repo.poll_interval_s * 2000), lastError: (err as Error).message,
      });
      logger.warn({ repo: repo.full_name, err: (err as Error).message }, '[polling] repo poll failed');
    }
  }
}
