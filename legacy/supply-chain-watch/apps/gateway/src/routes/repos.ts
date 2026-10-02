import { Router, type Router as ExpressRouter } from 'express';
import { z } from 'zod';
import { github, GitHubError } from '../github/client.js';
import { parseRepoInput } from '../util/parse.js';
import { logger } from '../logger.js';
import {
  deleteRepo, insertRepo, listRepos, updateRepo, type RepoRow,
} from '../repo/repos.js';
import { handleNewCommit } from '../collector/handle.js';
import { broadcast } from '../ws.js';

export const reposRouter: ExpressRouter = Router();

const registerBody = z.object({
  fullName: z.string().optional(),
  url: z.string().optional(),
  mode: z.enum(['polling', 'webhook']).default('polling'),
  alwaysLlm: z.boolean().default(false),
  pollIntervalS: z.number().int().min(10).max(3600).default(15),
});

function viewRepo(r: RepoRow) {
  return {
    id: r.id, owner: r.owner, name: r.name, fullName: r.full_name, mode: r.mode, status: r.status,
    defaultBranch: r.default_branch, stars: r.stars, alwaysLlm: r.always_llm, pollIntervalS: r.poll_interval_s,
    lastSyncAt: r.last_sync_at, nextPollAt: r.next_poll_at, rateLimitRemaining: r.rate_limit_remaining,
    lastError: r.last_error,
  };
}

reposRouter.get('/', async (_req, res) => {
  res.json({ ok: true, data: (await listRepos()).map(viewRepo) });
});

// 등록 없이 즉시 검사용 메타 + 최근 커밋 (docs/05 §1.4a)
reposRouter.post('/inspect', async (req, res) => {
  const input = (req.body?.url ?? req.body?.fullName ?? '') as string;
  const parsed = parseRepoInput(input);
  if (!parsed) return res.status(400).json({ ok: false, error: { code: 'BAD_URL', message: 'owner/repo 형식이 아닙니다' } });
  try {
    const meta = await github.getRepo(parsed.owner, parsed.name);
    if (!meta.data) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: '레포를 찾을 수 없습니다' } });
    const recent = await github.getRecentCommits(parsed.owner, parsed.name, { perPage: 20 });
    return res.json({
      ok: true,
      data: {
        repo: { fullName: meta.data.full_name, defaultBranch: meta.data.default_branch, stars: meta.data.stargazers_count, description: meta.data.description },
        commits: (recent.data ?? []).map((c) => ({ sha: c.sha, message: c.commit.message, authorLogin: c.author?.login ?? null, committedAt: c.commit.author.date })),
      },
    });
  } catch (err) {
    return handleGhError(err, res);
  }
});

reposRouter.post('/', async (req, res) => {
  const parse = registerBody.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ ok: false, error: { code: 'BAD_BODY', message: parse.error.message } });
  const body = parse.data;
  const parsed = parseRepoInput(body.url ?? body.fullName ?? '');
  if (!parsed) return res.status(400).json({ ok: false, error: { code: 'BAD_URL', message: 'owner/repo 형식이 아닙니다' } });

  try {
    const meta = await github.getRepo(parsed.owner, parsed.name);
    if (!meta.data) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: '레포를 찾을 수 없습니다' } });

    const repo = await insertRepo({
      owner: parsed.owner, name: parsed.name, mode: body.mode, alwaysLlm: body.alwaysLlm,
      pollIntervalS: body.pollIntervalS, defaultBranch: meta.data.default_branch, stars: meta.data.stargazers_count,
    });

    // 백필: 최근 5건을 'backfill' 소스로 적재 (정적 분석은 Phase 3 큐가 처리). 응답은 즉시.
    void backfill(repo, parsed.owner, parsed.name, meta.data.default_branch);

    broadcast('repo.status', { repoId: repo.id, status: repo.status, fullName: repo.full_name });
    return res.status(201).json({ ok: true, data: viewRepo(repo) });
  } catch (err) {
    return handleGhError(err, res);
  }
});

reposRouter.patch('/:id', async (req, res) => {
  const id = Number(req.params.id);
  const patch = z.object({
    mode: z.enum(['polling', 'webhook']).optional(),
    pollIntervalS: z.number().int().min(10).max(3600).optional(),
    alwaysLlm: z.boolean().optional(),
    status: z.enum(['ACTIVE', 'PAUSED']).optional(),
  }).parse(req.body ?? {});
  const updated = await updateRepo(id, {
    mode: patch.mode, poll_interval_s: patch.pollIntervalS, always_llm: patch.alwaysLlm, status: patch.status,
  });
  if (!updated) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: '없는 레포' } });
  broadcast('repo.status', { repoId: updated.id, status: updated.status, fullName: updated.full_name });
  res.json({ ok: true, data: viewRepo(updated) });
});

reposRouter.delete('/:id', async (req, res) => {
  const ok = await deleteRepo(Number(req.params.id));
  res.status(ok ? 200 : 404).json({ ok, data: { deleted: ok } });
});

async function backfill(repo: RepoRow, owner: string, name: string, branch: string): Promise<void> {
  try {
    const recent = await github.getRecentCommits(owner, name, { perPage: 5, sha: branch });
    // 오래된 것부터 처리(피드 순서) — dedup·diff·enqueue는 handleNewCommit이 담당
    for (const item of [...(recent.data ?? [])].reverse()) {
      await handleNewCommit(repo, item.sha, branch, 'backfill');
    }
    logger.info({ repo: repo.full_name }, 'backfill done');
  } catch (err) {
    logger.warn({ repo: repo.full_name, err: (err as Error).message }, 'backfill failed');
  }
}

function handleGhError(err: unknown, res: import('express').Response) {
  if (err instanceof GitHubError) {
    if (err.rateLimited) return res.status(429).json({ ok: false, error: { code: 'RATE_LIMITED', message: 'GitHub rate limit', resetAt: err.resetAt } });
    return res.status(err.status).json({ ok: false, error: { code: 'GITHUB', message: err.message } });
  }
  logger.error({ err: (err as Error).message }, 'repos route error');
  return res.status(500).json({ ok: false, error: { code: 'INTERNAL', message: '서버 오류' } });
}
