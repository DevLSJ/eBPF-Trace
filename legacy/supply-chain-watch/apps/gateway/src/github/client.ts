// GitHub REST 클라이언트: 인증, ETag, Rate Limit, 백오프, 타임아웃 (docs/02 §1·§2, skill).
import { request } from 'undici';
import { env } from '../env.js';
import { logger } from '../logger.js';
import type { GhCommitDetail, GhEvent, GhRepo, RateLimit } from './types.js';

const API = 'https://api.github.com';
const TIMEOUT_MS = 10_000;

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly rateLimited = false,
    readonly resetAt?: number,
  ) {
    super(message);
    this.name = 'GitHubError';
  }
}

function baseHeaders(accept = 'application/vnd.github+json'): Record<string, string> {
  const h: Record<string, string> = {
    Accept: accept,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'supply-chain-watch',
  };
  if (env.GITHUB_TOKEN) h.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  return h;
}

function parseRate(headers: Record<string, string | string[] | undefined>): RateLimit | undefined {
  const rem = headers['x-ratelimit-remaining'];
  const lim = headers['x-ratelimit-limit'];
  const reset = headers['x-ratelimit-reset'];
  if (rem === undefined) return undefined;
  return {
    remaining: Number(rem),
    limit: Number(lim ?? 0),
    resetAt: Number(reset ?? 0),
  };
}

function header(headers: Record<string, string | string[] | undefined>, k: string): string | undefined {
  const v = headers[k];
  return Array.isArray(v) ? v[0] : v;
}

export interface GhResponse<T> {
  status: number;
  data: T | null;
  etag?: string;
  pollInterval?: number;
  rateLimit?: RateLimit;
  rawText?: string;
}

async function call<T>(
  path: string,
  opts: { accept?: string; etag?: string; parse?: 'json' | 'text' } = {},
): Promise<GhResponse<T>> {
  const headers = baseHeaders(opts.accept);
  if (opts.etag) headers['If-None-Match'] = opts.etag;

  const res = await request(`${API}${path}`, {
    method: 'GET',
    headers,
    headersTimeout: TIMEOUT_MS,
    bodyTimeout: TIMEOUT_MS,
  });

  const rateLimit = parseRate(res.headers);
  const status = res.statusCode;

  if (status === 304) {
    await res.body.dump();
    return { status, data: null, etag: opts.etag, rateLimit };
  }
  if (status === 403 || status === 429) {
    await res.body.dump();
    const resetAt = rateLimit?.resetAt;
    const retryAfter = header(res.headers, 'retry-after');
    logger.warn({ path, status, remaining: rateLimit?.remaining }, 'github rate limited');
    throw new GitHubError(
      `rate limited (${status})`,
      status,
      true,
      retryAfter ? Math.floor(Date.now() / 1000) + Number(retryAfter) : resetAt,
    );
  }
  if (status >= 400) {
    const text = await res.body.text();
    throw new GitHubError(`github ${status}: ${text.slice(0, 200)}`, status);
  }

  const etag = header(res.headers, 'etag');
  const pollIntervalRaw = header(res.headers, 'x-poll-interval');
  const pollInterval = pollIntervalRaw ? Number(pollIntervalRaw) : undefined;

  if (opts.parse === 'text') {
    const rawText = await res.body.text();
    return { status, data: null, etag, pollInterval, rateLimit, rawText };
  }
  const data = (await res.body.json()) as T;
  return { status, data, etag, pollInterval, rateLimit };
}

export const github = {
  async getRepo(owner: string, name: string): Promise<GhResponse<GhRepo>> {
    return call<GhRepo>(`/repos/${owner}/${name}`);
  },

  async getEvents(owner: string, name: string, etag?: string): Promise<GhResponse<GhEvent[]>> {
    return call<GhEvent[]>(`/repos/${owner}/${name}/events?per_page=30`, { etag });
  },

  async getCommitDetail(owner: string, name: string, sha: string): Promise<GhResponse<GhCommitDetail>> {
    return call<GhCommitDetail>(`/repos/${owner}/${name}/commits/${sha}`);
  },

  async getCommitDiff(owner: string, name: string, sha: string): Promise<string> {
    const res = await call<never>(`/repos/${owner}/${name}/commits/${sha}`, {
      accept: 'application/vnd.github.v3.diff',
      parse: 'text',
    });
    return res.rawText ?? '';
  },

  async getRecentCommits(
    owner: string,
    name: string,
    opts: { since?: string; sha?: string; perPage?: number } = {},
  ): Promise<GhResponse<GhCommitDetail[]>> {
    const q = new URLSearchParams();
    if (opts.since) q.set('since', opts.since);
    if (opts.sha) q.set('sha', opts.sha);
    q.set('per_page', String(opts.perPage ?? 5));
    return call<GhCommitDetail[]>(`/repos/${owner}/${name}/commits?${q.toString()}`);
  },

  async getRateLimit(): Promise<RateLimit | undefined> {
    const res = await call<unknown>('/rate_limit');
    return res.rateLimit;
  },
};
