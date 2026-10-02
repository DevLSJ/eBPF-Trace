import type { RepoMode, RepoStatus } from '@scw/shared-types';
import { pool } from '../db/pool.js';

export interface RepoRow {
  id: number;
  owner: string;
  name: string;
  full_name: string;
  mode: RepoMode;
  status: RepoStatus;
  default_branch: string | null;
  stars: number | null;
  always_llm: boolean;
  poll_interval_s: number;
  etag: string | null;
  last_event_id: string | null;
  last_commit_seen_at: string | null;
  last_sync_at: string | null;
  next_poll_at: string | null;
  rate_limit_remaining: number | null;
  last_error: string | null;
}

const COLS = `id, owner, name, full_name, mode, status, default_branch, stars, always_llm,
  poll_interval_s, etag, last_event_id, last_commit_seen_at, last_sync_at, next_poll_at,
  rate_limit_remaining, last_error`;

export async function listRepos(): Promise<RepoRow[]> {
  const { rows } = await pool.query<RepoRow>(`SELECT ${COLS} FROM repositories ORDER BY id`);
  return rows;
}

export async function getRepoById(id: number): Promise<RepoRow | null> {
  const { rows } = await pool.query<RepoRow>(`SELECT ${COLS} FROM repositories WHERE id = $1`, [id]);
  return rows[0] ?? null;
}

export async function activeRepos(mode?: RepoMode): Promise<RepoRow[]> {
  const where = mode
    ? `status IN ('ACTIVE','REGISTERED','RATE_LIMITED') AND mode = '${mode}'`
    : `status IN ('ACTIVE','REGISTERED','RATE_LIMITED')`;
  const { rows } = await pool.query<RepoRow>(`SELECT ${COLS} FROM repositories WHERE ${where} ORDER BY id`);
  return rows;
}

export async function insertRepo(params: {
  owner: string;
  name: string;
  mode: RepoMode;
  alwaysLlm: boolean;
  pollIntervalS: number;
  defaultBranch: string | null;
  stars: number | null;
}): Promise<RepoRow> {
  const { rows } = await pool.query<RepoRow>(
    `INSERT INTO repositories (owner, name, mode, status, default_branch, stars, always_llm, poll_interval_s, next_poll_at)
     VALUES ($1,$2,$3,'ACTIVE',$4,$5,$6,$7, now())
     ON CONFLICT (owner, name) DO UPDATE SET
       mode = EXCLUDED.mode, always_llm = EXCLUDED.always_llm, poll_interval_s = EXCLUDED.poll_interval_s,
       default_branch = EXCLUDED.default_branch, stars = EXCLUDED.stars, status = 'ACTIVE', updated_at = now()
     RETURNING ${COLS}`,
    [params.owner, params.name, params.mode, params.defaultBranch, params.stars, params.alwaysLlm, params.pollIntervalS],
  );
  return rows[0]!;
}

export async function updateRepo(
  id: number,
  patch: Partial<Pick<RepoRow, 'mode' | 'poll_interval_s' | 'always_llm' | 'status'>>,
): Promise<RepoRow | null> {
  const sets: string[] = [];
  const vals: unknown[] = [];
  let i = 1;
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined) continue;
    sets.push(`${k} = $${i++}`);
    vals.push(v);
  }
  if (!sets.length) return getRepoById(id);
  vals.push(id);
  const { rows } = await pool.query<RepoRow>(
    `UPDATE repositories SET ${sets.join(', ')}, updated_at = now() WHERE id = $${i} RETURNING ${COLS}`,
    vals,
  );
  return rows[0] ?? null;
}

export async function deleteRepo(id: number): Promise<boolean> {
  const { rowCount } = await pool.query(`DELETE FROM repositories WHERE id = $1`, [id]);
  return (rowCount ?? 0) > 0;
}

// 폴링 스케줄러가 갱신하는 동기화 상태 (feature 3에서 사용)
export async function updateSyncState(
  id: number,
  s: {
    etag?: string | null;
    lastEventId?: string | null;
    status?: RepoStatus;
    rateLimitRemaining?: number | null;
    nextPollAt?: Date;
    lastError?: string | null;
  },
): Promise<void> {
  await pool.query(
    `UPDATE repositories SET
       etag = COALESCE($2, etag),
       last_event_id = COALESCE($3, last_event_id),
       status = COALESCE($4, status),
       rate_limit_remaining = COALESCE($5, rate_limit_remaining),
       next_poll_at = COALESCE($6, next_poll_at),
       last_error = $7,
       last_sync_at = now(), updated_at = now()
     WHERE id = $1`,
    [id, s.etag ?? null, s.lastEventId ?? null, s.status ?? null, s.rateLimitRemaining ?? null, s.nextPollAt ?? null, s.lastError ?? null],
  );
}
