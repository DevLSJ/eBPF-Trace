import type { CommitStatus } from '@scw/shared-types';
import type { GhCommitDetail } from '../github/types.js';
import { pool } from '../db/pool.js';

export interface CommitInsert {
  repoId: number;
  sha: string;
  branch: string | null;
  authorName: string | null;
  authorLogin: string | null;
  authorEmail: string | null;
  message: string;
  committedAt: string | null;
  htmlUrl: string;
  source: string;
  status?: CommitStatus;
  filesChanged?: number;
  additions?: number;
  deletions?: number;
  filesJson?: unknown;
}

export interface InsertedCommit {
  id: number;
  inserted: boolean;
}

// dedup 최종 방어선: ON CONFLICT DO NOTHING + RETURNING으로 실제 삽입 여부 판별 (docs/02 §5).
export async function insertCommit(c: CommitInsert): Promise<InsertedCommit | null> {
  const { rows } = await pool.query<{ id: number }>(
    `INSERT INTO commits (repo_id, sha, branch, author_name, author_login, author_email,
        message, committed_at, html_url, source, status, files_changed, additions, deletions, files_json)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
     ON CONFLICT (repo_id, sha) DO NOTHING
     RETURNING id`,
    [
      c.repoId, c.sha, c.branch, c.authorName, c.authorLogin, c.authorEmail,
      c.message, c.committedAt, c.htmlUrl, c.source, c.status ?? 'QUEUED',
      c.filesChanged ?? null, c.additions ?? null, c.deletions ?? null,
      c.filesJson ? JSON.stringify(c.filesJson) : null,
    ],
  );
  if (rows[0]) return { id: rows[0].id, inserted: true };
  // 이미 존재 → 기존 id 조회
  const existing = await pool.query<{ id: number }>(
    `SELECT id FROM commits WHERE repo_id = $1 AND sha = $2`,
    [c.repoId, c.sha],
  );
  return existing.rows[0] ? { id: existing.rows[0].id, inserted: false } : null;
}

export function fromCommitDetail(
  repoId: number,
  branch: string | null,
  source: string,
  d: GhCommitDetail,
): CommitInsert {
  return {
    repoId,
    sha: d.sha,
    branch,
    authorName: d.commit.author.name,
    authorLogin: d.author?.login ?? null,
    authorEmail: d.commit.author.email,
    message: d.commit.message,
    committedAt: d.commit.author.date,
    htmlUrl: d.html_url,
    source,
    filesChanged: d.files?.length ?? 0,
    additions: d.stats?.additions ?? 0,
    deletions: d.stats?.deletions ?? 0,
    filesJson: d.files?.map((f) => ({
      filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions,
    })),
  };
}

export async function updateCommitDiff(
  commitId: number,
  d: { diffText: string; diffHash: string; sizeBytes: number; truncated: boolean; filesJson: unknown; filesChanged: number; additions: number; deletions: number },
): Promise<void> {
  await pool.query(
    `UPDATE commits SET diff_text=$2, diff_hash=$3, diff_size_bytes=$4, diff_truncated=$5,
       files_json=$6, files_changed=$7, additions=$8, deletions=$9 WHERE id=$1`,
    [commitId, d.diffText, d.diffHash, d.sizeBytes, d.truncated, JSON.stringify(d.filesJson), d.filesChanged, d.additions, d.deletions],
  );
}
