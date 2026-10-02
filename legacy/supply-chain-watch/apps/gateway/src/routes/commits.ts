import { Router, type Router as ExpressRouter } from 'express';
import { pool } from '../db/pool.js';

export const commitsRouter: ExpressRouter = Router();

// 피드: v_commit_latest 기반 최신순 (docs/05 §1.2)
commitsRouter.get('/', async (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 50), 200);
  const levels = String(req.query.level ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const repoId = req.query.repoId ? Number(req.query.repoId) : null;

  const where: string[] = [];
  const params: unknown[] = [];
  let i = 1;
  if (levels.length) {
    where.push(`v.risk_level = ANY($${i++}::text[])`);
    params.push(levels);
  }
  if (repoId) {
    where.push(`v.repo_id = $${i++}`);
    params.push(repoId);
  }
  params.push(limit);

  const { rows } = await pool.query(
    `SELECT v.id, v.repo_id, r.full_name AS repo_full_name, v.sha, v.branch,
            v.author_login, v.author_name, v.message, v.committed_at, v.received_at,
            v.status, v.source, v.html_url, v.files_changed, v.additions, v.deletions,
            v.analysis_id, v.risk_score, v.risk_level, v.tags, v.llm_status
     FROM v_commit_latest v JOIN repositories r ON r.id = v.repo_id
     ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
     ORDER BY v.received_at DESC LIMIT $${i}`,
    params,
  );
  res.json({ ok: true, data: rows.map(toSummary) });
});

commitsRouter.get('/:id', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT v.*, r.full_name AS repo_full_name FROM v_commit_latest v
     JOIN repositories r ON r.id = v.repo_id WHERE v.id = $1`,
    [Number(req.params.id)],
  );
  if (!rows[0]) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: '없는 커밋' } });
  const c = rows[0];
  const a = await pool.query(
    `SELECT * FROM analyses WHERE commit_id = $1 ORDER BY attempt DESC LIMIT 1`,
    [Number(req.params.id)],
  );
  res.json({ ok: true, data: { commit: toSummary(c), diffText: c.diff_text, filesJson: c.files_json, analysis: a.rows[0] ?? null } });
});

interface Row {
  id: number; repo_id: number; repo_full_name: string; sha: string; branch: string | null;
  author_login: string | null; author_name: string | null; message: string;
  committed_at: string | null; received_at: string; status: string; source: string;
  html_url: string; files_changed: number | null; additions: number | null; deletions: number | null;
  analysis_id: number | null; risk_score: number | null; risk_level: string | null;
  tags: string[] | null; llm_status: string | null;
}

function toSummary(c: Row) {
  return {
    id: c.id, repoId: c.repo_id, repoFullName: c.repo_full_name, sha: c.sha,
    shortSha: (c.sha ?? '').slice(0, 7), branch: c.branch, authorLogin: c.author_login,
    authorName: c.author_name, message: c.message, committedAt: c.committed_at, receivedAt: c.received_at,
    status: c.status, source: c.source, htmlUrl: c.html_url,
    filesChanged: c.files_changed ?? 0, additions: c.additions ?? 0, deletions: c.deletions ?? 0,
    analysisId: c.analysis_id, riskScore: c.risk_score, riskLevel: c.risk_level,
    tags: c.tags ?? [], llmStatus: c.llm_status,
  };
}
