import { Router, type Router as ExpressRouter } from 'express';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { analysisQueue } from '../analysis/index.js';
import { broadcast } from '../ws.js';

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
  const id = Number(req.params.id);
  const { rows } = await pool.query(
    `SELECT v.*, r.full_name AS repo_full_name, r.default_branch, r.stars, r.mode AS repo_mode
     FROM v_commit_latest v JOIN repositories r ON r.id = v.repo_id WHERE v.id = $1`,
    [id],
  );
  if (!rows[0]) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: '없는 커밋' } });
  const c = rows[0];
  const a = await pool.query(`SELECT * FROM analyses WHERE commit_id = $1 ORDER BY attempt DESC LIMIT 1`, [id]);
  const attempts = await pool.query(
    `SELECT attempt, risk_score, risk_level, llm_status, llm_model, created_at FROM analyses WHERE commit_id = $1 ORDER BY attempt`,
    [id],
  );
  res.json({
    ok: true,
    data: {
      commit: toSummary(c),
      repo: { fullName: c.repo_full_name, defaultBranch: c.default_branch, stars: c.stars, mode: c.repo_mode },
      diffText: c.diff_text,
      diffTruncated: c.diff_truncated,
      files: c.files_json ?? [],
      analysis: a.rows[0] ? toAnalysis(a.rows[0]) : null,
      attempts: attempts.rows.map((r) => ({
        attempt: r.attempt, riskScore: r.risk_score, riskLevel: r.risk_level, llmStatus: r.llm_status, llmModel: r.llm_model, createdAt: r.created_at,
      })),
    },
  });
});

// 다시 분석 — 게이트·캐시와 무관하게 AI 정밀 분석까지 (docs/06 §4 액션)
commitsRouter.post('/:id/reanalyze', async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await pool.query(
    `SELECT c.id, c.sha, r.full_name FROM commits c JOIN repositories r ON r.id = c.repo_id WHERE c.id = $1`,
    [id],
  );
  if (!rows[0]) return res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: '없는 커밋' } });
  await pool.query(`UPDATE commits SET status = 'QUEUED' WHERE id = $1`, [id]);
  await analysisQueue.enqueue({ commitId: id, repoFullName: rows[0].full_name, sha: rows[0].sha, forceLlm: true });
  broadcast('analysis.started', { commitId: id, repoFullName: rows[0].full_name, sha: rows[0].sha, queued: true });
  res.status(202).json({ ok: true, data: { queued: true } });
});

// 사람 판정 — 정탐/오탐 (docs/03 §7). 오탐 사례는 룰·프롬프트 튜닝 근거
commitsRouter.post('/:id/verdict', async (req, res) => {
  const parsed = z.object({ verdict: z.enum(['TRUE_POSITIVE', 'FALSE_POSITIVE']).nullable() }).safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: { code: 'BAD_VERDICT', message: '정탐 또는 오탐만 선택할 수 있습니다' } });
  const { rowCount } = await pool.query(
    `UPDATE analyses SET verdict_by_user = $2
     WHERE id = (SELECT id FROM analyses WHERE commit_id = $1 ORDER BY attempt DESC LIMIT 1)`,
    [Number(req.params.id), parsed.data.verdict],
  );
  if (!rowCount) return res.status(404).json({ ok: false, error: { code: 'NO_ANALYSIS', message: '아직 분석 결과가 없습니다' } });
  res.json({ ok: true, data: { verdict: parsed.data.verdict } });
});

interface AnalysisRow {
  id: number; attempt: number; risk_score: number; risk_level: string; tags: string[]; static_score: number;
  static_level: string; matched_rules: unknown; sensitive_files: string[]; llm_status: string; llm_model: string | null;
  llm_result: Record<string, unknown> | null; prompt_version: number | null; llm_input_tokens: number | null;
  llm_output_tokens: number | null; llm_cache_read_tokens: number | null; llm_latency_ms: number | null;
  static_latency_ms: number | null; verdict_by_user: string | null; created_at: string;
}

function toAnalysis(a: AnalysisRow) {
  const r = a.llm_result ?? null;
  const { _summaryKo, _stages, _gateReasons, ...llm } = (r ?? {}) as Record<string, unknown>;
  return {
    id: a.id, attempt: a.attempt, riskScore: a.risk_score, riskLevel: a.risk_level, tags: a.tags ?? [],
    staticScore: a.static_score, staticLevel: a.static_level, matchedRules: a.matched_rules ?? [],
    sensitiveFiles: a.sensitive_files ?? [], llmStatus: a.llm_status, llmModel: a.llm_model,
    llm: r ? llm : null, stages: (_stages as unknown[]) ?? [], gateReasons: (_gateReasons as string[]) ?? [],
    promptVersion: a.prompt_version,
    usage: { inputTokens: a.llm_input_tokens ?? 0, outputTokens: a.llm_output_tokens ?? 0, cacheReadTokens: a.llm_cache_read_tokens ?? 0 },
    llmLatencyMs: a.llm_latency_ms, staticLatencyMs: a.static_latency_ms, verdict: a.verdict_by_user, createdAt: a.created_at,
  };
}

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
