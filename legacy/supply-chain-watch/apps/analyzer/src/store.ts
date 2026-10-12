// analyzer가 쓰는 DB 접근 — 분석 대상 커밋 로드, 상태 변경, 결과 저장 (gateway에서 이전, ADR-020 U5).
import type { AnalysisResult, CommitStatus } from '@scw/shared-types';
import { pool } from './db.js';

export interface CommitForAnalysis {
  id: number;
  repo_full_name: string;
  owner: string;
  name: string;
  sha: string;
  branch: string | null;
  author_login: string | null;
  author_name: string | null;
  message: string;
  committed_at: string | null;
  html_url: string;
  diff_text: string | null;
  files_json: unknown;
  always_llm: boolean;
  default_branch: string | null;
  stars: number | null;
}

export async function loadCommitForAnalysis(commitId: number): Promise<CommitForAnalysis | null> {
  const { rows } = await pool.query<CommitForAnalysis>(
    `SELECT c.id, r.full_name AS repo_full_name, r.owner, r.name, c.sha, c.branch,
            c.author_login, c.author_name, c.message, c.committed_at, c.html_url,
            c.diff_text, c.files_json, r.always_llm, r.default_branch, r.stars
     FROM commits c JOIN repositories r ON r.id = c.repo_id WHERE c.id = $1`,
    [commitId],
  );
  return rows[0] ?? null;
}

export async function setCommitStatus(commitId: number, status: CommitStatus): Promise<void> {
  await pool.query(`UPDATE commits SET status = $2 WHERE id = $1`, [commitId, status]);
}

export async function insertAnalysis(commitId: number, result: AnalysisResult): Promise<number> {
  const summaryKo = result.llm.result?.attackNarrativeKo ?? null;
  const { rows } = await pool.query<{ id: number; attempt: number }>(
    `INSERT INTO analyses (commit_id, attempt, risk_score, risk_level, tags, static_score, static_level,
        matched_rules, sensitive_files, llm_status, llm_model, llm_result, prompt_version,
        llm_input_tokens, llm_output_tokens, llm_cache_read_tokens, llm_latency_ms, static_latency_ms)
     VALUES ($1,
        (SELECT COALESCE(MAX(attempt),0)+1 FROM analyses WHERE commit_id=$1),
        $2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
     RETURNING id, attempt`,
    [
      commitId, result.riskScore, result.riskLevel, result.tags,
      result.static.score, result.static.level, JSON.stringify(result.static.matchedRules),
      result.static.sensitiveFiles, result.llm.status, result.llm.model ?? null,
      result.llm.result ? JSON.stringify({ ...result.llm.result, _summaryKo: summaryKo }) : null,
      result.llm.promptVersion ?? null,
      result.llm.usage?.inputTokens ?? null, result.llm.usage?.outputTokens ?? null,
      result.llm.usage?.cacheReadTokens ?? null, result.llm.latencyMs ?? null, result.static.latencyMs,
    ],
  );
  return rows[0]!.id;
}
