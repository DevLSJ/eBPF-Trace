import type { AnalysisResult } from '@scw/shared-types';
import { pool } from '../db/pool.js';

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
