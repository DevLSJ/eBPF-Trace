// 분석 워커: engine 호출 → 저장 → 상태·WS (docs/01 §2, docs/05 §2).
import { request } from 'undici';
import type { AnalysisResult } from '@scw/shared-types';
import { env } from '../env.js';
import { logger } from '../logger.js';
import { insertAnalysis } from '../repo/analyses.js';
import { loadCommitForAnalysis, setCommitStatus } from '../repo/commits.js';
import { broadcast } from '../ws.js';

export async function processCommit(commitId: number, onStep?: (step: string) => void): Promise<void> {
  const c = await loadCommitForAnalysis(commitId);
  if (!c) return;
  await setCommitStatus(commitId, 'ANALYZING');
  broadcast('analysis.started', { commitId, repoFullName: c.repo_full_name, sha: c.sha });
  onStep?.('정적 분석');

  const body = {
    commit: {
      repoFullName: c.repo_full_name, sha: c.sha, branch: c.branch, authorLogin: c.author_login,
      authorName: c.author_name, message: c.message, committedAt: c.committed_at,
      stars: c.stars, defaultBranch: c.default_branch,
    },
    files: Array.isArray(c.files_json) ? c.files_json : [],
    diff: c.diff_text ?? '',
    options: { alwaysLlm: c.always_llm },
  };

  const res = await request(`${env.ENGINE_URL}/analyze`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    headersTimeout: 60_000,
    bodyTimeout: 60_000,
  });
  if (res.statusCode !== 200) {
    const txt = await res.body.text();
    throw new Error(`engine ${res.statusCode}: ${txt.slice(0, 200)}`);
  }
  const result = (await res.body.json()) as AnalysisResult;
  onStep?.('저장');

  const analysisId = await insertAnalysis(commitId, result);
  await setCommitStatus(commitId, 'DONE');

  broadcast('analysis.completed', {
    commitId, analysisId, repoId: undefined, repoFullName: c.repo_full_name,
    sha: c.sha, shortSha: c.sha.slice(0, 7), riskScore: result.riskScore, riskLevel: result.riskLevel,
    tags: result.tags, llmStatus: result.llm.status,
    summaryKo: result.llm.result?.attackNarrativeKo ?? null,
  });
  logger.info({ sha: c.sha.slice(0, 7), level: result.riskLevel, score: result.riskScore }, 'analysis completed');
}
