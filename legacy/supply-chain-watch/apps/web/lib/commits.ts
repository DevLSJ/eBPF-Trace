import { api, type CommitFeedItem } from './api';

export interface Evidence { file: string; lineHint: string; reasonKo: string }
export interface LlmReport {
  riskScore: number; riskLevel: string; detectedTags: string[]; attackNarrativeKo: string;
  evidence: Evidence[]; benignExplanationKo: string | null; confidence: number; recommendedActionKo: string;
}
export interface MatchedRuleView {
  ruleId: string; category: string; severity: string; file: string; snippet: string; lineHint: string;
  count?: number; descriptionKo?: string;
}
export interface Stage { model: string; status: string; riskScore?: number | null; latencyMs?: number; error?: string | null }
export interface AnalysisView {
  id: number; attempt: number; riskScore: number; riskLevel: string; tags: string[];
  staticScore: number; staticLevel: string; matchedRules: MatchedRuleView[]; sensitiveFiles: string[];
  llmStatus: string; llmModel: string | null; llm: LlmReport | null; stages: Stage[]; gateReasons: string[];
  promptVersion: number | null; usage: { inputTokens: number; outputTokens: number; cacheReadTokens: number };
  llmLatencyMs: number | null; staticLatencyMs: number | null; verdict: string | null; createdAt: string;
}
export interface CommitDetail {
  commit: CommitFeedItem;
  repo: { fullName: string; defaultBranch: string | null; stars: number | null; mode: string };
  diffText: string | null;
  diffTruncated: boolean;
  files: { filename: string; status: string; additions: number; deletions: number }[];
  analysis: AnalysisView | null;
  attempts: { attempt: number; riskScore: number; riskLevel: string; llmStatus: string; llmModel: string | null; createdAt: string }[];
}

export const getCommit = (id: string | number) => api<CommitDetail>(`/api/commits/${id}`);
export const listCommits = (limit = 50) => api<CommitFeedItem[]>(`/api/commits?limit=${limit}`);
export const reanalyze = (id: number) => api<{ queued: boolean }>(`/api/commits/${id}/reanalyze`, { method: 'POST' });
export const setVerdict = (id: number, verdict: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | null) =>
  api<{ verdict: string | null }>(`/api/commits/${id}/verdict`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ verdict }),
  });

// 화면 용어 (docs/06 §0.9)
export const LLM_STATUS_LABEL: Record<string, string> = {
  OK: 'AI 정밀 분석 완료',
  CACHED: '같은 변경의 이전 AI 결과 재사용',
  SKIPPED_GATE: 'AI 분석 생략 — 정적 검사에서 의심 신호 없음',
  SKIPPED_BUDGET: 'AI 분석 생략 — 시간당 사용 한도',
  REFUSED: 'AI가 분석을 거절 — 정적 검사 결과 기준',
  ERROR: 'AI 분석 실패 — 정적 검사 결과 기준',
};
export const SEVERITY_LABEL: Record<string, string> = { CRITICAL: '치명', HIGH: '위험', MEDIUM: '주의', LOW: '참고' };
