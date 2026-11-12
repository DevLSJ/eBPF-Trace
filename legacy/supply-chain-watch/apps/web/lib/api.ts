import { GATEWAY_URL } from './utils';

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${GATEWAY_URL}${path}`, { credentials: 'include', ...init });
  const body = (await res.json().catch(() => null)) as { ok: boolean; data?: T; error?: { message: string } } | null;
  // 서버가 준 한글 사유를 그대로 화면에 쓸 수 있게 전달
  if (!res.ok || !body?.ok) throw new Error(body?.error?.message ?? `${path} ${res.status}`);
  return body.data as T;
}

export interface CommitFeedItem {
  id: number; repoId: number; repoFullName: string; sha: string; shortSha: string;
  branch: string | null; authorLogin: string | null; authorName: string | null; message: string;
  committedAt: string | null; receivedAt: string; status: string; source: string; htmlUrl: string;
  filesChanged: number; additions: number; deletions: number;
  analysisId: number | null; riskScore: number | null; riskLevel: string | null;
  tags: string[]; llmStatus: string | null;
}

export interface Overview {
  repos: { total: number; active: number; rate_limited: number; paused: number };
  today: { commits: number; high: number; medium: number; low: number; llm_calls: number };
  engine: { healthy: boolean; model?: string };
}
