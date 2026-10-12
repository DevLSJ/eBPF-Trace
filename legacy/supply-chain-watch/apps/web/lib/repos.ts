import { api } from './api';

export type RepoMode = 'polling' | 'webhook';

export interface Repo {
  id: number; owner: string; name: string; fullName: string; mode: RepoMode; status: string;
  defaultBranch: string | null; stars: number | null; alwaysLlm: boolean; pollIntervalS: number;
  lastSyncAt: string | null; nextPollAt: string | null; rateLimitRemaining: number | null; lastError: string | null;
}

export interface RepoPreview {
  repo: { fullName: string; defaultBranch: string; stars: number; description: string | null };
  commits: { sha: string; message: string; authorLogin: string | null; committedAt: string }[];
}

const json = (body: unknown): RequestInit => ({
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
});

export const listRepos = () => api<Repo[]>('/api/repos');
export const inspectRepo = (url: string) => api<RepoPreview>('/api/repos/inspect', json({ url }));
export const registerRepo = (url: string, mode: RepoMode) => api<Repo>('/api/repos', json({ url, mode }));
export const setRepoPaused = (id: number, paused: boolean) =>
  api<Repo>(`/api/repos/${id}`, {
    method: 'PATCH', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ status: paused ? 'PAUSED' : 'ACTIVE' }),
  });
export const deleteRepo = (id: number) => api<{ deleted: boolean }>(`/api/repos/${id}`, { method: 'DELETE' });

// 입력창의 여러 URL(쉼표·공백·줄바꿈 구분)을 분리. 화면에서 owner/repo 형태만 미리 거른다.
export function splitRepoInputs(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean))];
}

export function looksLikeRepo(s: string): boolean {
  return /^(https?:\/\/)?(www\.)?(github\.com\/)?[\w.-]+\/[\w.-]+(\.git)?\/?$/i.test(s.trim());
}

// docs/06 §0.9 쉬운 용어
export const MODE_LABEL: Record<RepoMode, string> = { polling: '주기 확인', webhook: '즉시 수신' };

export function repoStatusView(status: string): { label: string; tone: 'good' | 'warn' | 'crit' | 'muted' } {
  if (status === 'ACTIVE') return { label: '검사 중', tone: 'good' };
  if (status === 'PAUSED') return { label: '일시정지', tone: 'muted' };
  if (status === 'RATE_LIMITED') return { label: '요청 한도 대기', tone: 'warn' };
  return { label: '오류', tone: 'crit' };
}
