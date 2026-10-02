// GitHub REST 응답 중 수집에 쓰는 필드만 (docs/02).

export interface GhRepo {
  id: number;
  name: string;
  full_name: string;
  default_branch: string;
  stargazers_count: number;
  description: string | null;
  owner: { login: string };
}

export interface GhPushEventCommit {
  sha: string;
  message: string;
  distinct: boolean;
  author: { name: string; email: string };
}

export interface GhPushEventPayload {
  ref: string;
  head: string;
  before: string;
  size: number;
  commits: GhPushEventCommit[];
}

export interface GhEvent {
  id: string;
  type: string;
  actor: { login: string };
  payload: GhPushEventPayload;
  created_at: string;
}

export interface GhCommitFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  patch?: string;
}

export interface GhCommitDetail {
  sha: string;
  html_url: string;
  commit: {
    message: string;
    author: { name: string; email: string; date: string };
  };
  author: { login: string } | null;
  stats: { additions: number; deletions: number; total: number };
  files: GhCommitFile[];
}

export interface RateLimit {
  remaining: number;
  limit: number;
  resetAt: number; // epoch seconds
}
