// PushEvent → 새 커밋 추출 (순수 함수, 테스트 대상). docs/02 §2·§3.
import type { GhEvent } from '../github/types.js';

export interface DiscoveredCommit {
  sha: string;
  branch: string; // refs/heads/main → main
  message: string;
  authorName: string;
  authorEmail: string;
  oversized: boolean; // size > 20 → compare API 보강 필요
}

export interface ExtractResult {
  commits: DiscoveredCommit[];
  maxEventId: string | null;
}

function gt(a: string, b: string | null): boolean {
  if (b === null) return true;
  try {
    return BigInt(a) > BigInt(b);
  } catch {
    return a > b;
  }
}

export function extractNewCommits(events: GhEvent[], lastEventId: string | null): ExtractResult {
  const pushes = events
    .filter((e) => e.type === 'PushEvent' && gt(e.id, lastEventId))
    .sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : 1)); // 오래된 것부터

  const commits: DiscoveredCommit[] = [];
  let maxEventId = lastEventId;
  for (const ev of pushes) {
    const branch = (ev.payload.ref ?? '').replace(/^refs\/heads\//, '');
    const oversized = (ev.payload.size ?? 0) > 20;
    for (const c of ev.payload.commits ?? []) {
      if (!c.distinct) continue;
      commits.push({
        sha: c.sha, branch, message: c.message,
        authorName: c.author?.name ?? '', authorEmail: c.author?.email ?? '', oversized,
      });
    }
    if (maxEventId === null || gt(ev.id, maxEventId)) maxEventId = ev.id;
  }
  return { commits, maxEventId };
}
