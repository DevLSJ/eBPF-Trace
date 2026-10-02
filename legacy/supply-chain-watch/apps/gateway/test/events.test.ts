import { describe, expect, it } from 'vitest';
import { extractNewCommits } from '../src/collector/events.js';
import type { GhEvent } from '../src/github/types.js';

function pushEvent(id: string, ref: string, commits: Array<{ sha: string; distinct: boolean }>, size = commits.length): GhEvent {
  return {
    id, type: 'PushEvent', actor: { login: 'x' }, created_at: '2026-10-02T00:00:00Z',
    payload: { ref, head: 'h', before: 'b', size, commits: commits.map((c) => ({ ...c, message: 'm', author: { name: 'n', email: 'e' } })) },
  };
}

describe('extractNewCommits', () => {
  it('distinct=false 커밋은 건너뛴다', () => {
    const ev = [pushEvent('100', 'refs/heads/main', [{ sha: 'a', distinct: true }, { sha: 'b', distinct: false }])];
    const r = extractNewCommits(ev, null);
    expect(r.commits.map((c) => c.sha)).toEqual(['a']);
    expect(r.commits[0]!.branch).toBe('main');
  });

  it('lastEventId 이하 이벤트는 무시한다', () => {
    const ev = [pushEvent('100', 'refs/heads/main', [{ sha: 'old', distinct: true }]), pushEvent('200', 'refs/heads/dev', [{ sha: 'new', distinct: true }])];
    const r = extractNewCommits(ev, '100');
    expect(r.commits.map((c) => c.sha)).toEqual(['new']);
    expect(r.maxEventId).toBe('200');
  });

  it('모든 브랜치를 수집하고 branch를 기록한다', () => {
    const ev = [pushEvent('300', 'refs/heads/feature/x', [{ sha: 'c', distinct: true }])];
    const r = extractNewCommits(ev, null);
    expect(r.commits[0]!.branch).toBe('feature/x');
  });

  it('size>20이면 oversized 플래그', () => {
    const ev = [pushEvent('400', 'refs/heads/main', [{ sha: 'd', distinct: true }], 25)];
    expect(extractNewCommits(ev, null).commits[0]!.oversized).toBe(true);
  });

  it('PushEvent가 아니면 제외', () => {
    const ev: GhEvent[] = [{ ...pushEvent('500', 'refs/heads/main', [{ sha: 'e', distinct: true }]), type: 'WatchEvent' }];
    expect(extractNewCommits(ev, null).commits).toHaveLength(0);
  });
});
