import { describe, expect, it } from 'vitest';
import { parseRelayEvent } from '../src/analysis/relay.js';

const env = (type: string, payload: unknown = {}) => JSON.stringify({ type, ts: '2026-10-12T00:00:00Z', payload });

describe('parseRelayEvent (analyzer → /ws 중계)', () => {
  it('분석 이벤트 4종은 통과', () => {
    for (const t of ['analysis.started', 'analysis.completed', 'analysis.failed', 'agent.tick']) {
      expect(parseRelayEvent(env(t, { commitId: 1 }))?.type).toBe(t);
    }
  });
  it('analyzer가 보낼 일 없는 종류는 버림', () => {
    expect(parseRelayEvent(env('runtime.incident'))).toBeNull();
    expect(parseRelayEvent(env('commit.received'))).toBeNull();
  });
  it('형식이 깨진 메시지는 버림', () => {
    expect(parseRelayEvent('not json')).toBeNull();
    expect(parseRelayEvent(JSON.stringify({ payload: {} }))).toBeNull();
  });
  it('payload를 그대로 보존', () => {
    expect(parseRelayEvent(env('analysis.completed', { commitId: 7, riskScore: 0 }))?.payload).toEqual({ commitId: 7, riskScore: 0 });
  });
});
