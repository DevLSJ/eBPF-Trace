import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

// webhook.ts의 validSignature와 동일 로직을 테스트 (순수 HMAC 검증)
function makeSig(secret: string, raw: string): string {
  return 'sha256=' + createHmac('sha256', secret).update(raw).digest('hex');
}
function valid(secret: string, raw: string, sig: string | undefined): boolean {
  if (!secret || !sig) return false;
  const expected = makeSig(secret, raw);
  return sig.length === expected.length && sig === expected;
}

describe('webhook signature', () => {
  const secret = 'test-secret';
  const body = JSON.stringify({ ref: 'refs/heads/main', commits: [] });

  it('정상 서명 통과', () => {
    expect(valid(secret, body, makeSig(secret, body))).toBe(true);
  });
  it('변조된 본문 거부', () => {
    expect(valid(secret, body + 'x', makeSig(secret, body))).toBe(false);
  });
  it('틀린 시크릿 거부', () => {
    expect(valid(secret, body, makeSig('wrong', body))).toBe(false);
  });
  it('서명 없음 거부', () => {
    expect(valid(secret, body, undefined)).toBe(false);
  });
});
