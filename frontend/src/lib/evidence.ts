import { dest } from './nav';
import type { Event } from './types';

// 「증거 보기」(10/20 I) — 감사 로그를 그 컨테이너로 거르고, 격리된 첫 행의 상세를 「증거」 탭으로 연다
// 컨테이너는 필터라 state 로(10/21), tab 만 주소에
export const evidenceDest = (container: string) => dest('/audit?tab=evidence', { container });

// 도메인 조회 줄(10/20 I, 목업 screens.js dnsRow)
export type DnsKind = 'traced' | 'direct' | 'private' | 'off' | 'unknown';
export function dnsKindOf(e: Event): DnsKind {
  if (e.dstHost) return 'traced';
  if (e.dnsTraced === true) return isPublicIp(e.dstIp ?? '') ? 'direct' : 'private';
  if (e.dnsTraced === false) return 'off';
  return 'unknown';
}

// 백엔드 rules.IsPublicAddr 와 같은 기준 — 루프백 · 링크로컬(유니캐스트 · 멀티캐스트) · 사설 · 미지정은 공인 아님
export function isPublicIp(ip: string): boolean {
  const v4 = ip.replace(/^::ffff:/i, '').match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const n = v4.slice(1).map(Number);
    if (n.some((x) => x > 255)) return false;
    const [a, b, c] = n;
    const unspecified = n.every((x) => x === 0);
    return !(unspecified || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 224 && b === 0 && c === 0));
  }
  const x = ip.toLowerCase();
  if (!x.includes(':') || x === '::' || x === '::1') return false;
  return !(/^f[cd]/.test(x) || /^fe[89ab]/.test(x) || /^ff02:/.test(x));
}
