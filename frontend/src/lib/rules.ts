import type { Rule } from './types';

// 정책 적용 범위: 전체 · 설치 검사 전용 · 일부 컨테이너
export function scopeOf(r: Rule): { key: 'all' | 'sandbox' | 'some'; label: string } {
  const cs = r.containers ?? [];
  if (cs.length === 0) return { key: 'all', label: '전체' };
  if (cs.every((c) => c.startsWith('sg-install-'))) return { key: 'sandbox', label: '설치 검사 전용' };
  return { key: 'some', label: '일부 컨테이너' };
}

