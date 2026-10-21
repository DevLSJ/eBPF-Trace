import type { License, Role } from './types';

// 인증 화면 공용 값(W16) — 문구는 목업 shared/auth.js · 백엔드 internal/auth 와 같게

export const ROLE_KO: Record<Role, string> = { admin: '관리자', viewer: '조회자' };

export const AUTH_MSG = {
  lastAdmin: '마지막 관리자는 강등하거나 비활성화할 수 없습니다',
  mismatch: '새 비밀번호가 일치하지 않습니다',
};

// 백엔드 ValidatePassword 와 같은 규칙(사용자 결정 10/20: 5자) — 5자 이상 · 72바이트 이하 · 아이디와 다름(대소문자 무시)
export const PW_MIN = 5;
export function validatePassword(username: string, pw: string): string {
  if ([...pw].length < PW_MIN) return `비밀번호는 ${PW_MIN}자 이상이어야 합니다`;
  if (new TextEncoder().encode(pw).length > 72) return '비밀번호가 너무 깁니다(72바이트 이하)';
  if (pw.trim().toLowerCase() === username.trim().toLowerCase()) return '비밀번호는 아이디와 달라야 합니다';
  return '';
}

const DAY = 86_400_000;
export function daysLeft(l: License, now = Date.now()) {
  return Math.max(0, Math.ceil((Date.parse(l.expiresAt) - now) / DAY));
}

// 라이선스 칩(10/20 확정): 만료 빨강 · 30일 이하 노랑 · 그 외 「평가판 · N일 남음」
export type LicenseTone = 'ok' | 'warn' | 'danger' | 'none';
export function licenseTone(l: License | null, now = Date.now()): LicenseTone {
  if (!l) return 'none';
  const d = daysLeft(l, now);
  if (l.expired || d === 0) return 'danger';
  return d <= 30 ? 'warn' : 'ok';
}
export function licenseText(l: License | null, now = Date.now()) {
  if (!l) return '라이선스 없음';
  const d = daysLeft(l, now);
  if (l.expired || d === 0) return '라이선스 만료';
  return `${l.kind === 'trial' ? '평가판' : '라이선스'} · ${d}일 남음`;
}
