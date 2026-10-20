import type { InstallSession, Manager } from './types';

// API 계약 「동작 규칙」: 로컬 디렉터리는 마지막 경로 이름, 버전 표기(== · 마지막 @ 뒤)는 뗀다. npm 스코프 @a/b 는 그대로.
export function packageName(raw: string): string {
  let s = raw.trim().replace(/\/+$/, '');
  if (s.startsWith('.') || s.startsWith('/') || s.startsWith('~')) s = s.split('/').pop() ?? s;
  s = s.split(/==|>=|<=|~=|!=/)[0];
  const at = s.lastIndexOf('@');
  if (at > 0) s = s.slice(0, at);
  return s;
}

export const ECOSYSTEM: Record<Manager, string> = { pip: 'PyPI', npm: 'npm', cargo: 'crates.io' };

export const sessionLabel = (s: { packages: string[] }) => s.packages.join(' ');
export const installCommand = (s: { manager: string; packages: string[] }) => `sg-install ${s.manager} ${s.packages.join(' ')}`;

// 걸린 시간: 시작 → 끝(끝 보고 또는 컨테이너 종료)
export function duration(startIso: string, endIso?: string | null): string {
  if (!endIso) return '—';
  const sec = Math.max(0, Math.round((new Date(endIso).getTime() - new Date(startIso).getTime()) / 1000));
  return sec < 60 ? `${sec}초` : `${Math.floor(sec / 60)}분 ${sec % 60}초`;
}

export const EXAMPLE_COMMAND = 'tools/sg-install pip requests';

// 위반 수: 목록 응답에 violationCount 가 있으면 그것, 없으면 상세의 violations[].count 합
export const violationTotal = (s: InstallSession) => s.violationCount ?? s.violations?.reduce((n, v) => n + (v.count || 1), 0);
