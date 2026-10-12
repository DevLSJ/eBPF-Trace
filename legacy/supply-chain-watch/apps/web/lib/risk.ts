export function levelClass(level: string | null): string {
  switch (level) {
    case 'HIGH': return 'bg-crit-soft text-[var(--crit-ink)] border-[color-mix(in_srgb,var(--crit)_35%,transparent)]';
    case 'MEDIUM': return 'bg-warn-soft text-[var(--warn-ink)] border-[color-mix(in_srgb,var(--warn)_40%,transparent)]';
    case 'LOW': return 'bg-good-soft text-[var(--good-ink)] border-[color-mix(in_srgb,var(--good)_35%,transparent)]';
    default: return 'bg-info-soft text-info border-transparent';
  }
}
export function levelIcon(level: string | null): string {
  return level === 'HIGH' ? '▲' : level === 'MEDIUM' ? '◆' : level === 'LOW' ? '●' : '○';
}
export function statusLabel(status: string, level: string | null): string {
  if (status === 'QUEUED') return '대기';
  if (status === 'ANALYZING') return '분석중';
  if (status === 'FAILED') return '실패';
  return (level && LEVEL_LABEL[level]) ?? level ?? status;
}

// 화면 용어 (docs/06 §0.9): 등급은 위험/주의/안전, 분류는 쉬운 3개만. 영문 원어는 화면에 노출하지 않는다.
export const LEVEL_LABEL: Record<string, string> = { HIGH: '위험', MEDIUM: '주의', LOW: '안전' };

const TAG_GROUP: Record<string, string> = {
  ENV_EXFILTRATION: '정보 유출', CREDENTIAL_ACCESS: '정보 유출', CI_SECRET_LEAK: '정보 유출',
  INSTALL_HOOK: '숨은 실행', OBFUSCATION: '숨은 실행', EVASION: '숨은 실행', DOWNLOAD_EXECUTE: '숨은 실행',
  BACKDOOR: '숨은 실행', PERSISTENCE: '숨은 실행', CI_PRIVILEGE_ESCALATION: '숨은 실행',
  C2_CONNECTION: '외부 연결', SUPPLY_CHAIN: '외부 연결', CI_UNTRUSTED_ACTION: '외부 연결',
};

export function tagGroups(tags: string[] | null | undefined): string[] {
  return [...new Set((tags ?? []).map((t) => TAG_GROUP[t]).filter(Boolean))];
}
