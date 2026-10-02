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
  return level ?? status;
}
