import { levelOf, type Level, type Verdict } from '../lib/types';

const style: Record<Level, string> = {
  normal: 'bg-slate-100 text-slate-600',
  alert: 'bg-amber-100 text-amber-800',
  held: 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-200',
  killed: 'bg-red-600 text-white',
};

const levelLabel: Record<Level, string> = {
  normal: '정상',
  alert: '경고',
  held: '격리 대상',
  killed: '격리됨',
};

export function VerdictBadge({ v }: { v: Verdict }) {
  const level = levelOf(v);
  const title =
    level === 'held' ? (v.enforceError ? `격리 실패: ${v.enforceError}` : 'dry-run — 알림만 보냄') : undefined;
  return (
    <span title={title} className={`inline-block rounded px-2 py-0.5 text-xs font-medium whitespace-nowrap ${style[level]}`}>
      {levelLabel[level]}
    </span>
  );
}
