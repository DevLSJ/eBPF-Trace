import { LEVEL_LABEL, levelOf, type Level, type Verdict } from '../lib/types';

const style: Record<Level, string> = {
  normal: 'bg-slate-100 text-slate-600',
  alert: 'bg-amber-100 text-amber-800',
  held: 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-200',
  killed: 'bg-red-600 text-white',
};

// LevelBadge: 판정 단계만 알 때 (토폴로지 노드·체인처럼 Verdict 원본이 없는 곳)
export function LevelBadge({ level, title }: { level: Level; title?: string }) {
  return (
    <span title={title} className={`inline-block rounded px-2 py-0.5 text-xs font-medium whitespace-nowrap ${style[level]}`}>
      {LEVEL_LABEL[level]}
    </span>
  );
}

export function VerdictBadge({ v }: { v: Verdict }) {
  const level = levelOf(v);
  const title =
    level === 'held' ? (v.enforceError ? `격리 실패: ${v.enforceError}` : 'dry-run — 알림만 보냄') : undefined;
  return <LevelBadge level={level} title={title} />;
}
