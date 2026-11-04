import { LEVEL_LABEL, levelOf, type Level, type Verdict } from '../lib/types';

const style: Record<Level, string> = {
  normal: 'bg-slate-100 text-slate-600',
  alert: 'bg-amber-100 text-amber-800',
  held: 'bg-red-50 text-red-700',
  killed: 'bg-red-600 text-white',
};

// 상태 배지 pill(R4 11/04 — 목업 11/04e .badge 11.5/700 + 글자색 1px 테두리)
// LevelBadge: 판정 단계만 알 때 (토폴로지 노드·체인처럼 Verdict 원본이 없는 곳)
export function LevelBadge({ level, title }: { level: Level; title?: string }) {
  return (
    <span title={title} className={`sg-pill ${style[level]}`}>
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
