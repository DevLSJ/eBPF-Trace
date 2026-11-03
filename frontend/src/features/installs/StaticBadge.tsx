import { ScanVerdictBadge } from '../../components/Badges';
import type { InstallSession } from '../../lib/types';
import { skipText } from './staticScan';

// 설치 목록 「정적 검사」 열 · 상세 정적 칸의 배지(11/04) — 공급망 검사 화면의 판정 배지 그대로. 건너뜀 · 옛 세션은 회색 「—」(건너뜀은 title 에 이유)
export function StaticBadge({ s }: { s: InstallSession }) {
  const sc = s.scan;
  if (!sc)
    return (
      <span className="text-xs text-slate-300" data-static="none">
        —
      </span>
    );
  if (sc.status === 'skipped')
    return (
      <span className="text-xs text-slate-400" data-static="skipped" title={skipText(s)}>
        —
      </span>
    );
  return <ScanVerdictBadge status={sc.status} verdict={sc.verdict} error={sc.error} data-static={sc.status === 'done' ? (sc.verdict ?? 'clean') : sc.status} />;
}
