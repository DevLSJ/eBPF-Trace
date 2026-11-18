import { fmtMs, fmtSec, isolationMs, pauseMs, segmentsOf, type SegKey } from '../lib/timeline';
import type { Timeline } from '../lib/types';

// 격리 타임라인 가로 막대(10/30 계약 §3) — 설치 시트 결과 칸 · 토폴로지 판정 카드 · 보고서 · 시연 패널 ⑤ 가 같은 부품을 쓴다.
// 구간 4개: 탐지→판정(info) · 증거(warn) · 격리(danger) · 알림(accent), 각 ms 라벨, 합계 「격리까지 0.42초」. 없는 구간은 빈 칸.
// 11/16: 정지 시각(pausedAt)이 있으면 판정 다음에 「정지」 구간 + 합계 앞에 작은 「정지까지 0.02초」(보조 값). 없으면 예전 모양 그대로

const BAR: Record<SegKey, string> = { detect: 'bg-sky-500', pause: 'bg-violet-500', evidence: 'bg-amber-500', kill: 'bg-red-600', notify: 'bg-indigo-500' };
const DOT: Record<SegKey, string> = { detect: 'bg-sky-500', pause: 'bg-violet-500', evidence: 'bg-amber-500', kill: 'bg-red-600', notify: 'bg-indigo-500' };

export function TimelineBar({ timeline, compact }: { timeline: Timeline | null | undefined; compact?: boolean }) {
  const segs = segmentsOf(timeline);
  const total = isolationMs(timeline);
  const paused = pauseMs(timeline);
  const known = segs.filter((s) => s.ms !== null);
  const span = Math.max(1, known.reduce((n, s) => n + (s.ms ?? 0), 0));
  return (
    <div data-testid="timeline-bar" className={`grid gap-1.5 ${compact ? 'text-[11px]' : 'text-xs'}`}>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-slate-100" role="img" aria-label={total === null ? '격리 타임라인 없음' : `격리까지 ${fmtSec(total)}`}>
        {known.map((s) => (
          <i key={s.key} data-seg-bar={s.key} className={`block h-full ${BAR[s.key]}`} style={{ width: `${Math.max(4, ((s.ms ?? 0) / span) * 100)}%` }} title={`${s.label} ${fmtMs(s.ms)}`} />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-slate-600">
        {segs.map((s) => (
          <span key={s.key} data-seg={s.key} className="flex items-center gap-1 whitespace-nowrap">
            <i className={`size-2 rounded-sm ${s.ms === null ? 'bg-slate-300' : DOT[s.key]}`} aria-hidden />
            {s.label} <b className={`num ${s.ms === null ? 'font-normal text-slate-400' : 'text-slate-800'}`}>{fmtMs(s.ms)}</b>
          </span>
        ))}
        {paused === null ? null : (
          <span className="num ml-auto whitespace-nowrap text-slate-500" data-part="timeline-pause-total">
            정지까지 {fmtSec(paused)}
          </span>
        )}
        {/* 격리 시각이 없으면(이미 끝난 컨테이너 · 기록 없음, 11/16) 값 없는 「격리까지」 글자를 남기지 않는다 */}
        {total === null ? null : (
          <b className={`num whitespace-nowrap text-slate-900 ${paused === null ? 'ml-auto' : ''}`} data-part="timeline-total">
            격리까지 {fmtSec(total)}
          </b>
        )}
      </div>
    </div>
  );
}
