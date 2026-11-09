import { Pause, Play } from 'lucide-react';
import { useLayoutEffect, useRef, useState } from 'react';
import type { StreamVerdict } from '../hooks/useEventStream';
import { FIELD } from '../lib/fieldNames';
import { fmtTime } from '../lib/format';
import { detailOf, levelOf } from '../lib/types';
import { KindBadge } from './KindBadge';
import { Empty } from './Panel';
import { VerdictBadge } from './VerdictBadge';

const ROW = 40; // 고정 행 높이 — 보이는 행만 그린다(가상 스크롤)
const OVERSCAN = 8;
// 이미지 · 규칙 열은 표 폭 52rem 이상에서만(768px 화면의 가로 넘침 방지, W20)
const WIDE_ONLY = 'hidden @min-[52rem]:block';
// 시각 · 종류 · 상세는 표 폭 30rem 이상에서만 — 더 좁으면(768px 에서 상세 시트를 연 때) 컨테이너 · 탐지 결과만, 나머지는 시트에
const MID_ONLY = 'hidden @min-[30rem]:block';
const CTR_COL = 'min-w-0 flex-1 @min-[30rem]:w-32 @min-[30rem]:flex-none';

interface Props {
  verdicts: StreamVerdict[];
  selectedKey?: number;
  onSelect?: (v: StreamVerdict) => void;
  empty?: string;
  // full: 이벤트 화면용 표 — 헤더 + 이미지·규칙 열
  full?: boolean;
  // 표 폭이 좁을 때(상세 시트 열림) 이미지 · 규칙 열 숨김 — 둘 다 시트에 보인다.
  // 시트가 없어도 표가 52rem 보다 좁으면(768px 화면 등) 같은 두 열을 숨긴다(W20, 컨테이너 쿼리)
  showImage?: boolean;
}

export function EventFeed({ verdicts, selectedKey, onSelect, empty = '이벤트 수신 대기 중', full = false, showImage = true }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(400);
  const hasRows = verdicts.length > 0;
  // 10/30 모션: 처음 그릴 때 있던 행(key ≤ base)은 그대로, 그 뒤 들어온 위반 행은 danger-soft → 투명 1.2s
  const [base] = useState(() => verdicts.reduce((m, v) => Math.max(m, v.key), 0));

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, [hasRows]); // 빈 상태에서 시작하면 목록이 생길 때 다시 관찰

  if (!hasRows) return <Empty>{empty}</Empty>;

  const start = Math.max(0, Math.floor(scrollTop / ROW) - OVERSCAN);
  const end = Math.min(verdicts.length, Math.ceil((scrollTop + height) / ROW) + OVERSCAN);

  return (
    <div className="@container flex h-full flex-col">
      {full && (
        <div data-part="feed-head" className="flex h-9 shrink-0 items-center gap-3 border-b border-slate-200 bg-slate-50 px-4 text-xs font-bold text-slate-500">
          <span className={`w-16 shrink-0 ${MID_ONLY}`}>시각</span>
          <span className={CTR_COL}>컨테이너</span>
          {showImage && <span className={`w-40 shrink-0 ${WIDE_ONLY}`}>이미지</span>}
          <span className={`w-16 shrink-0 text-center ${MID_ONLY}`}>종류</span>
          <span className={`min-w-0 flex-1 ${MID_ONLY}`}>상세 (인자 · 경로 · 목적지)</span>
          {showImage && <span className={`w-36 shrink-0 ${WIDE_ONLY}`}>{FIELD.policy}</span>}
          <span className="w-20 shrink-0">탐지 결과</span>
        </div>
      )}
    <div ref={ref} data-fill="" className="min-h-0 flex-1 overflow-y-auto" onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}>
      <ul className="relative" aria-label="이벤트" style={{ height: verdicts.length * ROW }}>
        {verdicts.slice(start, end).map((v, i) => {
          const level = levelOf(v);
          const selected = v.key === selectedKey;
          const fresh = v.matched && v.key > base;
          return (
            <li
              key={v.key}
              style={{ top: (start + i) * ROW, height: ROW }}
              data-key={v.key}
              data-level={level}
              data-fresh={fresh ? 'true' : undefined}
              tabIndex={onSelect ? 0 : undefined}
              aria-selected={onSelect ? selected : undefined}
              onClick={onSelect && (() => onSelect(v))}
              onKeyDown={
                onSelect &&
                ((e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelect(v);
                  }
                })
              }
              className={`absolute inset-x-0 flex items-center gap-3 border-b border-slate-100 px-4 text-sm ${fresh ? 'sg-flash' : ''} ${
                onSelect ? 'cursor-pointer hover:bg-[var(--row-hover)] focus:outline-2 focus:-outline-offset-2 focus:outline-indigo-500' : ''
              } ${selected ? 'bg-indigo-50' : level === 'killed' || level === 'held' ? 'bg-red-50/60' : ''}`}
            >
              <span className={`num w-16 shrink-0 font-mono text-xs text-slate-500 ${full ? MID_ONLY : ''}`}>{fmtTime(v.event.timestamp)}</span>
              <span className={`truncate font-medium text-slate-800 ${full ? CTR_COL : 'w-32 shrink-0'}`} title={v.event.containerName}>
                {v.event.containerName}
              </span>
              {full && showImage && (
                <span className={`w-40 shrink-0 truncate text-xs text-slate-500 ${WIDE_ONLY}`} title={v.event.imageName}>
                  {v.event.imageName}
                </span>
              )}
              <span className={full ? `shrink-0 ${MID_ONLY}` : 'contents'}>
                <KindBadge kind={v.event.kind} />
              </span>
              <span className={`min-w-0 flex-1 truncate font-mono text-xs text-slate-600 ${full ? MID_ONLY : ''}`} title={detailOf(v.event)}>
                {detailOf(v.event)}
              </span>
              {full ? (
                showImage && (
                  <span className={`w-36 shrink-0 truncate text-xs text-slate-500 ${WIDE_ONLY}`} title={v.reason}>
                    {v.ruleId ?? ''}
                  </span>
                )
              ) : (
                v.matched && (
                  <span className="hidden max-w-48 truncate text-xs text-slate-500 xl:inline" title={v.reason}>
                    {v.ruleId}
                  </span>
                )
              )}
              <span className={full ? 'w-20 shrink-0' : ''}>
                <VerdictBadge v={v} />
              </span>
            </li>
          );
        })}
      </ul>
    </div>
    </div>
  );
}

export function PauseToggle({ paused, onPause, onResume, className = '' }: { paused: boolean; onPause: () => void; onResume: () => void; className?: string }) {
  return (
    <button
      type="button"
      onClick={paused ? onResume : onPause}
      className={`flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium whitespace-nowrap ${
        paused ? 'bg-amber-100 text-amber-800 hover:bg-amber-200' : 'text-slate-600 hover:bg-slate-100'
      } ${className}`}
    >
      {paused ? <Play className="size-3.5" aria-hidden /> : <Pause className="size-3.5" aria-hidden />}
      {paused ? '재개' : '일시정지'}
    </button>
  );
}
