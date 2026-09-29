import { Pause, Play } from 'lucide-react';
import { useLayoutEffect, useRef, useState } from 'react';
import type { StreamVerdict } from '../hooks/useEventStream';
import { fmtTime } from '../lib/format';
import { detailOf, levelOf } from '../lib/types';
import { KindBadge } from './KindBadge';
import { Empty } from './Panel';
import { VerdictBadge } from './VerdictBadge';

const ROW = 40; // 고정 행 높이 — 보이는 행만 그린다(가상 스크롤)
const OVERSCAN = 8;

interface Props {
  verdicts: StreamVerdict[];
  selectedKey?: number;
  onSelect?: (v: StreamVerdict) => void;
  empty?: string;
  // full: 이벤트 화면용 표 — 헤더 + 이미지·규칙 열
  full?: boolean;
  // 표 폭이 좁을 때(상세 패널 열림) 이미지 열 숨김
  showImage?: boolean;
}

export function EventFeed({ verdicts, selectedKey, onSelect, empty = '이벤트 수신 대기 중', full = false, showImage = true }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(400);
  const hasRows = verdicts.length > 0;

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
    <div className="flex h-full flex-col">
      {full && (
        <div className="flex h-9 shrink-0 items-center gap-3 border-b border-slate-200 bg-slate-50 px-4 text-xs font-medium text-slate-500">
          <span className="w-16 shrink-0">시각</span>
          <span className="w-32 shrink-0">컨테이너</span>
          {showImage && <span className="w-40 shrink-0">이미지</span>}
          <span className="w-16 shrink-0 text-center">Kind</span>
          <span className="min-w-40 flex-1">상세 (args · path · dst)</span>
          <span className="w-36 shrink-0">규칙</span>
          <span className="w-20 shrink-0">판정</span>
        </div>
      )}
    <div ref={ref} className="min-h-0 flex-1 overflow-y-auto" onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}>
      <ul className="relative" style={{ height: verdicts.length * ROW }}>
        {verdicts.slice(start, end).map((v, i) => {
          const level = levelOf(v);
          const selected = v.key === selectedKey;
          return (
            <li
              key={v.key}
              style={{ top: (start + i) * ROW, height: ROW }}
              onClick={onSelect && (() => onSelect(v))}
              className={`absolute inset-x-0 flex items-center gap-3 border-b border-slate-100 px-4 text-sm ${
                onSelect ? 'cursor-pointer hover:bg-slate-50' : ''
              } ${selected ? 'bg-indigo-50' : level === 'killed' || level === 'held' ? 'bg-red-50/60' : ''}`}
            >
              <span className="num w-16 shrink-0 font-mono text-xs text-slate-500">{fmtTime(v.event.timestamp)}</span>
              <span className="w-32 shrink-0 truncate font-medium text-slate-800" title={v.event.containerName}>
                {v.event.containerName}
              </span>
              {full && showImage && (
                <span className="w-40 shrink-0 truncate text-xs text-slate-500" title={v.event.imageName}>
                  {v.event.imageName}
                </span>
              )}
              <KindBadge kind={v.event.kind} />
              <span className={`${full ? 'min-w-40' : 'min-w-0'} flex-1 truncate font-mono text-xs text-slate-600`} title={detailOf(v.event)}>
                {detailOf(v.event)}
              </span>
              {full ? (
                <span className="w-36 shrink-0 truncate text-xs text-slate-500" title={v.reason}>
                  {v.ruleId ?? '—'}
                </span>
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

export function PauseToggle({ paused, onPause, onResume }: { paused: boolean; onPause: () => void; onResume: () => void }) {
  return (
    <button
      type="button"
      onClick={paused ? onResume : onPause}
      className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium ${
        paused ? 'bg-amber-100 text-amber-800 hover:bg-amber-200' : 'text-slate-600 hover:bg-slate-100'
      }`}
    >
      {paused ? <Play className="size-3.5" aria-hidden /> : <Pause className="size-3.5" aria-hidden />}
      {paused ? '재개' : '일시정지'}
    </button>
  );
}
