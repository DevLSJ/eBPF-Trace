import { useEffect, useRef, type CSSProperties } from 'react';
import { useLocation } from 'react-router-dom';
import { useStream } from '../../hooks/stream-context';
import { useToast } from '../../hooks/toast-context';
import { errorText } from '../../lib/api';
import { fmtNum } from '../../lib/format';

// D. 실시간 연결(10/20 확정) — 목업 shared/app.js 셸 connBanner · backfill.
// 끊기면 상단 붉은 배너, 다시 붙어 /api/events/recent 로 끊긴 구간을 채우면 「끊긴 동안 N건을 채웠습니다」 토스트.
// 최초 recent · stats 로드 실패는 삼키지 않고 붉은 배너 + 「다시 시도」(백엔드가 꺼져 있는데 「위반 없음」으로 보이지 않게)
export function StreamBanners() {
  const { down, backfill, loadError, retryLoad, recentError, verdicts } = useStream();
  // W20: 이벤트 화면에서 목록이 비어 recent 오류를 목록 칸이 보일 때는 배너를 겹쳐 띄우지 않는다(오류 표시 1곳)
  const shownInList = useLocation().pathname === '/events' && recentError != null && verdicts.length === 0;
  const toast = useToast();
  const shown = useRef(backfill);

  useEffect(() => {
    if (!backfill || backfill === shown.current) return;
    shown.current = backfill;
    toast(`실시간 연결이 다시 붙었습니다 — 끊긴 동안 ${fmtNum(backfill.n)}건을 채웠습니다`, { key: 'backfill', tone: 'ok' });
  }, [backfill, toast]);

  // 배너(10/30 계약 §7): soft 배경 + 왼쪽 4px 색 띠
  const danger = { '--banner-color': 'var(--danger)' } as CSSProperties;
  return (
    <>
      {loadError != null && !shownInList && (
        <div data-banner="load" role="alert" style={danger} className="sg-banner flex shrink-0 items-center gap-2 border-b border-red-200 bg-red-50 px-4 py-2 text-[13px] text-red-900 md:px-6">
          <span className="min-w-0 flex-1">
            <b>이벤트를 불러오지 못했습니다</b> — {errorText(loadError)}. 지금 보이는 목록 · 숫자는 실제와 다를 수 있습니다.
          </span>
          <button type="button" onClick={retryLoad} className="shrink-0 rounded-md border border-red-300 bg-white px-2.5 py-1 text-xs font-medium text-red-800 hover:bg-red-100">
            다시 시도
          </button>
        </div>
      )}
      {down && loadError == null && (
        <div data-banner="conn" role="alert" style={danger} className="sg-banner shrink-0 border-b border-red-200 bg-red-50 px-4 py-2 text-[13px] text-red-900 md:px-6">
          <b>실시간 연결이 끊겼습니다</b> — 다시 연결하는 중입니다(1초 → 10초 간격). 그동안의 이벤트는 다시 붙으면 채웁니다.
        </div>
      )}
    </>
  );
}
