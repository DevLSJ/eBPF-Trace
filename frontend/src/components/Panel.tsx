import { CircleSlash, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { Dest } from '../lib/nav';
import { errorText, isUnsupported } from '../lib/api';

// 패널(참고 대시보드 섹션 카드, 11/05) — 반경 8 · 1px 선 · hover 파란 선 · 머리 56 = 제목 17.9/700 + 부제(sub) + 오른쪽 actions · 「더 보기 ›」(more) · 바닥줄(foot, 채움 칸 밖)
export function Panel({
  title,
  sub,
  more,
  actions,
  foot,
  children,
  className = '',
  testId,
}: {
  title: ReactNode;
  sub?: ReactNode;
  more?: Dest & { label?: string };
  actions?: ReactNode;
  foot?: ReactNode;
  children: ReactNode;
  className?: string;
  testId?: string;
}) {
  return (
    <section className={`sg-card sg-panel flex min-h-0 flex-col overflow-hidden ${className}`} data-testid={testId}>
      <header className="sg-panel-head flex shrink-0 items-center gap-2.5">
        <h2 className="sg-panel-title min-w-0 truncate">{title}</h2>
        {sub && <span className="sg-panel-sub min-w-0 flex-1 truncate text-[12.5px] text-text-3">{sub}</span>}
        {(actions || more) && (
          <div className="ml-auto flex shrink-0 items-center gap-2">
            {actions}
            {more && (
              <Link to={more.to} state={more.state} className="text-[12.5px] font-medium whitespace-nowrap text-accent hover:underline" data-more="">
                {more.label ?? '더 보기'} ›
              </Link>
            )}
          </div>
        )}
      </header>
      <div className="min-h-0 flex-1">{children}</div>
      {foot}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="sg-empty flex h-full min-h-[180px] items-center justify-center p-6 text-center text-[14px] text-text-3">{children}</div>;
}

// 불러오기 실패 안내. 라우트가 없으면(404) 「백엔드 미지원」 — 그 영역만 비고 앱은 계속 동작한다.
export function LoadError({ error, what, compact }: { error: unknown; what: string; compact?: boolean }) {
  if (!error) return null;
  const unsupported = isUnsupported(error);
  return (
    <div
      role="note"
      data-unsupported={unsupported ? 'true' : undefined}
      className={`flex items-start gap-2 rounded-md border text-sm ${compact ? 'm-0 px-3 py-2' : 'm-4 px-4 py-3'} ${
        unsupported ? 'border-slate-200 bg-slate-50 text-slate-600' : 'border-red-200 bg-red-50 text-red-700'
      }`}
    >
      {unsupported ? <CircleSlash className="mt-0.5 size-4 shrink-0" aria-hidden /> : <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />}
      <span>
        {unsupported ? (
          <>
            <b>백엔드 미지원</b>, {what} API가 아직 백엔드에 없습니다.
          </>
        ) : (
          <>
            {what} 불러오기 실패: {errorText(error)}
          </>
        )}
      </span>
    </div>
  );
}
