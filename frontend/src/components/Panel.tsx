import { CircleSlash, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { errorText, isUnsupported } from '../lib/api';

export function Panel({
  title,
  actions,
  children,
  className = '',
  testId,
}: {
  title: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  testId?: string;
}) {
  return (
    <section className={`sg-card flex min-h-0 flex-col overflow-hidden ${className}`} data-testid={testId}>
      <header className="flex h-11 shrink-0 items-center justify-between gap-3 border-b border-border px-4">
        <h2 className="truncate text-sm font-semibold text-slate-800">{title}</h2>
        {actions}
      </header>
      <div className="min-h-0 flex-1">{children}</div>
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="flex h-full min-h-24 items-center justify-center p-6 text-center text-sm text-slate-400">{children}</div>;
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
            <b>백엔드 미지원</b> — {what} API가 아직 백엔드에 없습니다.
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
