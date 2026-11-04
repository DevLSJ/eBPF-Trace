import { CircleSlash, RotateCw, TriangleAlert, X, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { errorText, isUnsupported } from '../../lib/api';

// 목록 공통 상태(10/20 D, 목업 ui-kit.js skeleton · errorState · emptyState · filterChips · rowKeys) —
// 이벤트 · 감사 로그 · 설치 검사 · 공급망 검사 본문이 같이 쓴다

// 첫 로드 스켈레톤 — 줄 길이를 조금씩 달리해 표처럼 보이게
export function Skeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="grid gap-2.5 p-4" data-part="skeleton" aria-busy="true" aria-label="불러오는 중">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-3">
          <i className="sg-skeleton h-3" style={{ width: `${18 + (i % 3) * 6}%` }} />
          <i className="sg-skeleton h-3" style={{ width: `${30 + ((i * 7) % 4) * 8}%` }} />
          <i className="sg-skeleton h-3 w-[12%]" />
        </div>
      ))}
    </div>
  );
}

// 오류 + 「다시 시도」. 라우트가 없으면(백엔드 미지원) 다시 불러도 같으니 버튼 없이 안내만
export function ListError({ error, what, onRetry, retrying }: { error: unknown; what: string; onRetry?: () => void; retrying?: boolean }) {
  const unsupported = isUnsupported(error);
  return (
    <div className="flex h-full min-h-40 flex-col items-center justify-center gap-2 p-6 text-center text-sm" data-part="error" role="alert" data-unsupported={unsupported ? 'true' : undefined}>
      {unsupported ? <CircleSlash className="size-6 text-slate-400" aria-hidden /> : <TriangleAlert className="size-6 text-red-500" aria-hidden />}
      <b className="text-slate-800">{unsupported ? '백엔드 미지원' : `${what}을(를) 불러오지 못했습니다`}</b>
      <span className="text-xs text-slate-500">{unsupported ? `${what} API가 아직 백엔드에 없습니다.` : errorText(error)}</span>
      {onRetry && !unsupported && (
        <>
          <button
            type="button"
            data-action="retry"
            disabled={retrying}
            onClick={onRetry}
            className="mt-1 flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            <RotateCw className={`size-3.5 ${retrying ? 'sg-spin' : ''}`} aria-hidden /> 다시 시도
          </button>
          <span className="text-[11px] text-slate-400">30초마다 한 번씩 저절로 다시 불러 봅니다</span>
        </>
      )}
    </div>
  );
}

// 아이콘 있는 빈 상태
export function EmptyState({ icon: Icon, title, hint, actions, testId }: { icon: LucideIcon; title: ReactNode; hint?: ReactNode; actions?: ReactNode; testId?: string }) {
  return (
    <div className="flex h-full min-h-40 flex-col items-center justify-center gap-2 p-6 text-center text-sm" data-part="empty" data-testid={testId}>
      <Icon className="size-7 text-slate-300" aria-hidden />
      <b className="text-slate-700">{title}</b>
      {hint && <span className="max-w-md text-xs text-slate-500">{hint}</span>}
      {actions && <div className="mt-1 flex flex-wrap items-center justify-center gap-2">{actions}</div>}
    </div>
  );
}

export function ClearFiltersButton({ onClick, children = '필터 모두 해제' }: { onClick: () => void; children?: ReactNode }) {
  return (
    <button type="button" onClick={onClick} className="rounded-md border border-slate-300 px-2.5 py-1 text-xs text-slate-700 hover:bg-slate-50">
      {children}
    </button>
  );
}

// 적용된 필터 칩 — 칩마다 ✕, 끝에 「모두 해제」. 필터가 없으면 그리지 않는다(필터는 주소에 있다)
export interface AppliedFilter {
  key: string;
  label: string;
  clear: () => void;
}
export function AppliedFilters({ items, onClearAll }: { items: (AppliedFilter | null | false | undefined)[]; onClearAll: () => void }) {
  const list = items.filter(Boolean) as AppliedFilter[];
  if (!list.length) return null;
  return (
    <div className="flex shrink-0 flex-wrap items-center gap-1.5 border-b border-slate-100 px-4 py-1.5 text-xs" data-part="filter-chips">
      <span className="text-slate-500">적용된 필터</span>
      {list.map((x) => (
        <span key={x.key} data-chip={x.key} className="flex items-center gap-1 rounded-full bg-indigo-50 py-0.5 pr-1 pl-2.5 text-indigo-800">
          {x.label}
          {/* 이름은 숨은 글자로 — aria-label 로 두면 같은 이름의 입력 칸(getByLabel)과 겹친다 */}
          <button type="button" onClick={x.clear} className="rounded-full p-0.5 hover:bg-indigo-100">
            <X className="size-3" aria-hidden />
            <span className="sr-only">{x.label} 필터 해제</span>
          </button>
        </span>
      ))}
      <button type="button" data-action="clear-filters" onClick={onClearAll} className="rounded-md px-2 py-0.5 text-slate-600 hover:bg-slate-100">
        모두 해제
      </button>
    </div>
  );
}
