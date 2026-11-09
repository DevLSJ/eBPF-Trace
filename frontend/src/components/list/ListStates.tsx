import { CircleSlash, RotateCw, TriangleAlert, X, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { errorText, isUnsupported } from '../../lib/api';
import { josa } from '../../lib/layout';
import { emptyText, STATE_COPY } from './state-copy';

// 목록 공통 상태(10/20 D, 목업 ui-kit.js skeleton · errorState · emptyState · filterChips · rowKeys) —
// 이벤트 · 감사 로그 · 설치 검사 · 공급망 검사 본문이 같이 쓴다. 기본 문구는 state-copy.ts 한 곳(11/09 SPEC-1109 §7)

// 첫 로드 스켈레톤 — 줄 길이를 조금씩 달리해 표처럼 보이게
export function Skeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="grid gap-2.5 p-4" data-part="skeleton" aria-busy="true" aria-label={STATE_COPY.loading}>
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
      <b className="text-slate-800">{unsupported ? '백엔드 미지원' : `${what}${josa(what, ['을', '를'])} ${STATE_COPY.loadFailed}`}</b>
      <span className="text-xs text-slate-500">{unsupported ? `${what} API가 아직 백엔드에 없습니다.` : errorText(error)}</span>
      {onRetry && !unsupported && (
        <>
          <button
            type="button"
            data-action="retry"
            disabled={retrying}
            onClick={onRetry}
            className="sg-btn sg-btn-sm sg-btn-secondary mt-1 flex items-center gap-1.5"
          >
            <RotateCw className={`size-3.5 ${retrying ? 'sg-spin' : ''}`} aria-hidden /> {STATE_COPY.retry}
          </button>
          <span className="text-xs text-slate-400">30초마다 한 번씩 저절로 다시 불러 봅니다</span>
        </>
      )}
    </div>
  );
}

// 빈 상태(11/05 참고 대시보드) — 가운데 · 보조색 14px · 높이 180 · 아이콘 없음(11/05 결정, 10/20 「아이콘 있는 빈 상태」 대체). icon 은 받기만 한다
// 11/09 §7: title 을 안 주면 what 으로 「[무엇]이 없습니다.」(조사 자동), 그것도 없으면 「데이터가 없습니다.」. hint = 다음 할 일 한 문장, actions = 1차 단추
export function EmptyState({ title, what, hint, actions, testId }: { icon?: LucideIcon; title?: ReactNode; what?: string; hint?: ReactNode; actions?: ReactNode; testId?: string }) {
  return (
    <div className="sg-empty flex h-full min-h-[180px] flex-col items-center justify-center gap-1 p-6 text-center text-[14px] text-text-3" data-part="empty" data-testid={testId}>
      <span>{title ?? emptyText(what)}</span>
      {hint && <span className="max-w-md text-[12.5px]">{hint}</span>}
      {actions && <div className="mt-1 flex flex-wrap items-center justify-center gap-2">{actions}</div>}
    </div>
  );
}

// 쪽 번호 바닥줄 자리(R4 11/04) — 표 패널이 화면 오른쪽 끝이면(시트 닫힘) 오른쪽 아래 도우미 단추(52px)가 쪽 단추를 가리지 않게
// 오른쪽을 88px 비운다(목업 styles.css 「.split > .panel:last-child .tk-foot」 padding-right: 88px). 768 미만은 기존 그대로
export function PagerSlot({ children, edge = true }: { children: ReactNode; edge?: boolean }) {
  return <div className={`shrink-0 ${edge ? 'md:[&>.tk-foot]:pr-[88px]!' : ''}`}>{children}</div>;
}

// 검색 · 필터 결과 없음(11/09 §7): 「조건에 맞는 데이터가 없습니다」 + 「검색 조건을 바꾸거나 해제해 보세요.」 + 「조건 지우기」(onClear 를 줄 때)
export function NoResults({ onClear, testId }: { onClear?: () => void; testId?: string }) {
  return (
    <div className="sg-empty flex h-full min-h-[180px] flex-col items-center justify-center gap-1 p-6 text-center text-[14px] text-text-3" data-part="no-results" data-testid={testId}>
      <span>{STATE_COPY.noResults}</span>
      <span className="max-w-md text-[12.5px]">{STATE_COPY.noResultsHint}</span>
      {onClear && (
        <div className="mt-1">
          <ClearFiltersButton onClick={onClear}>{STATE_COPY.clear}</ClearFiltersButton>
        </div>
      )}
    </div>
  );
}

// 권한 없음(11/09 §7) — 「이 화면을 볼 권한이 없습니다.」(아이콘 없음). 조회자 화면에서 쓰기 단추를 숨기는 기존 규칙과는 별개 — 화면 자체를 못 볼 때만
// 11/09 G04: hint = 왜 · 어떻게 하면 되는지 한 문장(보조 글 12.5 — 설정 이름 같은 내부 이름은 hint 의 title 툴팁에만), actions = 1차 단추
export function NoPermission({ text = STATE_COPY.denied, hint, actions, testId }: { text?: string; hint?: ReactNode; actions?: ReactNode; testId?: string }) {
  return (
    <div className="sg-empty flex h-full min-h-[180px] flex-col items-center justify-center gap-1 p-6 text-center text-[14px] text-text-3" data-part="denied" role="status" data-testid={testId}>
      <span>{text}</span>
      {hint && <span className="max-w-md text-[12.5px]">{hint}</span>}
      {actions && <div className="mt-1 flex flex-wrap items-center justify-center gap-2">{actions}</div>}
    </div>
  );
}

// 필터 해제 단추 이름은 어디서나 「조건 지우기」 하나(11/09 G40, STATE_COPY.clear). children 은 다른 일(예: 「전체 보기」)을 할 때만
export function ClearFiltersButton({ onClick, children = STATE_COPY.clear }: { onClick: () => void; children?: ReactNode }) {
  return (
    <button type="button" onClick={onClick} className="sg-btn sg-btn-sm sg-btn-secondary">
      {children}
    </button>
  );
}

// 적용된 필터 칩 — 칩마다 ✕, 끝에 「조건 지우기」(11/09 G40 — 예전 「모두 해제」). 필터가 없으면 그리지 않는다
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
        {STATE_COPY.clear}
      </button>
    </div>
  );
}
