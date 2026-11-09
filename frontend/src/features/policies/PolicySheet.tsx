import { Lock } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { StatusPill } from '../../components/DataTable';
import { KindBadge } from '../../components/KindBadge';
import { EmptyState } from '../../components/list/ListStates';
import { PolicyEditor } from '../../components/PolicyEditor';
import { Sheet, type SheetTab } from '../../components/Sheet';
import type { SheetNav } from '../../components/sheet-nav';
import { KIND_SHORT, type ListField } from '../../lib/policyEasy';
import { SYSTEM_RULES, type PolicyView, type Rule } from '../../lib/types';
import { ContainersCard } from './ContainersCard';
import { PolicyChanges } from './PolicyChanges';
import { PolicyHits } from './PolicyHits';
import { ActionPill } from './PolicyBadges';
import { statusOf, STATUS } from './policyRow';

// 정책 상세 시트(11/09 — 사용자 원문 「정책 클릭시 상세 탭 나오고 편집 / 차단 이력 / 변경 이력」): 머리 = 정책 ID · 판정 · 종류(+ 상태),
// 탭 [편집 | 차단 이력 | 변경 이력] — 주소 ?id=<정책>&tab=blocks|changes(첫 탭은 쿼리 없음). 편집은 시트 안에서 바로(메인 기본값)
export const SHEET_TABS = ['edit', 'blocks', 'changes'] as const;

export function PolicySheet({
  id,
  rule,
  loading,
  tab,
  onTab,
  nav,
  onClose,
  start,
  editorKey,
  canWrite,
  enforceKill,
  existingIds,
  onSaved,
  onDeleted,
  onReverted,
}: {
  id: string;
  rule: PolicyView | undefined;
  loading: boolean;
  tab: string | null;
  onTab: (t: string) => void;
  nav?: SheetNav;
  onClose: () => void;
  // 편집 탭이 그릴 값(기본 규칙 「미리보기 후 추가」 · 「이 행동 허용」으로 바뀐 사본 포함)
  start: { rule: Rule; fresh: { field: ListField; value: string } | null; intro?: ReactNode; autoCheck?: boolean } | null;
  editorKey: string;
  canWrite: boolean;
  enforceKill: boolean;
  existingIds: string[];
  onSaved: (r: Rule) => void;
  onDeleted: () => void;
  onReverted: () => void;
}) {
  const system = SYSTEM_RULES.has(id);
  // 탭 머리 수(count)는 공통 탭 수 글자(11.5px)가 12px 규칙에 맞춰지면 붙인다 — 지금은 각 탭의 「총 N건」으로
  const tabs: SheetTab[] = [
    { key: 'edit', label: '편집' },
    { key: 'blocks', label: '차단 이력' },
    { key: 'changes', label: '변경 이력' },
  ];
  const cur = tab ?? 'edit';
  const st = rule ? STATUS[statusOf(rule)] : null;
  return (
    <Sheet
      kind="policy"
      title={id}
      subtitle={rule?.description || undefined}
      badges={
        rule && (
          <>
            <ActionPill rule={rule} />
            <KindBadge kind={rule.kind} label={KIND_SHORT[rule.kind]} />
            {st && statusOf(rule) !== 'on' && <StatusPill tone={st.tone}>{st.label}</StatusPill>}
          </>
        )
      }
      tabs={tabs}
      tab={cur}
      onTab={onTab}
      nav={nav}
      onClose={onClose}
      loading={loading && !rule}
    >
      {cur === 'blocks' ? (
        <PolicyHits key={id} ruleId={id} />
      ) : cur === 'changes' ? (
        <PolicyChanges
          key={id}
          ruleId={id}
          current={rule}
          canWrite={canWrite}
          onReverted={onReverted}
        />
      ) : (
        <div data-testid="editor" className="flex h-full min-h-0 flex-col">
          {system && (
            <p className="flex shrink-0 items-center gap-2 border-b border-border bg-surface-2 px-5 py-2 text-xs text-text-2" data-testid="system-rule">
              <Lock className="size-3.5" aria-hidden /> 시스템 규칙 — 도메인은{' '}
              <Link to="/policies/blocklist" className="text-accent-text hover:underline">
                차단 목록
              </Link>
              에서 관리합니다. 여기서 직접 편집할 수 없습니다.
            </p>
          )}
          {start ? (
            <div className="min-h-0 flex-1">
              <PolicyEditor
                key={editorKey}
                rule={start.rule}
                isNew={false}
                autoCheck={start.autoCheck}
                canWrite={canWrite}
                readOnly={system}
                enforceKill={enforceKill}
                existingIds={existingIds}
                fresh={start.fresh}
                intro={start.intro}
                containers={{ render: (p) => <ContainersCard {...p} /> }}
                onSaved={onSaved}
                onDeleted={onDeleted}
              />
            </div>
          ) : (
            !loading && <EmptyState title={`정책 ${id} 이(가) 지금 없습니다.`} hint="지운 정책이면 변경 이력 탭에서 지우기 전 값으로 되돌릴 수 있습니다." />
          )}
        </div>
      )}
    </Sheet>
  );
}
