import { Lock } from 'lucide-react';
import { StatusPill } from '../../components/DataTable';
import { SANDBOX_SCOPE } from '../../lib/policyEasy';
import type { Rule } from '../../lib/types';
import { ACTION_LABEL, scopeFromList } from './policyRow';

// 정책 목록 · 시트의 작은 표기 부품(11/09): 판정 배지 · 적용 컨테이너 칩 · 시스템 규칙 표시
export const ActionPill = ({ rule: r }: { rule: Rule }) => (
  <StatusPill tone={r.action === 'kill' ? 'danger' : 'warn'} data-action-badge={r.action}>
    {ACTION_LABEL[r.action]}
  </StatusPill>
);


const CHIP = 'shrink-0 rounded-[var(--r-sm)] px-1.5 py-0.5 text-xs whitespace-nowrap';
export function ContainerChips({ rule }: { rule: Rule }) {
  const xs = rule.containers ?? [];
  const s = scopeFromList(xs);
  if (s === 'all') return <span className="whitespace-nowrap text-text-2">모든 컨테이너</span>;
  if (s === 'sandbox')
    return (
      <span data-scope="sandbox" title={SANDBOX_SCOPE} className={`${CHIP} bg-accent-soft text-accent-text`}>
        설치 검사
      </span>
    );
  const shown = xs.slice(0, 2);
  return (
    <span className="flex min-w-0 items-center gap-1" data-scope="some" title={xs.join(' · ')}>
      {shown.map((x) => (
        <span key={x} className={`${CHIP} min-w-0 truncate bg-surface-2 font-mono text-text-2 ring-1 ring-border`}>
          {x}
        </span>
      ))}
      {xs.length > shown.length && <span className="num shrink-0 text-xs text-text-3">+{xs.length - shown.length}</span>}
    </span>
  );
}

export function SystemMark() {
  return (
    <span className="ml-1 inline-flex items-center gap-0.5 text-text-3" data-system="">
      <Lock className="size-3" aria-hidden /> 차단 목록에서 관리
    </span>
  );
}
