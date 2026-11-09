import type { HTMLAttributes } from 'react';
import { scopeOf } from '../lib/rules';
import { DECISION_LABEL, INSTALL_STATUS_LABEL, SCAN_VERDICT_LABEL, type Decision, type InstallStatus, type Rule, type ScanVerdict } from '../lib/types';

const statusStyle: Record<InstallStatus, string> = {
  running: 'sg-pill-info',
  passed: 'sg-pill-ok',
  isolated: 'sg-pill-danger',
  warned: 'sg-pill-warn',
  failed: 'sg-pill-neutral',
  unknown: 'sg-pill-neutral',
  refused: 'sg-pill-dark',
};

// 상태 배지(11/05 참고 대시보드): sg-pill = 27 · 12.5/750 · 톤 테두리 · 알약 모양. 톤 = 진행 info · 통과 ok · 격리 danger · 경고 warn · 실패/모름 neutral · 거부 dark
// 설치 결과
export function StatusBadge({ status }: { status: InstallStatus }) {
  return (
    <span data-status={status} className={`sg-pill ${statusStyle[status]}`}>
      {INSTALL_STATUS_LABEL[status]}
    </span>
  );
}

const decisionStyle: Record<Decision, string> = {
  pending: 'sg-pill-warn',
  malicious: 'sg-pill-danger',
  false_positive: 'sg-pill-info',
};

// 판정(사람의 결론)
export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span data-decision={decision} className={`sg-pill ${decisionStyle[decision]}`}>
      {DECISION_LABEL[decision]}
    </span>
  );
}

const scanVerdictStyle: Record<ScanVerdict, string> = {
  malicious: 'sg-pill-danger',
  vulnerable: 'sg-pill-warn',
  caution: 'sg-pill-warn',
  clean: 'sg-pill-ok',
};

// 공급망 검사 판정(검사 중 · 실패 · 4단계) — 공급망 검사 화면과 설치 목록 「정적 검사」 열(11/04)이 같은 배지. 실패 사유는 title
export function ScanVerdictBadge({
  status,
  verdict,
  error,
  className = '',
  ...rest
}: { status: 'running' | 'done' | 'failed'; verdict?: ScanVerdict | null; error?: string } & HTMLAttributes<HTMLSpanElement>) {
  const base = `sg-pill ${className}`;
  if (status === 'running')
    return (
      <span {...rest} className={`${base} sg-pill-info`}>
        검사 중…
      </span>
    );
  if (status === 'failed')
    return (
      <span title={error || undefined} {...rest} className={`${base} sg-pill-neutral`}>
        실패
      </span>
    );
  const v = verdict ?? 'clean';
  return (
    <span {...rest} className={`${base} ${scanVerdictStyle[v]}`}>
      {SCAN_VERDICT_LABEL[v]}
    </span>
  );
}

// 전체(기본)는 칩을 달지 않는다 — 좁힌 규칙만 눈에 띄게
export function ScopeChip({ rule }: { rule: Rule }) {
  const s = scopeOf(rule);
  if (s.key === 'all') return null;
  const tone = s.key === 'sandbox' ? 'bg-indigo-50 text-accent-text' : 'bg-violet-50 text-violet-700';
  return (
    <span data-scope={s.key} className={`shrink-0 rounded px-1.5 py-0.5 text-xs whitespace-nowrap ${tone}`}>
      {s.label}
    </span>
  );
}
