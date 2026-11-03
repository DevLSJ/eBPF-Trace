import type { HTMLAttributes } from 'react';
import { scopeOf } from '../lib/rules';
import { DECISION_LABEL, INSTALL_STATUS_LABEL, SCAN_VERDICT_LABEL, type Decision, type InstallStatus, type Rule, type ScanVerdict } from '../lib/types';

const statusStyle: Record<InstallStatus, string> = {
  running: 'bg-indigo-50 text-indigo-700 ring-1 ring-inset ring-indigo-200',
  passed: 'bg-emerald-50 text-emerald-700',
  isolated: 'bg-red-600 text-white',
  warned: 'bg-amber-100 text-amber-800',
  failed: 'bg-slate-200 text-slate-700',
  unknown: 'bg-white text-slate-600 ring-1 ring-inset ring-slate-300',
  refused: 'bg-slate-800 text-white',
};

// 설치 결과
export function StatusBadge({ status }: { status: InstallStatus }) {
  return (
    <span data-status={status} className={`inline-block rounded px-2 py-0.5 text-xs font-medium whitespace-nowrap ${statusStyle[status]}`}>
      {INSTALL_STATUS_LABEL[status]}
    </span>
  );
}

const decisionStyle: Record<Decision, string> = {
  pending: 'bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-300',
  malicious: 'bg-red-100 text-red-800',
  false_positive: 'bg-sky-100 text-sky-800',
};

// 판정(사람의 결론)
export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span data-decision={decision} className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ${decisionStyle[decision]}`}>
      {DECISION_LABEL[decision]}
    </span>
  );
}

const scanVerdictStyle: Record<ScanVerdict, string> = {
  malicious: 'bg-red-100 text-red-700',
  vulnerable: 'bg-amber-100 text-amber-800',
  caution: 'bg-amber-100 text-amber-800',
  clean: 'bg-emerald-50 text-emerald-700',
};

// 공급망 검사 판정(검사 중 · 실패 · 4단계) — 공급망 검사 화면과 설치 목록 「정적 검사」 열(11/04)이 같은 배지. 실패 사유는 title
export function ScanVerdictBadge({
  status,
  verdict,
  error,
  className = '',
  ...rest
}: { status: 'running' | 'done' | 'failed'; verdict?: ScanVerdict | null; error?: string } & HTMLAttributes<HTMLSpanElement>) {
  const base = `rounded px-1.5 py-0.5 text-xs ${className}`;
  if (status === 'running')
    return (
      <span {...rest} className={`${base} bg-indigo-50 text-indigo-700`}>
        검사 중…
      </span>
    );
  if (status === 'failed')
    return (
      <span title={error || undefined} {...rest} className={`${base} bg-slate-100 text-slate-600`}>
        실패
      </span>
    );
  const v = verdict ?? 'clean';
  return (
    <span {...rest} className={`${base} font-medium ${scanVerdictStyle[v]}`}>
      {SCAN_VERDICT_LABEL[v]}
    </span>
  );
}

// 전체(기본)는 칩을 달지 않는다 — 좁힌 규칙만 눈에 띄게
export function ScopeChip({ rule }: { rule: Rule }) {
  const s = scopeOf(rule);
  if (s.key === 'all') return null;
  const tone = s.key === 'sandbox' ? 'bg-indigo-50 text-indigo-700' : 'bg-violet-50 text-violet-700';
  return (
    <span data-scope={s.key} className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] whitespace-nowrap ${tone}`}>
      {s.label}
    </span>
  );
}
