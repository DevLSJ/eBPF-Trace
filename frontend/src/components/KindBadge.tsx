import { KIND_LONG, type RuleKind } from '../lib/types';

// dns(10/30)는 amber 계열(계약 §1 — 토큰 --warn-soft/--warn) · sequence(11/04, 연쇄 규칙 — 정책 목록에만)는 accent 토큰(index.css .badge-kind-sequence)
const style: Record<RuleKind, string> = {
  exec: 'bg-violet-50 text-violet-700',
  open: 'bg-sky-50 text-sky-700',
  connect: 'bg-teal-50 text-teal-700',
  dns: 'bg-amber-50 text-amber-800',
  sequence: 'badge-kind-sequence',
};

// label: 쉬운 말 표기(정책 목록 「파일 · 실행 · 통신 · 조회」). 없으면 kind 그대로. 툴팁은 긴 이름(「도메인 조회」 등)
export function KindBadge({ kind, label }: { kind: RuleKind; label?: string }) {
  return (
    <span data-kind-badge={kind} className={`inline-block rounded px-1.5 py-0.5 text-center text-xs ${label ? 'w-10' : 'w-16 font-mono'} ${style[kind]}`} title={kind === 'sequence' ? '연쇄' : KIND_LONG[kind]}>
      {label ?? kind}
    </span>
  );
}
