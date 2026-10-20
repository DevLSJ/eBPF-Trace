import type { Kind } from '../lib/types';

const style: Record<Kind, string> = {
  exec: 'bg-violet-50 text-violet-700',
  open: 'bg-sky-50 text-sky-700',
  connect: 'bg-teal-50 text-teal-700',
};

// label: 쉬운 말 표기(정책 목록 「파일 · 실행 · 통신」). 없으면 kind 그대로
export function KindBadge({ kind, label }: { kind: Kind; label?: string }) {
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-center text-xs ${label ? 'w-10' : 'w-16 font-mono'} ${style[kind]}`} title={kind}>
      {label ?? kind}
    </span>
  );
}
