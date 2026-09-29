import type { Kind } from '../lib/types';

const style: Record<Kind, string> = {
  exec: 'bg-violet-50 text-violet-700',
  open: 'bg-sky-50 text-sky-700',
  connect: 'bg-teal-50 text-teal-700',
};

export function KindBadge({ kind }: { kind: Kind }) {
  return <span className={`inline-block w-16 rounded px-1.5 py-0.5 text-center font-mono text-xs ${style[kind]}`}>{kind}</span>;
}
