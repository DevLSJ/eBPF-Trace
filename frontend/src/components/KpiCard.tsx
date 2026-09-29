import type { ReactNode } from 'react';

interface Props {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: 'default' | 'warn' | 'danger';
}

const tones = {
  default: 'text-slate-900',
  warn: 'text-amber-600',
  danger: 'text-red-600',
};

export function KpiCard({ label, value, hint, tone = 'default' }: Props) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
      <div className="text-sm text-slate-500">{label}</div>
      <div className={`num mt-1 text-3xl font-semibold tracking-tight ${tones[tone]}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}
