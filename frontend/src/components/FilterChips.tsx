// 필터 칩 묶음 — 키보드로 고를 수 있는 토글 버튼(aria-pressed)
export function FilterChips<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { value: T; label: string; count?: number }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={label}>
      <span className="w-12 shrink-0 text-xs text-slate-500">{label}</span>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={o.value === value}
          data-chip={o.value}
          onClick={() => onChange(o.value)}
          className={`rounded-full border px-2.5 py-0.5 text-xs whitespace-nowrap ${
            o.value === value ? 'border-indigo-600 bg-indigo-600 text-white' : 'border-slate-300 text-slate-600 hover:bg-slate-50'
          }`}
        >
          {o.label}
          {o.count !== undefined && <span className={`num ml-1 ${o.value === value ? 'text-indigo-100' : 'text-slate-400'}`}>{o.count}</span>}
        </button>
      ))}
    </div>
  );
}
