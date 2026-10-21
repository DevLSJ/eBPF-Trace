import { Fragment, useRef } from 'react';

// 4칸 키 입력(목업 ui-kit keyBoxes) — 칸마다 len 자리 숫자. 붙여넣으면 그 칸부터 나눠 채우고, 다 차면 다음 칸 · 빈 칸에서 지우면 앞 칸
export function KeyBoxes({
  value,
  onChange,
  groups = 4,
  len = 4,
  label = '키',
  onEnter,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  groups?: number;
  len?: number;
  label?: string;
  onEnter?: () => void;
}) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const fillFrom = (start: number, digits: string) => {
    const next = [...value];
    let k = 0;
    for (let i = start; i < groups && k < digits.length; i++, k += len) next[i] = digits.slice(k, k + len);
    onChange(next);
    refs.current[Math.min(groups - 1, start + Math.ceil(digits.length / len) - 1)]?.focus();
  };
  return (
    <div className="flex items-center gap-1.5" data-part="key-boxes">
      {Array.from({ length: groups }, (_, i) => (
        <Fragment key={i}>
          <input
            ref={(el) => {
              refs.current[i] = el;
            }}
            inputMode="numeric"
            autoComplete="off"
            maxLength={len}
            aria-label={`${label} ${i + 1}번째 칸`}
            placeholder={'X'.repeat(len)}
            value={value[i] ?? ''}
            onPaste={(e) => {
              const d = e.clipboardData.getData('text').replace(/\D/g, '');
              if (d.length > len) {
                e.preventDefault();
                fillFrom(i, d);
              }
            }}
            onChange={(e) => {
              const d = e.target.value.replace(/\D/g, '');
              if (d.length > len) return fillFrom(i, d);
              const next = [...value];
              next[i] = d;
              onChange(next);
              if (d.length === len) refs.current[i + 1]?.focus();
            }}
            onKeyDown={(e) => {
              if (e.key === 'Backspace' && !value[i]) refs.current[i - 1]?.focus();
              if (e.key === 'Enter') onEnter?.();
            }}
            className="h-9 w-[4.5rem] rounded-md border border-slate-300 text-center font-mono tracking-[0.15em] focus:border-indigo-500 focus:outline-none"
          />
          {i < groups - 1 && (
            <span className="text-slate-400" aria-hidden>
              -
            </span>
          )}
        </Fragment>
      ))}
    </div>
  );
}
