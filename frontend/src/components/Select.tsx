import { Check } from 'lucide-react';
import { useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';
import { placePop, usePopEvents, type Pop } from './popover';
import './table-kit.css';

// 필터 선택 상자(11/09, 참고 제품의 목록 필터 — 값 · 동작만). 기본 <select> · FilterChips 는 그대로 두고 새 화면이 쓴다.
//   첫 선택지 「<label> 전체」(값 '') · 고른 항목 = 주 색 글자 600 + 오른쪽 ✓ · 고르면 바로 onChange
//   키보드: 트리거에서 ↓ ↑ Enter Space 열기 · 목록에서 ↑ ↓ Home End 이동 · Enter 고름 · Esc 닫기(값 그대로) · Tab 닫기
//   항목이 searchAt(기본 10)개를 넘으면 목록 맨 위 검색칸(입력이 그쪽으로), 맞는 것이 없으면 「일치 항목 없음」
//   aria: 트리거 role=combobox · aria-haspopup=listbox · aria-expanded · aria-controls, 목록 role=listbox · 항목 role=option · aria-selected · aria-activedescendant
//   펼친 목록은 body(모달 안이면 그 dialog)에 붙어 잘리지 않는다
export interface SelectOption {
  value: string;
  label: string;
}

export function Select({
  label,
  value,
  options,
  onChange,
  name,
  all = true,
  allLabel,
  searchAt = 10,
  disabled,
  className,
}: {
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  // data-filter 이름(시험 · 화면 구분)
  name?: string;
  // 「○○ 전체」 첫 선택지(값 '')를 둔다
  all?: boolean;
  allLabel?: string;
  searchAt?: number;
  disabled?: boolean;
  className?: string;
}) {
  const trig = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const listId = useId();
  const [pop, setPop] = useState<Pop | null>(null);
  const [active, setActive] = useState(0);
  const [q, setQ] = useState('');
  const items = useMemo(() => (all ? [{ value: '', label: allLabel ?? `${label} 전체` }, ...options] : options), [all, allLabel, label, options]);
  const searchable = options.length > searchAt;
  const shown = useMemo(() => {
    const t = q.trim().toLowerCase();
    return t ? items.filter((o) => o.label.toLowerCase().includes(t)) : items;
  }, [items, q]);
  const cur = items.find((o) => o.value === value) ?? (all ? items[0] : undefined);
  const optId = (i: number) => `${listId}-o${i}`;

  const close = (focusBack: boolean) => {
    setPop(null);
    setQ('');
    if (focusBack) trig.current?.focus();
  };
  const place = () => trig.current && setPop(placePop(trig.current));
  usePopEvents(!!pop, [trig, box], close, place);
  const open = () => {
    if (disabled || !trig.current) return;
    setQ('');
    setActive(Math.max(0, items.findIndex((o) => o.value === value)));
    setPop(placePop(trig.current));
    // 열면 초점은 검색칸(있으면) 또는 목록 — aria-activedescendant 로 지금 항목을 알린다
    requestAnimationFrame(() => box.current?.querySelector<HTMLElement>(searchable ? 'input' : '[role="listbox"]')?.focus());
  };
  const pick = (o: SelectOption | undefined) => {
    if (!o) return;
    close(true);
    if (o.value !== value) onChange(o.value);
  };
  const scrollTo = (i: number) => requestAnimationFrame(() => document.getElementById(optId(i))?.scrollIntoView({ block: 'nearest' }));
  const onTrigKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (pop || !['ArrowDown', 'ArrowUp', 'Enter', ' ', 'F4'].includes(e.key)) return;
    e.preventDefault();
    open();
  };
  const onListKey = (e: KeyboardEvent<HTMLElement>) => {
    const n = shown.length;
    const go = (i: number) => {
      e.preventDefault();
      if (!n) return;
      const k = Math.max(0, Math.min(n - 1, i));
      setActive(k);
      scrollTo(k);
    };
    if (e.key === 'ArrowDown') return go(active + 1);
    if (e.key === 'ArrowUp') return go(active - 1);
    if (e.key === 'Home' && !searchable) return go(0);
    if (e.key === 'End' && !searchable) return go(n - 1);
    if (e.key === 'PageDown') return go(active + 5);
    if (e.key === 'PageUp') return go(active - 5);
    if (e.key === 'Enter') {
      e.preventDefault();
      return pick(shown[active]);
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      close(true);
    }
  };
  const activeId = pop && shown[active] ? optId(active) : undefined;

  return (
    <>
      <button
        ref={trig}
        type="button"
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={!!pop}
        aria-controls={pop ? listId : undefined}
        aria-label={label}
        data-filter={name}
        data-value={value}
        data-on={value ? '' : undefined}
        disabled={disabled}
        className={`tk-select${className ? ` ${className}` : ''}`}
        onClick={() => (pop ? close(false) : open())}
        onKeyDown={onTrigKey}
      >
        <span className="tk-select-text">{cur?.label ?? value}</span>
      </button>
      {pop &&
        createPortal(
          <div ref={box} data-overlay="select" className="tk-pop tk-listpop" style={pop.style}>
            {searchable && (
              <input
                type="text"
                role="searchbox"
                className="tk-pop-search"
                aria-label={`${label} 항목 검색`}
                placeholder="검색"
                aria-controls={listId}
                aria-activedescendant={activeId}
                value={q}
                maxLength={100}
                onChange={(e) => {
                  setQ(e.target.value);
                  setActive(0);
                }}
                onKeyDown={onListKey}
              />
            )}
            <ul id={listId} role="listbox" aria-label={label} tabIndex={-1} aria-activedescendant={searchable ? undefined : activeId} className="tk-listbox" onKeyDown={searchable ? undefined : onListKey}>
              {shown.map((o, i) => {
                const sel = o.value === value;
                return (
                  <li
                    key={o.value || '__all'}
                    id={optId(i)}
                    role="option"
                    aria-selected={sel}
                    data-value={o.value}
                    data-active={i === active ? '' : undefined}
                    className="tk-option"
                    onPointerMove={() => i !== active && setActive(i)}
                    onClick={() => pick(o)}
                  >
                    <span className="tk-option-text">{o.label}</span>
                    {sel && <Check className="tk-option-check" aria-hidden />}
                  </li>
                );
              })}
            </ul>
            {!shown.length && (
              <div className="tk-pop-empty" role="status">
                일치 항목 없음
              </div>
            )}
          </div>,
          pop.host,
        )}
    </>
  );
}
