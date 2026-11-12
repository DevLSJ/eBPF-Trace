'use client';
import { useState } from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { WL_GROUPS, normalizeEntry, validateWhitelist, type Whitelist, type WlField } from '@/lib/whitelist';

// 허용 목록 편집기 (ADR-020 U4): 기본은 항목별 칩 편집, 「고급」은 JSON 글자 편집.
// 어느 쪽이든 저장 전 validateWhitelist를 통과해야 onSave가 불린다.
export function WhitelistEditor({
  value,
  defaults,
  onSave,
}: {
  value: Whitelist;
  defaults: Whitelist;
  onSave: (wl: Whitelist) => Promise<void>;
}) {
  const [draft, setDraft] = useState<Whitelist>(value);
  const [saved, setSaved] = useState<Whitelist>(value);
  const [advanced, setAdvanced] = useState(false);
  const [text, setText] = useState('');
  const [textErrors, setTextErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);

  // 부모가 서버 값을 늦게 받아오면 아직 손대지 않았을 때만 반영
  const [seen, setSeen] = useState(value);
  if (value !== seen) {
    setSeen(value);
    if (JSON.stringify(draft) === JSON.stringify(saved)) {
      setDraft(value);
      setSaved(value);
    }
  }

  const dirty = advanced ? text !== JSON.stringify(saved, null, 2) : JSON.stringify(draft) !== JSON.stringify(saved);

  const openAdvanced = () => {
    setText(JSON.stringify(draft, null, 2));
    setTextErrors([]);
    setAdvanced(true);
  };

  // 글자 → 객체. 실패하면 사유 목록을 보여주고 그대로 둔다.
  const parseText = (): Whitelist | null => {
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch (e) {
      setTextErrors([`글자 형식이 올바르지 않습니다: ${(e as Error).message}`]);
      return null;
    }
    const r = validateWhitelist(raw);
    setTextErrors(r.errors);
    return r.value ?? null;
  };

  const closeAdvanced = () => {
    const v = parseText();
    if (!v) return;
    setDraft(v);
    setAdvanced(false);
  };

  const save = async () => {
    const v = advanced ? parseText() : validateWhitelist(draft).value ?? null;
    if (!v) return;
    setSaving(true);
    try {
      await onSave(v);
      setDraft(v);
      setSaved(v);
      if (advanced) setText(JSON.stringify(v, null, 2));
    } catch {
      /* 실패 안내는 부모(onSave)가 한다. 편집 내용은 그대로 둔다 */
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <b className="text-[13.5px]">검사 기준 (허용 목록)</b>
          <p className="mt-0.5 text-[12px] text-fg-2">저장하면 연결된 런타임 에이전트에 바로 적용됩니다.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={advanced ? closeAdvanced : openAdvanced}
            aria-pressed={advanced}
            className="rounded-lg border border-line-strong px-3 py-1.5 text-[12px] font-semibold"
          >
            {advanced ? '쉬운 화면으로' : '고급 (글자 편집)'}
          </button>
          <button
            type="button"
            onClick={() => {
              if (advanced) setText(JSON.stringify(defaults, null, 2));
              else setDraft(defaults);
            }}
            className="rounded-lg border border-line-strong px-3 py-1.5 text-[12px] font-semibold"
          >
            기본값으로
          </button>
          <button
            type="button"
            onClick={() => void save()}
            disabled={!dirty || saving}
            className="rounded-lg bg-accent px-3 py-1.5 text-[12px] font-bold text-white disabled:opacity-40"
          >
            {saving ? '적용 중…' : dirty ? '저장 후 에이전트에 적용' : '저장됨'}
          </button>
        </div>
      </div>

      {advanced ? (
        <div className="flex flex-col gap-2">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            aria-label="허용 목록 글자 편집"
            className="h-72 w-full resize-y rounded-lg border border-line-strong bg-surface-2 p-3 font-mono text-[12px] leading-relaxed"
          />
          {textErrors.length > 0 && (
            <ul role="alert" className="flex flex-col gap-0.5 rounded-lg bg-crit-soft px-3 py-2 text-[12.5px] text-crit-ink">
              {textErrors.slice(0, 8).map((e) => <li key={e}>{e}</li>)}
              {textErrors.length > 8 && <li>외 {textErrors.length - 8}건</li>}
            </ul>
          )}
        </div>
      ) : (
        WL_GROUPS.map((g) => (
          <div key={g.title} className="rounded-xl border border-line">
            <div className="border-b border-line px-3.5 py-2.5">
              <b className="text-[13px]">{g.title}</b>
              <span className="ml-2 text-[12px] text-fg-3">{g.help}</span>
            </div>
            <div className="flex flex-col divide-y divide-line">
              {g.fields.map((f) => (
                <FieldRow
                  key={f.key}
                  field={f}
                  items={draft[f.key] as (string | number)[]}
                  onChange={(items) => setDraft((d) => ({ ...d, [f.key]: items }))}
                />
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function FieldRow({ field, items, onChange }: { field: WlField; items: (string | number)[]; onChange: (v: (string | number)[]) => void }) {
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);

  const add = () => {
    const r = normalizeEntry(field.kind, input);
    if (r.error) return setError(r.error);
    if (items.some((i) => String(i) === String(r.value))) return setError('이미 있는 값입니다');
    onChange([...items, r.value!]);
    setInput('');
    setError(null);
  };

  return (
    <div className="grid gap-2 px-3.5 py-3 md:grid-cols-[200px_minmax(0,1fr)]">
      <div>
        <div className="text-[13px] font-semibold">{field.title}</div>
        <div className="text-[11.5px] leading-snug text-fg-3">{field.help}</div>
      </div>
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap gap-1.5">
          {items.length === 0 && <span className="text-[12px] text-fg-3">비어 있음</span>}
          {items.map((it) => (
            <span key={String(it)} className="inline-flex items-center gap-1 rounded-full border border-line bg-surface-2 py-0.5 pl-2.5 pr-1 font-mono text-[12px]">
              {String(it)}
              <button
                type="button"
                aria-label={`${field.title}에서 ${String(it)} 빼기`}
                onClick={() => onChange(items.filter((x) => x !== it))}
                className="grid h-4 w-4 place-items-center rounded-full text-fg-3 hover:bg-crit-soft hover:text-crit-ink"
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            value={input}
            onChange={(e) => { setInput(e.target.value); setError(null); }}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
            placeholder={field.placeholder}
            aria-label={`${field.title} 추가`}
            aria-invalid={!!error}
            className={cn('min-w-0 flex-1 rounded-lg border bg-surface px-2.5 py-1.5 text-[12.5px] outline-none focus:border-accent', error ? 'border-crit' : 'border-line-strong')}
          />
          <button type="button" onClick={add} className="shrink-0 rounded-lg border border-line-strong px-3 py-1.5 text-[12px] font-semibold">
            추가
          </button>
        </div>
        {error && <div className="text-[12px] text-crit-ink">{error}</div>}
      </div>
    </div>
  );
}
