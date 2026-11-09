import { X } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import {
  actOf,
  chipsOf,
  GROUPS,
  ID_PATTERN,
  KIND_TEXT,
  listOf,
  NUM_FIELDS,
  TYPE_LABEL,
  withList,
  type Act,
  type ChipGroupDef,
  type Draft,
  type ListField,
} from '../lib/policyEasy';
import type { Kind } from '../lib/types';

// 정책 「쉬운 설정」(10/16): ① 무엇을 ② 어떤 값(칩, 바로 형식 검사) ③ 걸리면 ④ 어디에 ⑤ 이름. 요약 문장은 PolicyEditor 가 아래에 붙인다
// 11/09: ④ 「어디에」는 적용 컨테이너 카드(features/policies/ContainersCard) — PolicyEditor 가 scope 로 넘긴다.
//   큰 2단 창에서는 카드가 오른쪽 칸에 있어 ④ 를 그리지 않는다(scope 없음)
const ACT_TEXT: Record<Act, [string, string]> = {
  alert: ['알림만 보내기', '컨테이너는 그대로 두고 알립니다'],
  kill: ['즉시 격리', '컨테이너를 바로 멈춥니다'],
  dry: ['시험 운영', '격리 대상으로 표시만 하고 멈추지 않습니다 — 새 정책을 먼저 써 볼 때'],
};

export function PolicyEasy({
  draft: d,
  onChange,
  isNew,
  enforceKill,
  fresh,
  scope,
}: {
  draft: Draft;
  onChange: (d: Draft) => void;
  isNew: boolean;
  enforceKill: boolean;
  fresh: { field: ListField; value: string } | null;
  // ④ 「어디에」 칸(적용 컨테이너 카드). 없으면 ④ 를 그리지 않는다(큰 창 오른쪽 칸에 있을 때)
  scope?: ReactNode;
}) {
  const g = GROUPS[d.kind];
  const idOk = ID_PATTERN.test(d.id);

  return (
    <div className="grid max-w-3xl gap-5 text-sm">
      <Step id="what" n={1} title="무엇을 감시할까요?">
        <Radios name="easy-kind" value={d.kind} options={Object.entries(KIND_TEXT) as [Kind, [string, string]][]} onPick={(v) => onChange({ ...d, kind: v })} />
      </Step>
      <Step id="values" n={2} title={d.kind === 'open' ? '어떤 파일인가요?' : d.kind === 'exec' ? '어떤 프로그램 · 명령인가요?' : d.kind === 'dns' ? '어떤 도메인 · 질의인가요?' : '어디로 가는 연결인가요?'}>
        <ChipGroup groupKey="block" def={g.block} draft={d} onChange={onChange} fresh={null} />
        {g.allow ? (
          <ChipGroup groupKey="allow" def={g.allow} draft={d} onChange={onChange} fresh={fresh} />
        ) : (
          <p className="text-xs text-slate-500">실행 정책에는 예외 목록이 없습니다 — 예외가 필요하면 ④ 에서 적용할 컨테이너를 좁히세요.</p>
        )}
        {d.kind === 'dns' && (
          // 10/30: 유출 의심 길이 상한 2개(계약 §1 「숫자 칸」)
          <div className="grid grid-cols-2 gap-3" data-part="dns-limits">
            {NUM_FIELDS.map(({ field, label, max, hint }) => (
              <label key={field} className="grid gap-1">
                <span className="font-medium text-slate-700">
                  {label} <small className="text-xs font-normal text-slate-400">{hint}</small>
                </span>
                <input className={inputCls} type="number" min={1} max={max} inputMode="numeric" data-field={field} value={d[field]} placeholder="비우면 보지 않음" onChange={(e) => onChange({ ...d, [field]: e.target.value })} />
              </label>
            ))}
          </div>
        )}
      </Step>
      <Step id="action" n={3} title="걸리면 어떻게 할까요?">
        <Radios
          name="easy-act"
          value={actOf(d)}
          options={Object.entries(ACT_TEXT) as [Act, [string, string]][]}
          onPick={(v) => onChange({ ...d, action: v === 'alert' ? 'alert' : 'kill', dryRun: v === 'dry' })}
        />
        {!enforceKill && <p className="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">지금 서버의 자동 격리가 꺼져 있어 「즉시 격리」도 알림만 갑니다 — 서버 설정 참고</p>}
      </Step>
      {scope && (
        <Step id="scope" n={4} title="어디에 적용할까요?">
          {scope}
        </Step>
      )}
      <Step id="name" n={scope ? 5 : 4} title="이름을 붙여 주세요">
        <label className="grid gap-1">
          <span className="font-medium text-slate-700">
            설명 <span className="text-xs font-normal text-slate-400">목록에 보이는 한 줄</span>
          </span>
          <input className={inputCls} data-field="description" value={d.description} placeholder="예: 리버스 셸 포트 차단" onChange={(e) => onChange({ ...d, description: e.target.value })} />
        </label>
        <label className="grid gap-1">
          <span className="font-medium text-slate-700">
            정책 이름(영문){' '}
            <span data-required="" aria-hidden className="text-danger-text">
              *
            </span>{' '}
            <span className="text-xs font-normal text-slate-400">{isNew ? '만든 뒤에는 바꿀 수 없습니다' : '바꿀 수 없음'}</span>
          </span>
          <input className={`${inputCls} font-mono`} data-field="id" aria-label="정책 이름(영문)" aria-required="true" value={d.id} disabled={!isNew} onChange={(e) => onChange({ ...d, id: e.target.value.trim() })} />
        </label>
        {!idOk && <p className="text-xs text-red-600">영문 소문자 · 숫자 · 하이픈(-)만 쓸 수 있습니다</p>}
        <label className="flex items-center gap-2">
          <input type="checkbox" className="accent-indigo-600" checked={!d.disabled} onChange={(e) => onChange({ ...d, disabled: !e.target.checked })} />이 정책 사용
        </label>
      </Step>
    </div>
  );
}

const inputCls = 'w-full rounded-[var(--r-md)] border border-slate-300 bg-field px-2.5 py-1.5 text-sm focus:border-indigo-500 focus:outline-none disabled:bg-slate-50 disabled:text-slate-500';

function Step({ id, n, title, children }: { id: string; n: number; title: string; children: ReactNode }) {
  return (
    <section className="grid gap-2" data-step={id}>
      <h3 className="flex items-center gap-2 font-semibold text-slate-800">
        <span className="grid size-5.5 place-items-center rounded-full bg-indigo-50 text-xs text-accent-text">{n}</span>
        {title}
      </h3>
      {children}
    </section>
  );
}

function Radios<T extends string>({ name, value, options, onPick }: { name: string; value: T; options: [T, [string, string]][]; onPick: (v: T) => void }) {
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(10rem,1fr))] gap-2" role="radiogroup">
      {options.map(([v, [label, sub]]) => (
        <label key={v} className={`flex cursor-pointer gap-2 rounded-lg border px-3 py-2.5 ${value === v ? 'border-indigo-500 bg-indigo-50' : 'border-slate-200 hover:border-slate-300'}`}>
          <input type="radio" name={name} value={v} checked={value === v} onChange={() => onPick(v)} className="mt-0.5 accent-indigo-600" />
          <span className="grid gap-0.5">
            <b className="font-medium text-slate-800">{label}</b>
            <small className="text-xs text-slate-500">{sub}</small>
          </span>
        </label>
      ))}
    </div>
  );
}

function ChipGroup({
  groupKey,
  def,
  draft: d,
  onChange,
  fresh,
}: {
  groupKey: string;
  def: ChipGroupDef;
  draft: Draft;
  onChange: (d: Draft) => void;
  fresh: { field: ListField; value: string } | null;
}) {
  const [text, setText] = useState('');
  const [err, setErr] = useState('');
  const chips = chipsOf(d, def);
  const add = (raw: string) => {
    const v = raw.trim();
    if (!v) return;
    const c = def.classify(v);
    if (!c.type) {
      setErr(`「${v}」 — ${c.error}`);
      return;
    }
    const f = def.fields[c.type]!;
    const val = c.value ?? v; // 질의 유형은 대문자로 저장(10/30)
    const xs = listOf(d, f);
    setErr('');
    setText('');
    if (!xs.includes(val)) onChange(withList(d, f, [...xs, val]));
  };
  const sugg = def.suggest.filter((s) => !chips.some((c) => c.value === s));
  return (
    <div className="grid gap-1.5" data-chips={groupKey}>
      <div>
        <b className="font-medium text-slate-700">{def.label}</b> <small className="text-xs text-slate-400">{def.hint}</small>
      </div>
      <div className="flex min-h-10 flex-wrap items-center gap-1.5 rounded-[var(--r-md)] border border-slate-300 bg-field p-1.5">
        {chips.map((c) => (
          <span
            key={`${c.field}:${c.value}`}
            data-chip=""
            data-type={c.type}
            data-value={c.value}
            data-new={fresh && fresh.field === c.field && fresh.value === c.value ? '' : undefined}
            className={`inline-flex items-center gap-1.5 rounded-full py-0.5 pr-1 pl-2 text-xs ring-1 ${fresh && fresh.field === c.field && fresh.value === c.value ? 'bg-emerald-50 ring-2 ring-emerald-600' : 'bg-slate-50 ring-slate-200'}`}
          >
            <small className="text-xs text-slate-500">{TYPE_LABEL[c.type]}</small>
            <span className="font-mono">{c.value}</span>
            <button
              type="button"
              aria-label={`${c.value} 빼기`}
              className="rounded-full p-0.5 text-slate-400 hover:bg-slate-200 hover:text-slate-700"
              onClick={() => onChange(withList(d, c.field, listOf(d, c.field).filter((x) => x !== c.value)))}
            >
              <X className="size-3" aria-hidden />
            </button>
          </span>
        ))}
        <input
          className="h-7 min-w-40 flex-1 bg-transparent px-1 text-sm focus:outline-none"
          placeholder="입력 후 Enter"
          aria-label={def.label}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              add(text);
            }
          }}
        />
      </div>
      {err && (
        <p className="text-xs text-red-600" data-chip-error="">
          {err}
        </p>
      )}
      {sugg.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <small className="text-xs text-slate-400">자주 쓰는 값</small>
          {sugg.map((s) => (
            <button key={s} type="button" onClick={() => add(s)} className="rounded-full border border-dashed border-slate-300 px-2 py-0.5 text-xs text-slate-600 hover:border-indigo-500 hover:text-indigo-600">
              + {s}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
