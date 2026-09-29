import { Play, Trash2 } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import YAML from 'yaml';
import { api, ApiError } from '../lib/api';
import { ConfirmButton } from './ConfirmButton';
import { KINDS, type Kind, type Rule } from '../lib/types';

type ListField =
  | 'containers'
  | 'denyComms'
  | 'denyArgs'
  | 'denyPaths'
  | 'allowPaths'
  | 'allowPorts'
  | 'allowCidrs'
  | 'denyPorts'
  | 'denyCidrs'
  | 'allowHosts'
  | 'denyHosts';

const portFields: ListField[] = ['allowPorts', 'denyPorts'];

// Kind별로 편집할 조건 필드
const fieldsByKind: Record<Kind, { field: ListField; label: string; hint: string }[]> = {
  exec: [
    { field: 'denyComms', label: '금지 프로세스', hint: 'comm 또는 argv[0] 이름 (예: curl, wget, nc)' },
    { field: 'denyArgs', label: '금지 인자 패턴', hint: '인자 문자열에 포함되면 위반 (예: | sh)' },
  ],
  open: [
    { field: 'denyPaths', label: '금지 경로', hint: '접두사 일치, * ? [ ] 가 있으면 glob (예: /home/*/.ssh/*)' },
    { field: 'allowPaths', label: '예외 경로', hint: '금지 경로보다 먼저 평가되는 허용 목록' },
  ],
  connect: [
    { field: 'allowPorts', label: '허용 포트', hint: '허용 포트·대역·도메인 중 하나면 통과, 그 밖은 위반' },
    { field: 'allowCidrs', label: '허용 대역', hint: 'CIDR 또는 IP (예: 10.0.0.0/8)' },
    { field: 'allowHosts', label: '허용 도메인', hint: 'DNS 응답으로 확인한 목적지 이름. pypi.org 는 *.pypi.org 도 포함' },
    { field: 'denyPorts', label: '금지 포트', hint: '허용 목록과 무관하게 항상 위반' },
    { field: 'denyCidrs', label: '금지 대역', hint: '허용 목록과 무관하게 항상 위반' },
    { field: 'denyHosts', label: '금지 도메인', hint: '허용 목록과 무관하게 항상 위반' },
  ],
};

const allListFields: ListField[] = ['containers', ...Object.values(fieldsByKind).flat().map((f) => f.field)];

interface Draft {
  id: string;
  description: string;
  kind: Kind;
  action: Rule['action'];
  dryRun: boolean;
  disabled: boolean;
  lists: Record<ListField, string>;
}

function toDraft(r: Rule): Draft {
  const lists = {} as Record<ListField, string>;
  for (const f of allListFields) lists[f] = ((r[f] as (string | number)[] | undefined) ?? []).join('\n');
  return {
    id: r.id,
    description: r.description ?? '',
    kind: r.kind,
    action: r.action,
    dryRun: !!r.dryRun,
    disabled: !!r.disabled,
    lists,
  };
}

// 폼 → Rule. 현재 kind에 해당하지 않는 조건은 버린다.
function toRule(d: Draft): Rule {
  const rule: Rule = { id: d.id.trim(), kind: d.kind, action: d.action };
  if (d.description.trim()) rule.description = d.description.trim();
  if (d.dryRun) rule.dryRun = true;
  if (d.disabled) rule.disabled = true;
  const active: ListField[] = ['containers', ...fieldsByKind[d.kind].map((f) => f.field)];
  for (const f of active) {
    const items = d.lists[f]
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!items.length) continue;
    if (portFields.includes(f)) {
      const ports = items.map(Number);
      const bad = items.find((_, i) => !Number.isInteger(ports[i]) || ports[i] < 1 || ports[i] > 65535);
      if (bad) throw new Error(`포트 값 오류: ${bad}`);
      (rule[f] as number[]) = ports;
    } else {
      (rule[f] as string[]) = items;
    }
  }
  return rule;
}

interface Props {
  rule: Rule;
  isNew: boolean;
  canWrite: boolean;
  onSaved: (r: Rule) => void;
  onDeleted: (id: string) => void;
}

const input = 'w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm focus:border-indigo-500 focus:outline-none disabled:bg-slate-50 disabled:text-slate-500';

export function PolicyEditor({ rule, isNew, canWrite, onSaved, onDeleted }: Props) {
  const [draft, setDraft] = useState<Draft>(() => toDraft(rule));
  const [mode, setMode] = useState<'form' | 'yaml'>('form');
  const [yamlText, setYamlText] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);

  const update = (patch: Partial<Draft>) => {
    setDraft((d) => ({ ...d, ...patch }));
    setSaved(false);
  };
  const updateList = (f: ListField, v: string) => update({ lists: { ...draft.lists, [f]: v } });

  const switchMode = (next: 'form' | 'yaml') => {
    if (next === mode) return;
    setError('');
    try {
      if (next === 'yaml') {
        setYamlText(YAML.stringify(toRule(draft)));
      } else {
        const parsed = YAML.parse(yamlText) as Rule;
        if (!parsed || typeof parsed !== 'object') throw new Error('YAML 최상위는 규칙 객체여야 함');
        if (!isNew && parsed.id !== rule.id) throw new Error('기존 정책의 id는 바꿀 수 없음 — 새 정책으로 만드세요');
        setDraft(toDraft(parsed));
      }
      setMode(next);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const current = (): Rule => {
    if (mode === 'form') return toRule(draft);
    const parsed = YAML.parse(yamlText) as Rule;
    if (!isNew && parsed?.id !== rule.id) throw new Error('기존 정책의 id는 바꿀 수 없음');
    return parsed;
  };

  const save = async () => {
    setError('');
    setBusy(true);
    try {
      const r = await api.saveRule(current());
      setDraft(toDraft(r));
      setSaved(true);
      onSaved(r);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.status} · ${e.message}` : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    try {
      await api.deleteRule(rule.id);
      onDeleted(rule.id);
    } catch (e) {
      setError(e instanceof ApiError ? `${e.status} · ${e.message}` : (e as Error).message);
      setBusy(false);
    }
  };

  const effective = draft.action === 'kill' && draft.dryRun ? 'kill → 알림만 (dry-run)' : draft.action;

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-center justify-between border-b border-slate-100 px-5 py-2.5">
        <div className="flex rounded-md border border-slate-300 p-0.5 text-xs font-medium" role="group" aria-label="편집 방식">
          {(['form', 'yaml'] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => switchMode(m)}
              className={`rounded px-3 py-1 ${mode === m ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100'}`}
            >
              {m === 'form' ? '폼' : 'YAML'}
            </button>
          ))}
        </div>
        <span className="text-xs text-slate-500">
          적용 결과: <b className={draft.action === 'kill' && !draft.dryRun ? 'text-red-600' : 'text-amber-600'}>{effective}</b>
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
        {mode === 'yaml' ? (
          <textarea
            className={`${input} h-full min-h-80 font-mono text-xs leading-relaxed`}
            value={yamlText}
            spellCheck={false}
            onChange={(e) => {
              setYamlText(e.target.value);
              setSaved(false);
            }}
            aria-label="정책 YAML"
          />
        ) : (
          <div className="grid max-w-2xl gap-4 text-sm">
            <Field label="id" hint="소문자·숫자·하이픈">
              <input className={input} value={draft.id} disabled={!isNew} onChange={(e) => update({ id: e.target.value })} />
            </Field>
            <Field label="설명">
              <input className={input} value={draft.description} onChange={(e) => update({ description: e.target.value })} />
            </Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label="kind">
                <select className={input} value={draft.kind} onChange={(e) => update({ kind: e.target.value as Kind })}>
                  {KINDS.map((k) => (
                    <option key={k}>{k}</option>
                  ))}
                </select>
              </Field>
              <Field label="action">
                <select className={input} value={draft.action} onChange={(e) => update({ action: e.target.value as Rule['action'] })}>
                  <option value="alert">alert — 알림</option>
                  <option value="kill">kill — 컨테이너 강제 종료</option>
                </select>
              </Field>
            </div>
            {fieldsByKind[draft.kind].map(({ field, label, hint }) => (
              <Field key={field} label={label} hint={hint}>
                <textarea
                  className={`${input} min-h-20 font-mono text-xs`}
                  value={draft.lists[field]}
                  onChange={(e) => updateList(field, e.target.value)}
                  placeholder="한 줄에 하나"
                />
              </Field>
            ))}
            <Field label="적용 컨테이너" hint="이름 또는 이미지 glob, 비우면 전체 (예: pkg-*)">
              <textarea
                className={`${input} min-h-14 font-mono text-xs`}
                value={draft.lists.containers}
                onChange={(e) => updateList('containers', e.target.value)}
                placeholder="전체"
              />
            </Field>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={draft.disabled} onChange={(e) => update({ disabled: e.target.checked })} className="accent-indigo-600" />
              비활성화 (평가하지 않음)
            </label>
          </div>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-3 border-t border-slate-100 px-5 py-3">
        {mode === 'form' && (
          <label className="flex cursor-pointer items-center gap-2 text-sm select-none" title="kill 정책을 알림만 보내도록 강제 (오탐 시 컨테이너 보호)">
            <span
              role="switch"
              aria-checked={draft.dryRun}
              tabIndex={0}
              onClick={() => update({ dryRun: !draft.dryRun })}
              onKeyDown={(e) => (e.key === ' ' || e.key === 'Enter') && update({ dryRun: !draft.dryRun })}
              className={`relative h-5 w-9 rounded-full transition-colors ${draft.dryRun ? 'bg-amber-500' : 'bg-slate-300'}`}
            >
              <span className={`absolute top-0.5 size-4 rounded-full bg-white transition-all ${draft.dryRun ? 'left-4.5' : 'left-0.5'}`} />
            </span>
            dry-run
          </label>
        )}
        {error && <span className="min-w-0 flex-1 truncate text-sm text-red-600" title={error}>{error}</span>}
        {saved && !error && <span className="flex-1 text-sm text-emerald-600">저장 후 엔진에 적용됨</span>}
        <div className="ml-auto flex gap-2">
          {!isNew && (
            <ConfirmButton
              onConfirm={remove}
              confirmLabel="눌러서 삭제 확정"
              disabled={busy || !canWrite}
              className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm text-red-600 hover:bg-red-50 disabled:opacity-40"
            >
              <Trash2 className="size-4" aria-hidden /> 삭제
            </ConfirmButton>
          )}
          <button
            type="button"
            onClick={save}
            disabled={busy || !canWrite}
            title={canWrite ? undefined : '관리자 토큰을 입력하세요'}
            className="flex items-center gap-1.5 rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-40"
          >
            저장 후 적용 <Play className="size-3.5" aria-hidden />
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="grid gap-1">
      <span className="font-medium text-slate-700">
        {label}
        {hint && <span className="ml-2 text-xs font-normal text-slate-400">{hint}</span>}
      </span>
      {children}
    </label>
  );
}
