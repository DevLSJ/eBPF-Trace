import { ArrowLeft, ArrowRight, Play, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import YAML from 'yaml';
import { api, ApiError } from '../lib/api';
import { fmtNum } from '../lib/format';
import { ID_PATTERN, NUM_FIELDS, summarize, toDraft, toRule, type Draft, type ListField } from '../lib/policyEasy';
import { ConfirmDialog } from './Modal';
import { PolicyEasy } from './PolicyEasy';
import { KINDS, type DirectIp, type Kind, type Level, type Preview, type Rule } from '../lib/types';

// 고급 폼의 조건 필드 이름 · 설명(쉬운 설정은 components/PolicyEasy.tsx)
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
  // dns(10/30 계약 §1 고급 폼): 길이 상한 2개는 아래 숫자 칸(dns 에서만)
  dns: [
    { field: 'allowHosts', label: '허용 도메인', hint: '하나라도 있으면 여기 없는 도메인 질의는 위반(점 없는 이름 · *.arpa · *.local · *.internal 제외)' },
    { field: 'denyHosts', label: '금지 도메인', hint: '접미사 일치 — 허용 목록과 무관하게 항상 위반' },
    { field: 'denyQtypes', label: '금지 질의 유형', hint: '대문자(예: TXT, ALL) — 허용 목록과 무관하게 항상 위반' },
  ],
};

interface Props {
  rule: Rule;
  isNew: boolean;
  canWrite: boolean;
  // 쓰기 자체가 막힌 정책(시스템 규칙) — 저장 전 확인도 막는다
  readOnly?: boolean;
  enforceKill: boolean;
  existingIds: string[];
  // 이벤트 · 감사 행 「이 행동 허용」으로 새로 더한 예외(강조)
  fresh?: { field: ListField; value: string } | null;
  // 처음 그릴 때 바로 「저장 전 확인」을 연다(새 기본 규칙 「미리보기 후 추가」, 10/20 F)
  autoCheck?: boolean;
  onSaved: (r: Rule) => void;
  onDeleted: (id: string) => void;
}

const input = 'w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm focus:border-indigo-500 focus:outline-none disabled:bg-slate-50 disabled:text-slate-500';
type Mode = 'easy' | 'form' | 'yaml';
const MODES: [Mode, string][] = [
  ['easy', '쉬운 설정'],
  ['form', '고급 · 폼'],
  ['yaml', '고급 · YAML'],
];
const LV: Record<Level, string> = { normal: '통과', alert: '알림', held: '격리 대상', killed: '격리' };
const LV_TO: Record<Level, string> = { normal: '통과로', alert: '알림으로', held: '격리 대상으로', killed: '격리로' };

// 정책 편집 — 쉬운 설정(기본) · 고급 폼 · 고급 YAML 이 같은 draft 를 고친다.
// 저장은 늘 「저장 전 확인」(한 줄 요약 + 최근 감사 로그 재평가 POST /api/policies/preview)을 거친다 (10/16 목업 확정)
export function PolicyEditor({ rule, isNew, canWrite, readOnly, enforceKill, existingIds, fresh, autoCheck, onSaved, onDeleted }: Props) {
  const [draft, setDraft] = useState<Draft>(() => toDraft(rule));
  const [mode, setMode] = useState<Mode>('easy');
  const [yamlText, setYamlText] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [freshMark, setFreshMark] = useState(fresh ?? null);
  const [check, setCheck] = useState<{ rule: Rule; preview: Preview | null; error: string } | null>(null);
  const [askDelete, setAskDelete] = useState(false);

  const change = (d: Draft) => {
    setDraft(d);
    setSaved(false);
    setError('');
  };
  const update = (patch: Partial<Draft>) => change({ ...draft, ...patch });
  const updateList = (f: ListField, v: string) => update({ lists: { ...draft.lists, [f]: v } });

  const switchMode = (next: Mode) => {
    if (next === mode) return;
    setError('');
    try {
      if (next === 'yaml') {
        setYamlText(YAML.stringify(toRule(draft)));
      } else if (mode === 'yaml') {
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
    if (mode !== 'yaml') return toRule(draft);
    const parsed = YAML.parse(yamlText) as Rule;
    if (!isNew && parsed?.id !== rule.id) throw new Error('기존 정책의 id는 바꿀 수 없음');
    return parsed;
  };

  const openCheck = async () => {
    setError('');
    let r: Rule;
    try {
      r = current();
      if (!ID_PATTERN.test(r.id ?? '')) throw new Error('정책 이름은 영문 소문자 · 숫자 · 하이픈(-)만 쓸 수 있습니다');
      if (isNew && existingIds.includes(r.id)) throw new Error(`이미 있는 이름입니다: ${r.id} — 다른 이름을 쓰세요`);
    } catch (e) {
      setError((e as Error).message);
      return;
    }
    setCheck({ rule: r, preview: null, error: '' });
    try {
      const pv = await api.previewRule(r);
      setCheck((c) => (c && c.rule === r ? { ...c, preview: pv } : c));
    } catch (e) {
      setCheck((c) => (c && c.rule === r ? { ...c, error: e instanceof ApiError ? `${e.status} · ${e.message}` : (e as Error).message } : c));
    }
  };

  // 새 기본 규칙: 열자마자 저장 전 확인(StrictMode 이중 실행에도 한 번)
  const autoDone = useRef(false);
  useEffect(() => {
    if (!autoCheck || autoDone.current) return;
    autoDone.current = true;
    void openCheck();
    // openCheck 는 처음 그린 draft 로 한 번만 부른다
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoCheck]);

  const save = async (r: Rule) => {
    setError('');
    setBusy(true);
    try {
      const out = await api.saveRule(r);
      setDraft(toDraft(out));
      setSaved(true);
      setCheck(null);
      setFreshMark(null);
      onSaved(out);
    } catch (e) {
      setCheck(null);
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

  if (check) return <SaveCheck check={check} canWrite={canWrite} busy={busy} onBack={() => setCheck(null)} onSave={() => void save(check.rule)} />;

  const effective = draft.action === 'kill' && draft.dryRun ? 'kill → 알림만 (dry-run)' : draft.action;

  return (
    <div className="flex h-full flex-col" data-view="rule-editor">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-slate-100 px-5 py-2.5">
        <div className="flex rounded-md border border-slate-300 p-0.5 text-xs font-medium" role="group" aria-label="편집 방식">
          {MODES.map(([m, label]) => (
            <button
              key={m}
              type="button"
              data-mode={m}
              aria-pressed={mode === m}
              onClick={() => switchMode(m)}
              className={`rounded px-3 py-1 ${mode === m ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100'}`}
            >
              {label}
            </button>
          ))}
        </div>
        {mode === 'easy' ? (
          freshMark && <span className="text-xs text-emerald-700">예외 {freshMark.value} 를 더했습니다 — 확인 후 저장하세요</span>
        ) : (
          <span className="text-xs text-slate-500">
            적용 결과: <b className={draft.action === 'kill' && !draft.dryRun ? 'text-red-600' : 'text-amber-600'}>{effective}</b>
          </span>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
        {mode === 'easy' ? (
          <PolicyEasy draft={draft} onChange={change} isNew={isNew} enforceKill={enforceKill} fresh={freshMark} />
        ) : mode === 'yaml' ? (
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
                <select className={input} data-field="kind" value={draft.kind} onChange={(e) => update({ kind: e.target.value as Kind })}>
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
                  data-field={field}
                  value={draft.lists[field]}
                  onChange={(e) => updateList(field, e.target.value)}
                  placeholder="한 줄에 하나"
                />
              </Field>
            ))}
            {draft.kind === 'dns' && (
              <div className="grid grid-cols-2 gap-4">
                {NUM_FIELDS.map(({ field, label, max, hint }) => (
                  <Field key={field} label={label} hint={hint}>
                    <input className={input} type="number" min={1} max={max} inputMode="numeric" data-field={field} value={draft[field]} placeholder="비우면 보지 않음" onChange={(e) => update({ [field]: e.target.value })} />
                  </Field>
                ))}
              </div>
            )}
            <Field label="적용 컨테이너" hint="이름 또는 이미지 glob, 비우면 전체 (예: pkg-*)">
              <textarea
                className={`${input} min-h-14 font-mono text-xs`}
                data-field="containers"
                value={draft.lists.containers}
                onChange={(e) => updateList('containers', e.target.value)}
                placeholder="전체"
              />
            </Field>
            {draft.kind === 'connect' && (
              <Field label="도메인 조회 없는 IP 직접 연결" hint="directIp — trace_dns 가 켜져 있을 때만 판단, 비우면 옛 동작">
                <select className={input} data-field="directIp" value={draft.directIp} onChange={(e) => update({ directIp: e.target.value as DirectIp | '' })}>
                  <option value="">(비움)</option>
                  <option value="allow">allow — 통과</option>
                  <option value="alert">alert — 알림</option>
                  <option value="kill">kill — 격리</option>
                </select>
              </Field>
            )}
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={draft.disabled} onChange={(e) => update({ disabled: e.target.checked })} className="accent-indigo-600" />
              비활성화 (평가하지 않음)
            </label>
          </div>
        )}
      </div>

      {mode === 'easy' && (
        <p className="shrink-0 border-t border-slate-100 bg-indigo-50 px-5 py-2.5 text-sm font-medium text-slate-800" data-summary="">
          {summarize(draft)}
        </p>
      )}

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
          {!isNew && canWrite && (
            <button
              type="button"
              onClick={() => setAskDelete(true)}
              disabled={busy || readOnly}
              className="sg-btn text-danger hover:bg-danger-soft"
            >
              <Trash2 className="size-4" aria-hidden /> 삭제
            </button>
          )}
          <button
            type="button"
            onClick={() => void openCheck()}
            disabled={busy || readOnly}
            className="sg-btn sg-btn-primary"
          >
            저장 전 확인 <ArrowRight className="size-3.5" aria-hidden />
          </button>
        </div>
      </div>
      {askDelete && (
        <ConfirmDialog
          title="정책 삭제"
          target={rule.id}
          okLabel="삭제"
          effects={['엔진에서 바로 빠집니다 — 이 정책으로 걸리던 행동은 다음 이벤트부터 통과', '지난 감사 로그는 그대로 남습니다', '변경 이력에 「정책 편집」으로 남습니다']}
          undo="YAML 을 복사해 두었다면 「새 정책 › 고급 · YAML」로 다시 만들 수 있습니다"
          onCancel={() => setAskDelete(false)}
          onConfirm={() => {
            setAskDelete(false);
            void remove();
          }}
        />
      )}
    </div>
  );
}

// 저장 전 확인 — 요약 + 최근 감사 로그를 이 정책으로 다시 평가한 결과. 미리보기를 못 해도(옛 백엔드) 저장은 할 수 있다
function SaveCheck({
  check,
  canWrite,
  busy,
  onBack,
  onSave,
}: {
  check: { rule: Rule; preview: Preview | null; error: string };
  canWrite: boolean;
  busy: boolean;
  onBack: () => void;
  onSave: () => void;
}) {
  const pv = check.preview;
  const groups = pv ? Object.entries(pv.changed.reduce<Record<string, number>>((m, x) => ((m[`${x.before}>${x.after}`] = (m[`${x.before}>${x.after}`] ?? 0) + 1), m), {})) : [];
  return (
    <div className="flex h-full flex-col" data-view="rule-editor">
      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
        <section className="grid max-w-3xl gap-3 text-sm" data-part="save-check">
          <h3 className="text-base font-semibold text-slate-800">저장 전 확인</h3>
          <p className="rounded-md bg-indigo-50 px-3 py-2.5 font-medium text-slate-800" data-summary="">
            {summarize(toDraft(check.rule))}
          </p>
          {check.error ? (
            <p className="text-amber-700">미리보기를 계산하지 못했습니다 — {check.error}. 저장은 할 수 있습니다.</p>
          ) : !pv ? (
            <p className="text-slate-500">최근 감사 로그로 미리 계산하는 중…</p>
          ) : (
            <>
              <p data-preview-count="">
                최근 감사 로그 {fmtNum(pv.evaluated)}건을 이 정책으로 다시 평가 — 결과가 바뀌는 과거 위반 <b className="num">{fmtNum(pv.changed.length)}건</b>
              </p>
              {groups.length ? (
                <ul className="list-disc pl-5">
                  {groups.map(([k, n]) => {
                    const [b, a] = k.split('>') as [Level, Level];
                    return (
                      <li key={k}>
                        {LV[b] ?? b}에서 {LV_TO[a] ?? a} 바뀜 <b className="num">{n}건</b>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <p className="text-xs text-slate-500">과거 기록 중 결과가 바뀌는 것은 없습니다. 저장한 뒤 들어오는 행동부터 적용됩니다.</p>
              )}
              {pv.changed.length > 0 && (
                <table className="w-full text-xs">
                  <thead className="text-left text-slate-500">
                    <tr>
                      <th className="py-1 font-semibold">#</th>
                      <th className="py-1 font-semibold">컨테이너</th>
                      <th className="py-1 font-semibold">지금 → 저장 후</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pv.changed.slice(0, 20).map((r) => (
                      <tr key={r.auditId} className="border-t border-slate-100">
                        <td className="num py-1 text-slate-400">{r.auditId}</td>
                        <td className="py-1">{r.container}</td>
                        <td className="py-1">
                          {LV[r.before as Level] ?? r.before} → <b>{LV[r.after as Level] ?? r.after}</b>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
          <div className="flex items-center gap-3 pt-1">
            <button type="button" onClick={onBack} className="sg-btn text-text-2 hover:bg-surface-2">
              <ArrowLeft className="size-3.5" aria-hidden /> 고치기
            </button>
            {/* 조회자는 저장 버튼을 그리지 않는다(W16) — 미리보기는 조회자도 */}
            {canWrite ? (
              <button
                type="button"
                onClick={onSave}
                disabled={busy}
                className="sg-btn sg-btn-primary"
              >
                저장 후 적용 <Play className="size-3.5" aria-hidden />
              </button>
            ) : (
              <span className="text-xs text-slate-500">저장은 관리자만 할 수 있습니다</span>
            )}
          </div>
        </section>
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
