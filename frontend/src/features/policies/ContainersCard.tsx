import { X } from 'lucide-react';
import { useState } from 'react';
import { ActionButton, IconAction } from '../../components/ActionButton';
import { CONTAINERS_REQUIRED } from '../../components/PolicyEditor';
import { StatusPill } from '../../components/DataTable';
import { useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { classifyName, SANDBOX_SCOPE, type Scope } from '../../lib/policyEasy';
import type { Action, IntegrationContainer, IntegrationStatus } from '../../lib/types';
import { containerMatches } from './glob';

// 적용 컨테이너 카드(11/09 사용자 결정 「정책별 컨테이너 카드」): 정책 규칙의 기존 containers 칸(비면 모든 컨테이너)을 고른다.
//   범위 분절 모든 컨테이너 · 설치 검사(sg-install-*) · 지정 → 지정이면 실행 중 컨테이너(GET /api/integration 의 감시 목록)에서 고르거나 이름 패턴(Enter)
//   항목마다 「지금 일치 N개」 · 감시 여부 · (격리 정책이면) 격리 가능 / 격리 보류(격리 범위 밖 — 라벨 · ENFORCE_CONTAINERS 필요)
//   「지정」인데 0개면 저장을 막는다(그대로 저장하면 모든 컨테이너가 된다) — 막는 사유는 PolicyEditor CONTAINERS_REQUIRED
//   범위 단추가 꺼지면(11/09 G16) lockReason(시스템 규칙 · 고급 YAML)을 aria-disabled 사유로 — 초점은 가고 누름만 막힘. 사유 없는 조회자는 예전처럼 진짜 disabled
const SCOPES: [Scope, string, string][] = [
  ['all', '모든 컨테이너', '운영 중인 컨테이너와 설치 검사 모두'],
  ['sandbox', '설치 검사', '패키지를 시험 설치하는 감시 컨테이너'],
  ['some', '지정', '이름 · 이미지 패턴으로 고름'],
];

export function ContainersCard({
  scope,
  containers,
  onChange,
  action,
  dryRun,
  readOnly,
  note,
  lockReason,
}: {
  scope: Scope;
  containers: string[];
  onChange: (scope: Scope, containers: string[]) => void;
  action: Action;
  dryRun: boolean;
  readOnly?: boolean;
  note?: string;
  lockReason?: string;
}) {
  const live = useLoad(api.integration);
  const list = (live.data?.containers ?? []).filter((c) => !c.ignored);
  const [text, setText] = useState('');
  const [err, setErr] = useState('');
  const picked = scope === 'some' ? containers.filter((c) => c !== SANDBOX_SCOPE) : [];
  const kill = action === 'kill' && !dryRun;
  const pick = (s: Scope) => {
    if (readOnly || s === scope) return;
    onChange(s, s === 'all' ? [] : s === 'sandbox' ? [SANDBOX_SCOPE] : picked);
  };
  const add = (raw: string) => {
    const v = raw.trim();
    if (!v) return;
    if (!classifyName(v).type) {
      setErr('이름 패턴은 예: pkg-* 모양으로 입력하세요.');
      return;
    }
    setErr('');
    setText('');
    if (!picked.includes(v)) onChange('some', [...picked, v]);
  };
  const remove = (v: string) => onChange('some', picked.filter((x) => x !== v));
  const toggle = (name: string, on: boolean) => (on ? add(name) : remove(name));

  return (
    <section className="grid gap-3 text-sm" data-part="containers-card" aria-label="적용 컨테이너">
      <div>
        <h3 className="font-semibold text-text">적용 컨테이너</h3>
        <p className="text-xs text-text-3">이 정책으로 판정할 컨테이너(비우면 모든 컨테이너)</p>
      </div>
      <div className="grid grid-cols-3 gap-1 rounded-[var(--r-md)] border border-border p-1" role="group" aria-label="적용 범위">
        {SCOPES.map(([k, label, sub]) => (
          <ActionButton
            key={k}
            data-scope-pick={k}
            aria-pressed={scope === k}
            title={sub}
            reason={readOnly && lockReason}
            disabled={readOnly && !lockReason}
            onClick={() => pick(k)}
            className={`rounded-[var(--r-sm)] px-2 py-1.5 text-[13px] font-medium ${scope === k ? 'bg-accent-soft text-accent-text' : 'text-text-2 hover:bg-surface-2'} disabled:cursor-not-allowed aria-disabled:cursor-not-allowed`}
          >
            {label}
          </ActionButton>
        ))}
      </div>
      {note && <p className="rounded-[var(--r-sm)] bg-surface-2 px-3 py-2 text-xs text-text-2">{note}</p>}

      {scope !== 'some' ? (
        <Summary scope={scope} list={list} kill={kill} live={live} />
      ) : (
        <>
          {!readOnly && (
            <div className="grid gap-1.5">
              <b className="text-xs font-semibold text-text-2">실행 중 컨테이너에서 고르기</b>
              {live.error ? (
                <p className="text-xs text-text-3" data-part="running-error">
                  실행 중 컨테이너 목록을 불러오지 못했습니다. 이름 패턴으로 추가하세요.
                </p>
              ) : !live.data ? (
                <p className="text-xs text-text-3">불러오는 중…</p>
              ) : !list.length ? (
                <p className="text-xs text-text-3">실행 중인 컨테이너가 없습니다.</p>
              ) : (
                <ul className="grid max-h-44 gap-0.5 overflow-y-auto rounded-[var(--r-md)] border border-border p-1" data-part="running-list">
                  {list.map((c) => (
                    <li key={c.id}>
                      <label className="flex cursor-pointer items-center gap-2 rounded-[var(--r-sm)] px-2 py-1 hover:bg-surface-2">
                        <input type="checkbox" className="accent-[var(--accent)]" checked={picked.includes(c.name)} onChange={(e) => toggle(c.name, e.target.checked)} />
                        <span className="min-w-0 flex-1 truncate font-mono text-[13px]">{c.name}</span>
                        <small className="truncate text-xs text-text-3">{c.image}</small>
                      </label>
                    </li>
                  ))}
                </ul>
              )}
              <label className="grid gap-1">
                <span className="text-xs font-semibold text-text-2">이름 패턴</span>
                <input
                  className="h-9 rounded-[var(--r-md)] border border-[var(--field-line)] bg-field px-2.5 font-mono text-[13px]"
                  aria-label="이름 패턴"
                  placeholder="예: web-*"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      add(text);
                    }
                  }}
                />
              </label>
              {err && (
                <p role="alert" className="text-xs text-danger-text" data-part="pattern-error">
                  {err}
                </p>
              )}
            </div>
          )}
          {picked.length ? (
            <ul className="grid gap-2" data-part="entries">
              {picked.map((p) => (
                <Entry key={p} pattern={p} list={list} known={!!live.data} kill={kill} env={live.data?.env} readOnly={readOnly} onRemove={() => remove(p)} />
              ))}
            </ul>
          ) : (
            <p role="alert" className="rounded-[var(--r-sm)] bg-danger-soft px-3 py-2 text-[13px] text-danger-text" data-part="containers-error">
              {CONTAINERS_REQUIRED}.
            </p>
          )}
        </>
      )}
    </section>
  );
}

const count = (xs: IntegrationContainer[], f: (c: IntegrationContainer) => boolean) => xs.filter(f).length;

function Summary({ scope, list, kill, live }: { scope: Scope; list: IntegrationContainer[]; kill: boolean; live: { data?: IntegrationStatus; error?: unknown } }) {
  if (live.error || !live.data)
    return (
      <p className="text-xs text-text-3" data-part="scope-summary">
        {scope === 'all' ? '운영 중인 컨테이너와 설치 검사 컨테이너 모두에 적용합니다.' : `설치 검사 컨테이너(${SANDBOX_SCOPE})에만 적용합니다.`}
      </p>
    );
  const hit = scope === 'all' ? list : list.filter((c) => containerMatches(SANDBOX_SCOPE, c));
  const w = count(hit, (c) => c.watched);
  const e = count(hit, (c) => c.enforce);
  return (
    <div className="grid gap-1 rounded-[var(--r-md)] border border-border px-3 py-2.5" data-part="scope-summary">
      <b className="text-[13px] font-medium text-text">{scope === 'all' ? `지금 실행 중 ${hit.length}개 모두` : `${SANDBOX_SCOPE}(지금 일치 ${hit.length}개)`}</b>
      <span className="text-xs text-text-3">
        {scope === 'sandbox' ? '설치 검사 컨테이너는 늘 격리 범위입니다. 시험 설치를 시작하면 여기에 들어옵니다.' : `감시 ${w}개 · 격리 범위 ${e}개${kill && e < hit.length ? `, 격리 범위 밖 ${hit.length - e}개는 위반이면 알림만 남습니다.` : ''}`}
      </span>
    </div>
  );
}

function Entry({
  pattern,
  list,
  known,
  kill,
  env,
  readOnly,
  onRemove,
}: {
  pattern: string;
  list: IntegrationContainer[];
  known: boolean;
  kill: boolean;
  env?: IntegrationStatus['env'];
  readOnly?: boolean;
  onRemove: () => void;
}) {
  const hit = list.filter((c) => containerMatches(pattern, c));
  const n = hit.length;
  const w = count(hit, (c) => c.watched);
  const e = count(hit, (c) => c.enforce);
  const watch = !n ? null : w === n ? '감시 중' : w === 0 ? '감시 밖' : `감시 중 ${w}개 · 감시 밖 ${n - w}개`;
  const iso = !n || !kill ? null : e === n ? '격리 가능' : e === 0 ? '격리 보류' : `격리 가능 ${e}개 · 격리 보류 ${n - e}개`;
  return (
    <li className="grid gap-1 rounded-[var(--r-md)] border border-border px-3 py-2" data-entry={pattern}>
      <div className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-text" title={pattern}>
          {pattern}
        </span>
        {known && (
          <span className="num shrink-0 text-xs text-text-3" data-part="match-count">
            지금 일치 {n}개
          </span>
        )}
        {!readOnly && <IconAction icon={X} label="빼기" target={pattern} onClick={onRemove} />}
      </div>
      {known && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs text-text-3" data-part="entry-status">
          {n === 0 ? (
            <span>지금 실행 중인 컨테이너 중 일치 없음, 이후 뜨는 컨테이너에 적용</span>
          ) : (
            <>
              <StatusPill tone={w === n ? 'ok' : 'neutral'}>{watch}</StatusPill>
              {iso && <StatusPill tone={e === n ? 'ok' : 'warn'}>{iso}</StatusPill>}
            </>
          )}
        </div>
      )}
      {known && kill && n > 0 && e < n && (
        <p className="text-xs text-text-3" data-part="hold-hint">
          격리 범위 밖이라 위반이면 알림만 남습니다. 라벨 {env?.labelEnforce ?? 'supplyguard.enforce'}=true 를 붙이면 격리됩니다.
        </p>
      )}
    </li>
  );
}
