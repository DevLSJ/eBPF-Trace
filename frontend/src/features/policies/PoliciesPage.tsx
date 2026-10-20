import { FileCode, KeyRound, Lock, Plus, Settings } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DecisionBadge, ScopeChip } from '../../components/Badges';
import { ConfirmButton } from '../../components/ConfirmButton';
import { KindBadge } from '../../components/KindBadge';
import { PageActions } from '../../components/PageActions';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { PolicyEditor } from '../../components/PolicyEditor';
import { useCases } from '../../hooks/cases-context';
import { useStream } from '../../hooks/stream-context';
import { useAdminToken, useLoad } from '../../hooks/useLoad';
import { api, errorText } from '../../lib/api';
import { fmtTime } from '../../lib/format';
import { actionLabel, fromTemplate, KIND_SHORT, KIND_TEXT, ruleFromBlock, ruleWithAllow, TEMPLATES } from '../../lib/policyEasy';
import { caseLabel, KINDS, SYSTEM_RULES, type Info, type Kind } from '../../lib/types';
import { BlocklistPanel, ChangesPanel } from './BlocklistPanels';
import { changeText } from '../../lib/proposal';
import { ProposalDetail } from './ProposalDetail';

const NEW = '__new__';
const BULK = '__yaml__';

// 정책 — 질문 하나: 「이 변경을 적용하면 무엇이 달라지나?」 맨 위는 판정에서 나온 「제안된 변경」
export function PoliciesPage() {
  const { info } = useStream();
  const { cases, reload: reloadCases } = useCases();
  const [params, setParams] = useSearchParams();
  const [token, setToken] = useAdminToken();
  const selected = params.get('id') ?? '';
  const proposalId = params.get('proposal') ?? '';

  const rules = useLoad(api.listRules);
  const loadDrafts = useCallback(() => api.proposals(), []);
  const proposals = useLoad(loadDrafts);
  const blocklist = useLoad(api.blocklist);
  const loadChanges = useCallback(() => api.changes(50), []);
  const changes = useLoad(loadChanges);

  const drafts = (proposals.data ?? []).filter((p) => p.state === 'draft');
  const canWrite = !info?.authRequired || token !== '';

  const select = useCallback((p: Record<string, string>) => setParams(p, { replace: true }), [setParams]);

  // 아무것도 고르지 않았으면: 제안이 있으면 첫 제안, 없으면 첫 정책 (URL 에 남긴다)
  const firstDraft = drafts[0]?.id;
  const firstRule = rules.data?.[0]?.id;
  const proposalsSettled = proposals.data !== undefined || !!proposals.error;
  useEffect(() => {
    if (selected || proposalId || !proposalsSettled) return;
    if (firstDraft) select({ proposal: firstDraft });
    else if (firstRule) select({ id: firstRule });
  }, [selected, proposalId, proposalsSettled, firstDraft, firstRule, select]);

  const refreshAll = () => {
    rules.reload();
    proposals.reload();
    blocklist.reload();
    changes.reload();
    reloadCases();
  };

  const current = rules.data?.find((r) => r.id === selected);
  const proposal = proposals.data?.find((p) => p.id === proposalId);
  const existingIds = (rules.data ?? []).map((r) => r.id);

  // 새 정책의 시작점(10/16): ?tpl=<템플릿> 또는 이벤트 · 감사 행의 ?intent=block&kind&value. 기존 정책에 ?intent=allow&value = 예외 추가
  const tpl = params.get('tpl') ?? '';
  const intent = params.get('intent') ?? '';
  const intentKind = params.get('kind') as Kind | null;
  const intentValue = params.get('value') ?? '';
  // PolicyEditor 는 rule 을 처음 그릴 때만 읽는다(key 가 바뀌면 새로) — 매 렌더 새로 만들어도 편집 중인 값은 그대로
  const start = (() => {
    if (selected === NEW) {
      if (intent === 'block' && intentKind && KINDS.includes(intentKind) && intentValue) return { rule: ruleFromBlock(intentKind, intentValue, existingIds), fresh: null };
      if (tpl) return { rule: fromTemplate(tpl, existingIds), fresh: null };
      return null;
    }
    if (current && intent === 'allow' && intentValue) return ruleWithAllow(current, intentValue);
    return current ? { rule: current, fresh: null } : null;
  })();
  const [ssOpen, setSsOpen] = useState(false);

  return (
    <div className="grid h-full min-h-0 grid-cols-[21rem_minmax(0,1fr)] gap-4">
      <PageActions>
        <span className="relative">
          <button
            type="button"
            data-server-settings=""
            aria-expanded={ssOpen}
            onClick={() => setSsOpen((o) => !o)}
            className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-slate-600 hover:bg-slate-100"
          >
            <Settings className="size-3.5" aria-hidden /> 서버 설정 · 자동 격리 {info?.enforceKill === false ? '꺼짐' : '켜짐'}
          </button>
          {ssOpen && info && <ServerSettings info={info} onClose={() => setSsOpen(false)} />}
        </span>
        {info?.authRequired ? (
          <label className="flex items-center gap-2 text-xs text-slate-500">
            <KeyRound className="size-4 shrink-0" aria-hidden />
            관리자 토큰
            <input
              type="password"
              autoComplete="off"
              placeholder="변경 · 판정 시 필요"
              className="h-8 w-56 rounded-md border border-slate-300 px-2 text-sm focus:border-indigo-500 focus:outline-none"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          </label>
        ) : (
          <span className="text-xs text-slate-400">쓰기 토큰 불필요 (mock 소스)</span>
        )}
      </PageActions>

      <div className="flex min-h-0 flex-col gap-4">
        <Panel
          className="max-h-[45%] shrink-0"
          testId="proposals"
          title={
            <span>
              제안된 변경 <span className="num ml-1 font-normal text-slate-400">{drafts.length}</span>
            </span>
          }
        >
          {proposals.error && !proposals.data ? (
            <LoadError error={proposals.error} what="제안" compact />
          ) : drafts.length === 0 ? (
            <p className="px-4 py-3 text-xs text-slate-400">적용 대기 제안 없음 — 설치 검사 · 토폴로지에서 판정하면 여기에 생깁니다</p>
          ) : (
            <ul className="h-full overflow-y-auto">
              {drafts.map((p) => {
                const c = cases?.find((x) => x.id === p.caseId);
                return (
                  <li key={p.id}>
                    <button
                      type="button"
                      data-proposal={p.id}
                      onClick={() => select({ proposal: p.id })}
                      className={`grid w-full gap-1 border-b border-slate-100 px-4 py-2.5 text-left text-sm hover:bg-slate-50 ${p.id === proposalId ? 'bg-indigo-50' : ''}`}
                    >
                      <span className="flex items-center gap-2">
                        <DecisionBadge decision={p.decision} />
                        <span className="min-w-0 flex-1 truncate font-mono text-slate-800">{c ? caseLabel(c) : p.caseId}</span>
                        <span className="num text-xs text-slate-400">{fmtTime(p.createdAt)}</span>
                      </span>
                      <span className="truncate text-xs text-slate-500">{p.changes.map(changeText).join(' · ')}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>

        <Panel
          className="min-h-0 flex-1"
          testId="rules"
          title={`정책 ${rules.data ? rules.data.length : ''}`}
          actions={
            <div className="flex gap-1">
              <button
                type="button"
                onClick={() => select({ id: BULK })}
                className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-600 hover:bg-slate-100"
                title="전체 정책을 YAML로 보기·일괄 적용"
              >
                <FileCode className="size-3.5" aria-hidden /> YAML
              </button>
              <button
                type="button"
                onClick={() => select({ id: NEW })}
                className="flex items-center gap-1 rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
              >
                <Plus className="size-3.5" aria-hidden /> 새 정책
              </button>
            </div>
          }
        >
          <div className="flex h-full flex-col">
            {!!rules.error && <p className="p-4 text-sm text-red-600">불러오기 실패: {errorText(rules.error)}</p>}
            {rules.data?.length === 0 && <Empty>정책 없음</Empty>}
            <ul className="min-h-0 flex-1 overflow-y-auto">
              {rules.data?.map((r) => (
                <li key={r.id}>
                  <button
                    type="button"
                    data-rule={r.id}
                    onClick={() => select({ id: r.id })}
                    className={`flex w-full items-center gap-2 border-b border-slate-100 px-4 py-2.5 text-left text-sm hover:bg-slate-50 ${r.id === selected ? 'bg-indigo-50' : ''}`}
                  >
                    <span
                      className={`size-2 shrink-0 rounded-full ${r.disabled ? 'border border-slate-400' : 'bg-emerald-500'}`}
                      title={r.disabled ? '비활성' : '활성'}
                    />
                    {/* 쉬운 말 우선: 설명(없으면 이름) + 영문 이름은 작게 (10/16) */}
                    <span className={`grid min-w-0 flex-1 ${r.disabled ? 'text-slate-400' : 'text-slate-800'}`} title={r.description || r.id}>
                      <span className="truncate font-medium">{r.description || r.id}</span>
                      <small className="truncate font-mono text-[11px] text-slate-400">{r.id}</small>
                    </span>
                    {SYSTEM_RULES.has(r.id) ? (
                      <span className="flex shrink-0 items-center gap-1 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600" data-system>
                        <Lock className="size-3" aria-hidden /> 차단 목록
                      </span>
                    ) : (
                      <ScopeChip rule={r} />
                    )}
                    <span
                      className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                        r.action === 'kill' && !r.dryRun ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-800'
                      }`}
                    >
                      {actionLabel(r)}
                    </span>
                    <KindBadge kind={r.kind} label={KIND_SHORT[r.kind]} />
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </Panel>
      </div>

      <div className="grid min-h-0 grid-rows-[minmax(0,1fr)_13rem] gap-4">
        {proposalId ? (
          <ProposalDetail
            key={proposalId}
            proposal={proposal}
            loading={!proposals.data && !proposals.error}
            error={proposals.error}
            canWrite={canWrite}
            onDone={refreshAll}
          />
        ) : (
          <Panel
            className="min-h-0"
            testId="editor"
            title={
              selected === NEW
                ? start
                  ? `새 정책 · ${start.rule.description || start.rule.id}`
                  : '새 정책 · 무엇을 하고 싶나요?'
                : selected === BULK
                  ? '전체 정책 YAML'
                  : current
                    ? `정책 편집 · ${current.id}${start?.fresh ? ' — 예외 추가' : ''}`
                    : '정책 편집'
            }
          >
            {selected === BULK ? (
              <BulkYaml canWrite={canWrite} onApplied={refreshAll} />
            ) : selected === NEW && !start ? (
              <Templates onPick={(key) => select({ id: NEW, tpl: key })} />
            ) : start ? (
              <div className="flex h-full flex-col">
                {current && SYSTEM_RULES.has(current.id) && (
                  <p className="flex shrink-0 items-center gap-2 border-b border-slate-100 bg-slate-50 px-5 py-2 text-xs text-slate-600" data-testid="system-rule">
                    <Lock className="size-3.5" aria-hidden /> 시스템 규칙 — 차단 목록(도메인)에서 관리합니다. 여기서 직접 편집할 수 없습니다.
                  </p>
                )}
                <div className="min-h-0 flex-1">
                  <PolicyEditor
                    key={`${selected}|${tpl}|${intent}|${intentValue}`}
                    rule={start.rule}
                    isNew={selected === NEW}
                    canWrite={canWrite}
                    readOnly={!!current && SYSTEM_RULES.has(current.id)}
                    enforceKill={info?.enforceKill !== false}
                    existingIds={existingIds}
                    fresh={start.fresh}
                    onSaved={(r) => {
                      refreshAll();
                      select({ id: r.id });
                    }}
                    onDeleted={() => {
                      refreshAll();
                      select({});
                    }}
                  />
                </div>
              </div>
            ) : (
              <Empty>왼쪽에서 정책을 고르거나 새 정책을 만드세요</Empty>
            )}
          </Panel>
        )}
        <div className="grid min-h-0 grid-cols-2 gap-4">
          <BlocklistPanel data={blocklist.data} error={blocklist.error} canWrite={canWrite} onChanged={refreshAll} />
          <ChangesPanel data={changes.data} error={changes.error} />
        </div>
      </div>
    </div>
  );
}

// 새 정책 — 목적별 템플릿에서 시작(10/16)
function Templates({ onPick }: { onPick: (key: string) => void }) {
  return (
    <div className="h-full overflow-y-auto px-5 py-4" data-view="templates">
      <p className="text-sm text-slate-500">무엇을 막고 싶은지 고르면 값이 채워진 채로 시작합니다. 저장 전에 모두 고칠 수 있습니다.</p>
      <div className="mt-3 grid grid-cols-[repeat(auto-fill,minmax(14rem,1fr))] gap-3">
        {TEMPLATES.map((t) => (
          <button
            key={t.key}
            type="button"
            data-template={t.key}
            onClick={() => onPick(t.key)}
            className={`grid gap-1 rounded-lg border p-3.5 text-left hover:border-indigo-500 hover:bg-indigo-50 ${t.key === 'blank' ? 'border-dashed border-slate-300' : 'border-slate-200'}`}
          >
            <span className="justify-self-start rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-500">{KIND_TEXT[t.rule.kind][0]}</span>
            <b className="text-sm font-semibold text-slate-800">{t.title}</b>
            <small className="text-xs text-slate-500">{t.desc}</small>
          </button>
        ))}
      </div>
    </div>
  );
}

// 서버 설정 — 보기만. 바꾸는 방법은 서버 .env + 재시작 (10/16 확정: 화면에서 바꾸지 않는다 — 범위를 잘못 넓히면 다른 컨테이너가 격리된다)
function ServerSettings({ info, onClose }: { info: Info; onClose: () => void }) {
  const watch = info.watchContainers ?? [];
  const ignore = info.ignoreContainers ?? [];
  const rows: [string, string, string, string][] = [
    ['자동 격리', info.enforceKill ? '켜짐' : '꺼짐 (알림만)', 'ENFORCE_KILL', info.enforceKill ? '「즉시 격리」 정책에 걸리면 컨테이너를 멈춥니다' : '모든 정책이 알림만 보냅니다'],
    ['감시 범위', watch.length ? watch.join(', ') : '모든 컨테이너', 'WATCH_CONTAINERS', '이 범위의 컨테이너만 평가 · 격리합니다'],
    ['제외', ignore.length ? ignore.join(', ') : '없음', 'IGNORE_CONTAINERS', 'SupplyGuard 자신처럼 보지 않을 컨테이너'],
  ];
  return (
    <div className="absolute top-9 left-0 z-30 grid w-[28rem] gap-2 rounded-lg border border-slate-200 bg-white p-4 text-left shadow-xl" data-part="server-settings" role="dialog" aria-label="서버 설정">
      <div className="flex items-center justify-between">
        <b className="text-sm text-slate-800">서버 설정</b>
        <button type="button" onClick={onClose} aria-label="닫기" className="rounded px-1.5 text-slate-400 hover:bg-slate-100">
          ✕
        </button>
      </div>
      {rows.map(([label, value, env, desc]) => (
        <div key={env} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-t border-slate-100 pt-2">
          <div>
            <b className="text-sm font-medium text-slate-800">{label}</b>
            <div className="text-xs text-slate-500">{desc}</div>
          </div>
          <div className="grid justify-items-end gap-0.5">
            <span className="text-sm font-semibold text-slate-800">{value}</span>
            <code className="text-[11px] text-slate-500">{env}</code>
          </div>
        </div>
      ))}
      <p className="border-t border-slate-100 pt-2 text-xs text-slate-500">
        바꾸는 방법: 서버의 .env 에서 위 값을 고친 뒤 백엔드를 다시 시작하세요. 화면에서는 바꾸지 않습니다 — 범위를 잘못 넓히면 다른 컨테이너가 격리될 수 있습니다.
      </p>
    </div>
  );
}

// 전체 교체: PUT /api/policies (YAML 원클릭 적용)
function BulkYaml({ canWrite, onApplied }: { canWrite: boolean; onApplied: () => void }) {
  const [text, setText] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .exportYaml()
      .then(setText)
      .catch((e: Error) => setMsg({ ok: false, text: e.message }));
  }, []);

  const apply = async () => {
    if (text === null) return;
    setBusy(true);
    try {
      const rs = await api.applyYaml(text);
      onApplied();
      setMsg({ ok: true, text: `${rs.length}개 정책을 엔진에 적용함` });
    } catch (e) {
      setMsg({ ok: false, text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="min-h-0 flex-1 p-4">
        <textarea
          className="h-full w-full rounded-md border border-slate-300 p-3 font-mono text-xs leading-relaxed focus:border-indigo-500 focus:outline-none"
          value={text ?? '불러오는 중…'}
          disabled={text === null}
          spellCheck={false}
          onChange={(e) => setText(e.target.value)}
          aria-label="전체 정책 YAML"
        />
      </div>
      <div className="flex shrink-0 items-center gap-3 border-t border-slate-100 px-5 py-3">
        {msg && <span className={`min-w-0 flex-1 truncate text-sm ${msg.ok ? 'text-emerald-600' : 'text-red-600'}`}>{msg.text}</span>}
        <ConfirmButton
          onConfirm={apply}
          confirmLabel="기존 정책을 모두 교체 — 확정"
          disabled={busy || !canWrite || text === null}
          className="ml-auto rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-40"
        >
          전체 교체 후 적용 ▶
        </ConfirmButton>
      </div>
    </div>
  );
}

