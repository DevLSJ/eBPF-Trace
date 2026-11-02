import { FileCode, Lock, Plus } from 'lucide-react';
import { startTransition, useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DecisionBadge, ScopeChip } from '../../components/Badges';
import { KindBadge } from '../../components/KindBadge';
import { ConfirmDialog } from '../../components/Modal';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { PolicyEditor } from '../../components/PolicyEditor';
import { useCases } from '../../hooks/cases-context';
import { useStream } from '../../hooks/stream-context';
import { useAuth } from '../../hooks/auth-context';
import { useFilters } from '../../hooks/useFilters';
import { useLoad } from '../../hooks/useLoad';
import { api, errorText } from '../../lib/api';
import { fmtTime } from '../../lib/format';
import { actionLabel, fromTemplate, KIND_SHORT, KIND_TEXT, ruleFromBlock, ruleWithAllow, TEMPLATES } from '../../lib/policyEasy';
import { caseLabel, KINDS, SYSTEM_RULES, type Kind } from '../../lib/types';
import { mergeDefault } from '../../lib/policyDefaults';
import { BlocklistPanel, ChangesPanel } from './BlocklistPanels';
import { DefaultsBanner } from './DefaultsBanner';
import { changeText } from '../../lib/proposal';
import { ProposalDetail } from './ProposalDetail';

const NEW = '__new__';
const BULK = '__yaml__';

// 정책 — 질문 하나: 「이 변경을 적용하면 무엇이 달라지나?」 맨 위는 판정에서 나온 「제안된 변경」
export function PoliciesPage() {
  const { info } = useStream();
  const { cases, reload: reloadCases } = useCases();
  const [params, setParams] = useSearchParams();
  const { isAdmin } = useAuth();
  const selected = params.get('id') ?? '';
  const proposalId = params.get('proposal') ?? '';
  // 미리 채우기(tpl · intent · kind · value · default)는 화면 상태로만 — 주소에는 id · proposal 만(10/21)
  const [prefill, setPrefill] = useFilters('/policies');
  // 새 기본 규칙 「미리보기 후 추가」(10/20 F) — default=<id> 면 그 규칙(바뀐 규칙은 빠진 값만 더한 사본)으로 바로 저장 전 확인
  const defaultId = prefill.default;

  const rules = useLoad(api.listRules);
  const loadDrafts = useCallback(() => api.proposals(), []);
  const proposals = useLoad(loadDrafts);
  const blocklist = useLoad(api.blocklist);
  const loadChanges = useCallback(() => api.changes(50), []);
  const changes = useLoad(loadChanges);
  const defaults = useLoad(api.policyDefaults);

  const drafts = (proposals.data ?? []).filter((p) => p.state === 'draft');
  // 조회자는 쓰기 버튼을 그리지 않는다(W16) — 서버 설정 보기는 「설정」 화면으로 옮겼다
  const canWrite = isAdmin;

  const select = useCallback(
    (p: Record<string, string>) => {
      const { tpl = '', intent = '', kind = '', value = '', default: def = '', ...link } = p;
      // 주소 변경(라우터는 transition 으로 그린다)과 한 번에 그린다 — 따로 그리면 「아무것도 안 고름」 순간에 첫 정책 자동 선택이 끼어든다
      startTransition(() => setPrefill({ tpl, intent, kind, value, default: def }));
      setParams(link, { replace: true });
    },
    [setParams, setPrefill],
  );

  // 아무것도 고르지 않았으면: 제안이 있으면 첫 제안, 없으면 첫 정책 (URL 에 남긴다)
  const firstDraft = drafts[0]?.id;
  const firstRule = rules.data?.[0]?.id;
  const proposalsSettled = proposals.data !== undefined || !!proposals.error;
  useEffect(() => {
    if (selected || proposalId || defaultId || !proposalsSettled) return;
    if (firstDraft) select({ proposal: firstDraft });
    else if (firstRule) select({ id: firstRule });
  }, [selected, proposalId, defaultId, proposalsSettled, firstDraft, firstRule, select]);

  const refreshAll = () => {
    rules.reload();
    proposals.reload();
    blocklist.reload();
    changes.reload();
    defaults.reload();
    reloadCases();
  };

  const current = rules.data?.find((r) => r.id === selected);
  const proposal = proposals.data?.find((p) => p.id === proposalId);
  const existingIds = (rules.data ?? []).map((r) => r.id);

  // 새 정책의 시작점(10/16): tpl=<템플릿> 또는 이벤트 · 감사 행의 intent=block · kind · value. 기존 정책에 intent=allow · value = 예외 추가
  const { tpl, intent, value: intentValue } = prefill;
  const intentKind = (prefill.kind || null) as Kind | null;
  // PolicyEditor 는 rule 을 처음 그릴 때만 읽는다(key 가 바뀌면 새로) — 매 렌더 새로 만들어도 편집 중인 값은 그대로
  const pendingDefault = defaultId
    ? (() => {
        const d = defaults.data;
        const miss = d?.missing?.find((r) => r.id === defaultId);
        if (miss) return { rule: miss, isNew: true, title: `새 기본 규칙 · ${miss.id}` };
        const diff = d?.differs?.find((x) => x.id === defaultId);
        const cur = rules.data?.find((r) => r.id === defaultId);
        if (diff && cur) return { rule: mergeDefault(cur, diff.default), isNew: false, title: `바뀐 기본 규칙 · ${diff.id} — 빠진 값만 더함` };
        return null;
      })()
    : null;
  const start = (() => {
    if (pendingDefault) return { rule: pendingDefault.rule, fresh: null };
    if (selected === NEW) {
      if (intent === 'block' && intentKind && KINDS.includes(intentKind) && intentValue) return { rule: ruleFromBlock(intentKind, intentValue, existingIds), fresh: null };
      if (tpl) return { rule: fromTemplate(tpl, existingIds), fresh: null };
      return null;
    }
    if (current && intent === 'allow' && intentValue) return ruleWithAllow(current, intentValue);
    return current ? { rule: current, fresh: null } : null;
  })();

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <DefaultsBanner
        data={defaults.error ? undefined : defaults.data}
        canWrite={canWrite}
        onPreview={(x) => select(x.kind === 'differs' ? { id: x.id, default: x.id } : { default: x.id })}
      />
      {/* 768 미만(10/30): 1열로 쌓고 화면 안에서 스크롤 */}
      <div className="grid min-h-0 flex-1 gap-4 max-md:content-start max-md:overflow-y-auto md:grid-cols-[21rem_minmax(0,1fr)]">

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
                {canWrite && (
                  <button
                    type="button"
                    onClick={() => select({ id: NEW })}
                    className="flex items-center gap-1 rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
                  >
                    <Plus className="size-3.5" aria-hidden /> 새 정책
                  </button>
                )}
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

        <div className="grid min-h-0 gap-4 md:grid-rows-[minmax(0,1fr)_13rem]">
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
                pendingDefault
                  ? pendingDefault.title
                  : selected === NEW
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
                <BulkYaml canWrite={canWrite} ruleCount={(rules.data ?? []).filter((r) => !SYSTEM_RULES.has(r.id)).length} onApplied={refreshAll} />
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
                      key={`${selected}|${tpl}|${intent}|${intentValue}|${pendingDefault ? defaultId : ''}`}
                      rule={start.rule}
                      isNew={pendingDefault ? pendingDefault.isNew : selected === NEW}
                      autoCheck={!!pendingDefault}
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
          <div className="grid min-h-0 grid-cols-2 gap-4 max-md:h-52">
            <BlocklistPanel data={blocklist.data} error={blocklist.error} canWrite={canWrite} onChanged={refreshAll} />
            <ChangesPanel data={changes.data} error={changes.error} />
          </div>
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

// 전체 교체: PUT /api/policies (YAML 원클릭 적용)
function BulkYaml({ canWrite, ruleCount, onApplied }: { canWrite: boolean; ruleCount: number; onApplied: () => void }) {
  const [text, setText] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [ask, setAsk] = useState(false);

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
          readOnly={!canWrite}
          aria-label="전체 정책 YAML"
        />
      </div>
      <div className="flex shrink-0 items-center gap-3 border-t border-slate-100 px-5 py-3">
        {msg && <span className={`min-w-0 flex-1 truncate text-sm ${msg.ok ? 'text-emerald-600' : 'text-red-600'}`}>{msg.text}</span>}
        {!canWrite && <span className="text-xs text-slate-500">읽기 전용 — 전체 교체는 관리자만 합니다</span>}
        {canWrite && (
          <button
            type="button"
            onClick={() => setAsk(true)}
            disabled={busy || text === null}
            className="ml-auto rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-40"
          >
            전체 교체 후 적용 ▶
          </button>
        )}
      </div>
      {ask && (
        <ConfirmDialog
          title="전체 정책 교체"
          target="YAML 의 정책 전체"
          okLabel="교체 후 적용"
          effects={[
            `지금 정책 ${ruleCount}개를 YAML 의 내용으로 모두 바꿉니다(시스템 규칙 blocklist-hosts 는 그대로)`,
            'YAML 에 없는 정책은 지워집니다',
            '엔진에 바로 적용 · 변경 이력에 남습니다',
          ]}
          undo="바꾸기 전 YAML 을 복사해 두면 같은 화면에서 다시 교체할 수 있습니다"
          onCancel={() => setAsk(false)}
          onConfirm={() => {
            setAsk(false);
            void apply();
          }}
        />
      )}
    </div>
  );
}

