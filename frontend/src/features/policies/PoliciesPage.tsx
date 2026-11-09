import { FileCode, Plus } from 'lucide-react';
import { startTransition, useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DecisionBadge } from '../../components/Badges';
import { GridCells, SortHead, StatusPill, TablePager, TableScroll } from '../../components/DataTable';
import { KindBadge } from '../../components/KindBadge';
import { fmtStatus } from '../../components/list/cell-format';
import { TimeText, TwoLine } from '../../components/list/cells';
import { downloadCSV } from '../../components/list/csv';
import { rowKeys, rowState, useBusy } from '../../components/list/hooks';
import { EmptyState, ListError, NoResults, PagerSlot, Skeleton } from '../../components/list/ListStates';
import { FilterBar, SearchField } from '../../components/list/SearchField';
import { PageActions } from '../../components/PageActions';
import { LoadError } from '../../components/Panel';
import { ScreenNote } from '../../components/ScreenNote';
import { Select } from '../../components/Select';
import { Sheet } from '../../components/Sheet';
import { sheetNav } from '../../components/sheet-nav';
import { TableToolbar } from '../../components/TableToolbar';
import { useAuth } from '../../hooks/auth-context';
import { useCases } from '../../hooks/cases-context';
import { useStream } from '../../hooks/stream-context';
import { useToast } from '../../hooks/toast-context';
import { useFilters } from '../../hooks/useFilters';
import { useListQuery } from '../../hooks/useListQuery';
import { useLoad } from '../../hooks/useLoad';
import { COL_W, useTableKit, type Column } from '../../hooks/useTableKit';
import { api } from '../../lib/api';
import { FIELD } from '../../lib/fieldNames';
import { mergeDefault } from '../../lib/policyDefaults';
import { fromTemplate, KIND_SHORT, ruleFromBlock, ruleWithAllow } from '../../lib/policyEasy';
import { screenCopy } from '../../lib/screenCopy';
import { caseLabel, KINDS, stripView, SYSTEM_RULES, type Kind, type PolicyView, type Rule } from '../../lib/types';
import { BulkYamlModal } from './BulkYamlModal';
import { CreatePolicyModal, type CreateStart } from './CreatePolicyModal';
import { DefaultsBanner } from './DefaultsBanner';
import { ActionPill, ContainerChips, SystemMark } from './PolicyBadges';
import { ACT_OPTIONS, actMatches, condSummary, containersText, originOf, SCOPE_OPTIONS, scopeFromList, STATUS, statusOf } from './policyRow';
import { PolicySheet, SHEET_TABS } from './PolicySheet';
import { ProposalDetail } from './ProposalDetail';

// 정책 목록(11/09 사용자 결정 — 「정책」 아래 정책 · 차단 목록 · 변경 이력 세 페이지): 머리 「정책 생성」(주) · 「YAML 일괄 적용」(보조)
//   띠: 판정 제안(적용 대기 → 누르면 제안 시트 ?proposal=) · 새 기본 규칙
//   거르기: 검색(정책 ID · 설명) · 종류 · 판정(사용 안 함 포함) · 적용 범위 — 화면 상태(10/21 결정 유지 · 새로고침하면 기본값)
//   표: 상태 맨 앞 · 정책(설명 위 · ID 아래) · 종류 · 판정 · 적용 컨테이너 · 마지막 위반(감사 로그) · 마지막 수정(updatedAt), 숨김 = 조건 요약 · 출처 · 처리자
//   행 → 정책 시트(?id=<정책>&tab=) · 옛 주소 ?id=__new__(생성 창) · ?id=__yaml__(YAML 일괄 적용) · ?proposal=<제안> 은 그대로 열린다
export const NEW = '__new__';
export const BULK = '__yaml__';
const FILTERS = { q: '', rkind: '', act: '', scope: '' };
const KIND_OPTIONS = (['open', 'exec', 'connect', 'dns', 'sequence'] as const).map((k) => ({ value: k, label: KIND_SHORT[k] }));

type Row = PolicyView & { lastHit?: string };

// 마지막 위반 — 감사 로그 최근 500건에서 정책마다 첫 기록, 그 안에 없고 기록이 더 있으면 그 정책만 한 건씩 더 묻는다
async function lastHits(ids: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const pg = await api.auditPage({ offset: 0, limit: 500 });
  const items = Array.isArray(pg) ? pg : pg.items;
  for (const a of items) if (a.ruleId && !out.has(a.ruleId)) out.set(a.ruleId, a.event.timestamp);
  const more = !Array.isArray(pg) && pg.total > items.length;
  if (more) {
    const rest = ids.filter((id) => !out.has(id));
    const got = await Promise.allSettled(rest.map((rule) => api.auditPage({ rule, offset: 0, limit: 1 })));
    got.forEach((g, i) => {
      const x = g.status === 'fulfilled' ? (Array.isArray(g.value) ? g.value[0] : g.value.items[0]) : undefined;
      if (x) out.set(rest[i], x.event.timestamp);
    });
  }
  return out;
}

export function PoliciesPage() {
  const { info } = useStream();
  const { cases, reload: reloadCases } = useCases();
  const { isAdmin } = useAuth();
  const toast = useToast();
  // 조회자는 쓰기 단추를 그리지 않는다(W16)
  const canWrite = isAdmin;
  const lq = useListQuery({
    filters: FILTERS,
    validate: { rkind: (v) => KIND_OPTIONS.some((o) => o.value === v), act: (v) => ACT_OPTIONS.some((o) => o.value === v), scope: (v) => SCOPE_OPTIONS.some((o) => o.value === v) },
    tabs: SHEET_TABS,
  });
  const [params, setParams] = useSearchParams();
  // 미리 채우기(tpl · intent · kind · value · default)는 화면 상태로만 — 주소에는 id · proposal · tab 만(10/21)
  const [prefill, setPrefill] = useFilters('/policies');
  const proposalId = params.get('proposal') ?? '';
  const sel = lq.id ?? '';

  const rules = useLoad(api.listRules);
  const loadDrafts = useCallback(() => api.proposals(), []);
  const proposals = useLoad(loadDrafts);
  const defaults = useLoad(api.policyDefaults);
  const idsKey = (rules.data ?? []).map((r) => r.id).join('\n');
  const loadHits = useCallback(() => lastHits(idsKey ? idsKey.split('\n') : []), [idsKey]);
  const hits = useLoad(rules.data ? loadHits : null);
  const busy = useBusy(rules.loading && !!rules.data);

  const drafts = (proposals.data ?? []).filter((p) => p.state === 'draft');
  const existingIds = (rules.data ?? []).map((r) => r.id);
  const clearPrefill = useCallback(() => setPrefill({ tpl: '', intent: '', kind: '', value: '', default: '' }), [setPrefill]);

  // 주소의 링크용 값(id · tab · proposal)을 한 번에 바꾼다
  const go = useCallback(
    (next: Partial<Record<'id' | 'tab' | 'proposal', string | null>>) =>
      setParams(
        (p) => {
          const n = new URLSearchParams(p);
          for (const [k, v] of Object.entries(next)) if (v) n.set(k, v);
          else n.delete(k);
          return n;
        },
        { replace: true },
      ),
    [setParams],
  );
  const refreshAll = () => {
    rules.reload();
    proposals.reload();
    defaults.reload();
    hits.reload();
    reloadCases();
  };

  // ── 표 ──
  const columns = useMemo<Column<Row>[]>(
    () => [
      {
        key: 'status',
        label: '상태',
        width: COL_W.status,
        sort: (r) => STATUS[statusOf(r)].order,
        cell: (r) => {
          const s = STATUS[statusOf(r)];
          return (
            <StatusPill tone={s.tone} data-status={statusOf(r)}>
              {s.label}
            </StatusPill>
          );
        },
        csv: (r) => STATUS[statusOf(r)].label,
      },
      {
        key: 'policy',
        label: '정책',
        fill: true,
        sort: (r) => r.id,
        // 좁은 화면에서도 정책 이름이 읽히게 최소 11rem — 넘치면 표가 가로로 밀린다
        cell: (r) => (
          <span className="block min-w-[11rem]">
            <TwoLine top={r.description || r.id} sub={SYSTEM_RULES.has(r.id) ? <>{r.id}<SystemMark /></> : r.id} title={r.description ? `${r.description} (${r.id})` : r.id} />
          </span>
        ),
        csv: (r) => `${r.description || r.id} (${r.id})`,
      },
      { key: 'kind', label: '종류', sort: (r) => r.kind, cell: (r) => <KindBadge kind={r.kind} label={KIND_SHORT[r.kind]} />, csv: (r) => KIND_SHORT[r.kind] },
      { key: 'action', label: '판정', sort: (r) => r.action, cell: (r) => <ActionPill rule={r} />, csv: (r) => (r.action === 'kill' ? '격리' : '경고') },
      { key: 'containers', label: '적용 컨테이너', maxWidth: 320, cell: (r) => <ContainerChips rule={r} />, csv: containersText },
      { key: 'lastHit', label: '마지막 위반', width: COL_W.time, sort: (r) => r.lastHit ?? '', cell: (r) => (r.lastHit ? <TimeText value={r.lastHit} kind="status" /> : null), csv: (r) => (r.lastHit ? fmtStatus(r.lastHit) : null) },
      { key: 'updated', label: '마지막 수정', width: COL_W.time, sort: (r) => r.updatedAt ?? '', cell: (r) => (r.updatedAt ? <TimeText value={r.updatedAt} kind="status" /> : null), csv: (r) => (r.updatedAt ? fmtStatus(r.updatedAt) : null) },
      { key: 'cond', label: '조건 요약', hidden: true, maxWidth: 480, cell: (r) => <span className="block truncate" title={condSummary(r)}>{condSummary(r)}</span>, csv: condSummary },
      { key: 'origin', label: '출처', hidden: true, cell: originOf },
      { key: 'by', label: FIELD.by, hidden: true, width: COL_W.user, cell: (r) => r.updatedBy || null },
    ],
    [],
  );
  const kit = useTableKit<Row>({ columns, grid: 'policies', query: lq.table });
  const rows = useMemo<Row[]>(() => (rules.data ?? []).map((r) => ({ ...r, lastHit: hits.data?.get(r.id) })), [rules.data, hits.data]);
  const f = lq.filters;
  const q = f.q.trim().toLowerCase();
  const list = rows.filter(
    (r) =>
      (!q || r.id.toLowerCase().includes(q) || (r.description ?? '').toLowerCase().includes(q)) &&
      (!f.rkind || r.kind === f.rkind) &&
      actMatches(r, f.act) &&
      (!f.scope || scopeFromList(r.containers ?? []) === f.scope),
  );
  const view = kit.view(list);
  const ids = view.rows.map((r) => r.id);
  const open = (id: string) => (proposalId ? go({ proposal: null, id, tab: null }) : lq.open(id));

  // ── 시트 · 창에 넘길 시작 값 ──
  const defaultId = prefill.default;
  const { tpl, intent, value: intentValue } = prefill;
  const intentKind = (prefill.kind || null) as Kind | null;
  const current = rules.data?.find((r) => r.id === sel);
  const pendingDefault = defaultId
    ? (() => {
        const d = defaults.data;
        const miss = d?.missing?.find((r) => r.id === defaultId);
        if (miss) return { rule: miss, isNew: true, intro: `새 기본 규칙 · ${miss.id}` };
        const diff = d?.differs?.find((x) => x.id === defaultId);
        if (diff && current) return { rule: mergeDefault(stripView(current), diff.default), isNew: false, intro: `바뀐 기본 규칙 · ${diff.id}(빠진 값만 더함)` };
        return null;
      })()
    : null;
  const createStart: CreateStart | null = (() => {
    if (pendingDefault?.isNew) return { rule: pendingDefault.rule, fresh: null, intro: pendingDefault.intro, autoCheck: true };
    if (intent === 'block' && intentKind && KINDS.includes(intentKind) && intentValue) return { rule: ruleFromBlock(intentKind, intentValue, existingIds), fresh: null, intro: `「${intentValue}」 막기에서 시작함` };
    if (tpl) {
      const r = fromTemplate(tpl, existingIds);
      return { rule: r, fresh: null, intro: `템플릿 「${r.description || r.id}」에서 시작합니다. 저장 전에 모두 고칠 수 있습니다.` };
    }
    return null;
  })();
  const sheetStart = (() => {
    if (!current) return null;
    if (pendingDefault && !pendingDefault.isNew) return { rule: pendingDefault.rule, fresh: null, intro: pendingDefault.intro, autoCheck: true };
    if (intent === 'allow' && intentValue) {
      const x = ruleWithAllow(stripView(current), intentValue);
      return { ...x, intro: x.fresh ? `예외 ${x.fresh.value} 를 더한 값입니다. 확인 후 저장하세요` : undefined };
    }
    return { rule: stripView(current), fresh: null };
  })();
  const editorKey = `${sel}|${intent}|${intentValue}|${defaultId}`;
  const enforceKill = info?.enforceKill !== false;
  const onCreated = (r: Rule) => {
    refreshAll();
    toast(`정책 ${r.id} 을(를) 저장했습니다.`, { key: `policy:${r.id}`, tone: 'ok' });
    startTransition(clearPrefill);
    go({ id: r.id, tab: null });
  };
  const proposal = proposals.data?.find((p) => p.id === proposalId);
  const pc = proposal && cases?.find((c) => c.id === proposal.caseId);

  return (
    <div className="flex h-full min-h-0 flex-col gap-3" data-screen="policies">
      {canWrite && (
        <PageActions>
          <div className="ml-auto flex shrink-0 items-center gap-2">
            <button type="button" data-action="policy-yaml" onClick={() => go({ id: BULK, tab: null, proposal: null })} className="sg-btn sg-btn-sm sg-btn-secondary flex items-center gap-1.5 whitespace-nowrap">
              <FileCode className="size-3.5" aria-hidden /> YAML 일괄 적용
            </button>
            <button
              type="button"
              data-action="policy-create"
              onClick={() => {
                clearPrefill();
                go({ id: NEW, tab: null, proposal: null });
              }}
              className="sg-btn sg-btn-sm sg-btn-primary flex items-center gap-1.5 whitespace-nowrap"
            >
              <Plus className="size-3.5" aria-hidden /> 정책 생성
            </button>
          </div>
        </PageActions>
      )}
      <p className="shrink-0 text-[13.5px] text-text-3" data-part="screen-copy">
        {screenCopy('policies')}
      </p>
      {(drafts.length > 0 || (!!proposals.error && !proposals.data)) && (
        <section className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1.5 rounded-[var(--r-md)] border border-warn bg-warn-soft px-4 py-2 text-[13.5px]" data-testid="proposals">
          {proposals.error && !proposals.data ? (
            <LoadError error={proposals.error} what="제안" compact />
          ) : (
            <>
              <b className="text-text">적용 대기 제안 {drafts.length}건</b>
              <span className="text-xs text-text-2">판정에서 나온 정책 · 차단 목록 변경, 눌러서 미리보기 후 적용하거나 버림</span>
              <span className="flex flex-wrap items-center gap-1.5">
                {drafts.slice(0, 4).map((p) => {
                  const c = cases?.find((x) => x.id === p.caseId);
                  return (
                    <button
                      key={p.id}
                      type="button"
                      data-proposal={p.id}
                      onClick={() => go({ proposal: p.id, id: null, tab: null })}
                      className="flex items-center gap-1.5 rounded-[var(--r-sm)] border border-border bg-surface px-2 py-1 text-xs hover:bg-surface-2"
                    >
                      <DecisionBadge decision={p.decision} />
                      <span className="max-w-48 truncate font-mono text-text">{c ? caseLabel(c) : p.caseId}</span>
                    </button>
                  );
                })}
                {drafts.length > 4 && <span className="text-xs text-text-3">외 {drafts.length - 4}건</span>}
              </span>
            </>
          )}
        </section>
      )}
      <DefaultsBanner
        data={defaults.error ? undefined : defaults.data}
        canWrite={canWrite}
        onPreview={(x) => {
          setPrefill({ tpl: '', intent: '', kind: '', value: '', default: x.id });
          go(x.kind === 'differs' ? { id: x.id, tab: null, proposal: null } : { id: NEW, tab: null, proposal: null });
        }}
      />
      <FilterBar name="policies" active={lq.active} onClear={lq.clearFilters}>
        <SearchField label="정책 검색" placeholder="정책 ID · 설명" value={f.q} onApply={(v) => lq.setFilters({ q: v })} />
        <Select name="rkind" label="종류" value={f.rkind} options={KIND_OPTIONS} onChange={(v) => lq.setFilters({ rkind: v })} />
        <Select name="act" label="판정" value={f.act} options={ACT_OPTIONS} onChange={(v) => lq.setFilters({ act: v })} />
        <Select name="scope" label="적용 범위" value={f.scope} options={SCOPE_OPTIONS} onChange={(v) => lq.setFilters({ scope: v })} />
      </FilterBar>
      <div className="sg-card flex min-h-0 flex-1 flex-col overflow-hidden" data-testid="rules">
        <TableToolbar
          name="policies"
          total={rules.data ? list.length : null}
          kit={kit}
          onRefresh={refreshAll}
          refreshing={busy}
          onExport={() => downloadCSV(`policies-${new Date().toISOString().slice(0, 10)}.csv`, kit.csv(list))}
        />
        {rules.error && !rules.data ? (
          <ListError error={rules.error} what="정책" onRetry={rules.reload} />
        ) : !rules.data ? (
          <Skeleton />
        ) : !rules.data.length ? (
          <EmptyState
            what="정책"
            hint="「정책 생성」으로 첫 정책을 만드세요."
            actions={
              canWrite && (
                <button type="button" className="sg-btn sg-btn-primary" onClick={() => go({ id: NEW, tab: null })}>
                  정책 생성
                </button>
              )
            }
          />
        ) : !list.length ? (
          <NoResults onClear={lq.clearFilters} />
        ) : (
          <TableScroll data-fill="" className="min-h-0 flex-1 overflow-auto">
            <table className="sg-table min-w-[760px]" data-table="policies">
              <SortHead kit={kit} />
              <tbody>
                {view.rows.map((r) => (
                  <tr key={r.id} data-rule={r.id} {...rowState({ open: r.id === sel })} {...rowKeys(() => open(r.id))} onClick={() => open(r.id)} className="cursor-pointer">
                    <GridCells kit={kit} row={r} />
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
        {rules.data && list.length > 0 && (
          <PagerSlot>
            <TablePager name="policies" total={view.total} from={view.from} to={view.to} page={view.page} size={kit.size} onPage={kit.setPage} onSize={kit.setSize} />
          </PagerSlot>
        )}
      </div>
      <ScreenNote screen="policies" />

      {sel && sel !== NEW && sel !== BULK && (
        <PolicySheet
          id={sel}
          rule={current}
          loading={!rules.data}
          tab={lq.tab}
          onTab={lq.setTab}
          nav={sheetNav(ids, sel, (id) => lq.open(id))}
          onClose={() => {
            clearPrefill();
            lq.close();
          }}
          start={sheetStart}
          editorKey={editorKey}
          canWrite={canWrite}
          enforceKill={enforceKill}
          existingIds={existingIds}
          onSaved={() => {
            refreshAll();
            clearPrefill();
          }}
          onDeleted={() => {
            refreshAll();
            clearPrefill();
            lq.close();
          }}
          onReverted={refreshAll}
        />
      )}
      {sel === NEW && (!!rules.data || !!rules.error) && (!defaultId || !!defaults.data || !!defaults.error) && (
        <CreatePolicyModal
          start={createStart}
          canWrite={canWrite}
          enforceKill={enforceKill}
          existingIds={existingIds}
          onClose={() => {
            clearPrefill();
            go({ id: null, tab: null });
          }}
          onSaved={onCreated}
        />
      )}
      {sel === BULK && (
        <BulkYamlModal canWrite={canWrite} ruleCount={(rules.data ?? []).filter((r) => !SYSTEM_RULES.has(r.id)).length} onClose={() => go({ id: null })} onApplied={refreshAll} />
      )}
      {proposalId && (
        <Sheet kind="proposal" size="wide" title={`판정 제안 ${proposalId}`} subtitle={pc ? `${pc.id} 판정에서 나온 변경` : undefined} onClose={() => go({ proposal: null })}>
          <ProposalDetail key={proposalId} proposal={proposal} loading={!proposals.data && !proposals.error} error={proposals.error} canWrite={canWrite} onDone={refreshAll} bare />
        </Sheet>
      )}
    </div>
  );
}
