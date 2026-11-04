import { Download, History as HistoryIcon, RotateCw, ScrollText, SearchX } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DecisionBadge } from '../../components/Badges';
import { DnsRow } from '../../components/DnsRow';
import { SequenceRow } from '../../components/SequenceRow';
import { downloadCSV } from '../../components/list/csv';
import { rowKeys, useAutoRetry } from '../../components/list/hooks';
import { AppliedFilters, ClearFiltersButton, EmptyState, ListError, Skeleton } from '../../components/list/ListStates';
import { KindBadge } from '../../components/KindBadge';
import { PageActions } from '../../components/PageActions';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { PolicyStarts } from '../../components/PolicyStarts';
import { Section, Sheet } from '../../components/Sheet';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useCases } from '../../hooks/cases-context';
import { useFilters } from '../../hooks/useFilters';
import { useLoad } from '../../hooks/useLoad';
import { api, errorText, type AuditParams } from '../../lib/api';
import { fmtDateTime, shortId } from '../../lib/format';
import { scanHref, SOURCE_LABEL } from '../../lib/guide';
import { installDest, topologyDest } from '../../lib/nav';
import { isInstallContainer } from '../../lib/topology';
import { caseLabel, CHANGE_KIND_LABEL, DECISION_LABEL, detailOf, KIND_LONG, KINDS, LEVEL_LABEL, levelOf, type AuditEntry, type Case } from '../../lib/types';
import { EvidenceView } from './EvidenceView';

const PAGE = 100;
const ctl = 'h-8 rounded-md border border-slate-300 bg-white px-2 text-sm focus:border-indigo-500 focus:outline-none';
const FILTERS = ['kind', 'action', 'rule', 'container', 'since', 'until'] as const;
type FilterKey = (typeof FILTERS)[number];
type Filters = Record<FilterKey, string>;

// datetime-local(로컬 시각) → RFC3339
const toIso = (v: string) => (v ? new Date(v).toISOString() : '');
const fdt = (v: string) => v.replace('T', ' ');
const ACTION_KO: Record<string, string> = { alert: '경고', kill: '격리' };
// CSV 내보내기(10/20 D): 백엔드 한 번에 최대 500행(store.MaxAuditLimit) — 나눠 받아 최대 10,000행
const CSV_PAGE = 500;
const CSV_MAX = 10_000;

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

// 감사 로그 — 질문 하나: 「언제 무엇이 걸렸고, 어떻게 닫혔나?」 기간 조회는 여기만
export function AuditPage() {
  const [params, setParams] = useSearchParams();
  const view = params.get('view') === 'changes' ? 'changes' : 'violations';
  const id = params.get('id');
  const tab = params.get('tab') === 'evidence' ? 'evidence' : 'detail';
  // 필터는 화면 상태로만, 링크용(view · id · tab)만 주소에(10/21)
  const [filters, setFilters] = useFilters('/audit');
  const debounced = useDebounced(filters, 300);
  const { cases } = useCases();
  const caseOf = useMemo(() => new Map((cases ?? []).map((c) => [c.id, c])), [cases]);

  const setFilter = (k: FilterKey, v: string) => setFilters({ [k]: v });
  const set = (k: 'id' | 'tab', v: string, replace = k !== 'id') => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k === 'id' && !replace) next.delete('tab'); // 다른 행을 열면 상세 탭부터
    setParams(next, { replace });
  };
  const clearKeys = (keys: readonly FilterKey[]) => {
    if (keys.length) setFilters(Object.fromEntries(keys.map((k) => [k, ''])));
    const next = new URLSearchParams(params);
    next.delete('id');
    next.delete('tab');
    setParams(next, { replace: true });
  };
  const periodChip = !!(filters.since || filters.until) && {
    key: 'period',
    label: `기간: ${filters.since ? fdt(filters.since) : '처음'} ~ ${filters.until ? fdt(filters.until) : '지금'}`,
    clear: () => clearKeys(['since', 'until']),
  };
  const chips =
    view === 'violations'
      ? [
          !!filters.kind && { key: 'kind', label: `종류: ${filters.kind}`, clear: () => clearKeys(['kind']) },
          !!filters.action && { key: 'action', label: `대응: ${ACTION_KO[filters.action] ?? filters.action}`, clear: () => clearKeys(['action']) },
          !!filters.rule && { key: 'rule', label: `규칙: ${filters.rule}`, clear: () => clearKeys(['rule']) },
          !!filters.container && { key: 'container', label: `컨테이너: ${filters.container}`, clear: () => clearKeys(['container']) },
          periodChip,
        ]
      : [periodChip];
  const filtered = chips.some(Boolean);

  return (
    <div className="flex h-full min-h-0 gap-4">
      <PageActions>
        <div className="flex rounded-md border border-slate-300 p-0.5" role="group" aria-label="보기">
          {(
            [
              ['violations', '위반 이력'],
              ['changes', '판정 · 변경 이력'],
            ] as const
          ).map(([v, label]) => (
            <button
              key={v}
              type="button"
              aria-pressed={view === v}
              onClick={() => {
                const next = new URLSearchParams(params);
                if (v === 'changes') next.set('view', v);
                else next.delete('view');
                next.delete('id');
                setParams(next, { replace: true });
              }}
              className={`rounded px-3 py-1 text-xs font-medium ${view === v ? 'bg-indigo-600 text-white' : 'text-slate-600 hover:bg-slate-100'}`}
            >
              {label}
            </button>
          ))}
        </div>
      </PageActions>
      <Panel className="min-w-0 flex-1" testId="audit" title={view === 'changes' ? '판정 · 정책 변경 이력' : '위반 이력'}>
        <div className="flex h-full flex-col">
          <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-slate-100 px-4 py-2.5 text-sm">
            {view === 'violations' && (
              <>
                <label className="flex items-center gap-1.5 text-slate-500">
                  종류
                  <select className={ctl} value={filters.kind} onChange={(e) => setFilter('kind', e.target.value)}>
                    <option value="">전체</option>
                    {KINDS.map((k) => (
                      <option key={k} value={k}>
                        {k === 'dns' ? `dns (${KIND_LONG.dns})` : k}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex items-center gap-1.5 text-slate-500">
                  대응
                  <select className={ctl} value={filters.action} onChange={(e) => setFilter('action', e.target.value)}>
                    <option value="">전체</option>
                    <option value="alert">경고 (alert)</option>
                    <option value="kill">격리 (kill)</option>
                  </select>
                </label>
                <label className="flex items-center gap-1.5 text-slate-500">
                  규칙
                  <input className={`${ctl} w-32`} placeholder="규칙 id" value={filters.rule} onChange={(e) => setFilter('rule', e.target.value)} />
                </label>
                <label className="flex items-center gap-1.5 text-slate-500">
                  컨테이너
                  <input className={`${ctl} w-32`} placeholder="이름" value={filters.container} onChange={(e) => setFilter('container', e.target.value)} />
                </label>
              </>
            )}
            <label className="flex items-center gap-1.5 text-slate-500">
              기간
              <input type="datetime-local" className={ctl} value={filters.since} onChange={(e) => setFilter('since', e.target.value)} aria-label="기간 시작" />
              ~
              <input type="datetime-local" className={ctl} value={filters.until} onChange={(e) => setFilter('until', e.target.value)} aria-label="기간 끝" />
            </label>
            {view === 'violations' && <ExportCsv filters={filters} caseOf={caseOf} />}
          </div>
          <AppliedFilters items={chips} onClearAll={() => clearKeys(FILTERS)} />
          {view === 'violations' ? (
            <Violations
              filters={debounced}
              caseOf={caseOf}
              selectedId={id}
              filtered={filtered}
              autoOpen={tab === 'evidence' && !id}
              onClear={() => clearKeys(FILTERS)}
              onOpen={(rid, auto) => set('id', String(rid), auto)}
            />
          ) : (
            <History cases={cases} since={debounced.since} until={debounced.until} filtered={filtered} onClear={() => clearKeys(FILTERS)} />
          )}
        </div>
      </Panel>
      {view === 'violations' && id && (
        <AuditSheetLoader id={Number(id)} caseOf={caseOf} tab={tab} onTab={(t) => set('tab', t === 'evidence' ? 'evidence' : '', true)} onClose={() => clearKeys([])} />
      )}
    </div>
  );
}

// 시트는 목록에서 찾는다(목록 상태를 공유하려고 전역 캐시에 둔다)
const rowCache = new Map<number, AuditEntry>();

function Violations({
  filters,
  caseOf,
  selectedId,
  filtered,
  autoOpen,
  onClear,
  onOpen,
}: {
  filters: Filters;
  caseOf: Map<string, Case>;
  selectedId: string | null;
  filtered: boolean;
  // 「증거 보기」 링크(?tab=evidence + state 의 컨테이너 필터)로 들어오면 격리된 첫 행(없으면 첫 행)을 연다
  autoOpen: boolean;
  onClear: () => void;
  onOpen: (id: number, auto?: boolean) => void;
}) {
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  // 첫 페이지를 한 번이라도 받았나(스켈레톤) · 마지막 오류
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const fetchPage = useCallback(
    async (before?: number) => {
      setLoading(true);
      try {
        const p: AuditParams = { ...filters, since: toIso(filters.since), until: toIso(filters.until), limit: PAGE, before };
        const page = await api.audit(p);
        page.forEach((r) => rowCache.set(r.id, r));
        setRows((prev) => (before ? [...prev, ...page] : page));
        setHasMore(page.length === PAGE);
        setLoaded(true);
        setError(null);
      } catch (e) {
        setError(e);
      } finally {
        setLoading(false);
      }
    },
    [filters],
  );

  useEffect(() => {
    const t = window.setTimeout(() => void fetchPage(), 0);
    return () => window.clearTimeout(t);
  }, [fetchPage]);

  const failing = !!error && !loaded;
  const retry = useCallback(() => void fetchPage(), [fetchPage]);
  useAutoRetry(failing, error, retry);

  const opened = useRef(false);
  useEffect(() => {
    if (!autoOpen || opened.current || !loaded || !rows.length) return;
    opened.current = true;
    const first = rows.find((r) => levelOf(r) === 'killed') ?? rows[0];
    onOpen(first.id, true);
  }, [autoOpen, loaded, rows, onOpen]);

  return (
    <>
      {!!error && loaded && <LoadError error={error} what="감사 로그" compact />}
      <div data-fill="" className="min-h-0 flex-1 overflow-auto" data-testid="audit-scroll">
        {failing ? (
          <ListError error={error} what="감사 로그" onRetry={retry} retrying={loading} />
        ) : !loaded ? (
          <Skeleton rows={8} />
        ) : rows.length === 0 ? (
          filtered ? (
            <EmptyState icon={SearchX} title="조건에 맞는 기록 없음" actions={<ClearFiltersButton onClick={onClear} />} />
          ) : (
            <EmptyState icon={ScrollText} title="아직 위반 기록이 없습니다" hint="정책에 걸린 행동이 있으면 여기에 쌓입니다. 정상 이벤트는 저장하지 않습니다." />
          )
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10 bg-slate-50 text-left text-xs text-slate-500">
              <tr>
                {['#', '시각', '컨테이너 · 패키지', '종류', '상세', '규칙', '탐지 결과', '판정'].map((h) => (
                  <th key={h} className="px-3 py-2 font-semibold whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => {
                const c = a.caseId ? caseOf.get(a.caseId) : undefined;
                const install = a.install ?? null;
                return (
                  <tr
                    key={a.id}
                    {...rowKeys(() => onOpen(a.id))}
                    data-audit={a.id}
                    aria-selected={String(a.id) === selectedId}
                    onClick={() => onOpen(a.id)}
                    className={`cursor-pointer border-b border-slate-100 hover:bg-slate-50 focus:outline-2 focus:-outline-offset-2 focus:outline-indigo-500 ${
                      String(a.id) === selectedId ? 'bg-indigo-50' : ''
                    }`}
                  >
                    <td className="num px-3 py-2 text-right text-xs text-slate-400">{a.id}</td>
                    <td className="num px-3 py-2 font-mono text-xs whitespace-nowrap text-slate-600">{fmtDateTime(a.event.timestamp)}</td>
                    <td className="max-w-52 truncate px-3 py-2 whitespace-nowrap" title={a.event.containerName}>
                      {install ? (
                        <span className="flex items-center gap-1.5">
                          <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-[11px] text-indigo-700">설치 검사</span>
                          <span className="truncate font-mono text-slate-800">{install.label}</span>
                        </span>
                      ) : (
                        <span className="font-medium text-slate-800">{a.event.containerName}</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <KindBadge kind={a.event.kind} />
                    </td>
                    <td className="w-full max-w-0 truncate px-3 py-2 font-mono text-xs text-slate-600" title={detailOf(a.event)}>
                      {detailOf(a.event)}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs whitespace-nowrap">{a.ruleId}</td>
                    <td className="px-3 py-2">
                      <VerdictBadge v={a} />
                    </td>
                    <td className="px-3 py-2" data-col="decision">
                      {c ? <DecisionBadge decision={c.decision} /> : <span className="text-xs text-slate-300">—</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {hasMore && (
          <div className="p-3 text-center">
            <button
              type="button"
              disabled={loading}
              onClick={() => void fetchPage(rows[rows.length - 1]?.id)}
              className="rounded-md border border-slate-300 px-4 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
            >
              <RotateCw className={`mr-1 inline size-3.5 ${loading ? 'sg-spin' : ''}`} aria-hidden />더 보기
            </button>
          </div>
        )}
      </div>
    </>
  );
}

function AuditSheetLoader({
  id,
  caseOf,
  tab,
  onTab,
  onClose,
}: {
  id: number;
  caseOf: Map<string, Case>;
  tab: 'detail' | 'evidence';
  onTab: (t: 'detail' | 'evidence') => void;
  onClose: () => void;
}) {
  // 목록에 없으면(직접 연 주소) 그 id 바로 앞에서 한 건을 다시 찾는다
  const cached = rowCache.get(id);
  const load = useCallback(() => (cached ? Promise.resolve([cached]) : api.audit({ before: id + 1, limit: 1 })), [cached, id]);
  const r = useLoad(load);
  const a = r.data?.find((x) => x.id === id);
  // 증거는 격리(kill) 직전에만 모으므로 탭은 격리된 행에만 — 링크로 증거 탭을 바로 연 경우는 그대로 보인다
  const tabs = !!a && (levelOf(a) === 'killed' || tab === 'evidence');
  const shown = tabs ? tab : 'detail';
  return (
    <Sheet kind="audit" title={`감사 기록 #${id}`} onClose={onClose}>
      {a ? (
        <>
          {tabs && (
            <div className="flex gap-1 border-b border-slate-100 px-4 pt-2" role="tablist" aria-label="보기">
              {(
                [
                  ['detail', '상세'],
                  ['evidence', '증거'],
                ] as const
              ).map(([k, label]) => (
                <button
                  key={k}
                  type="button"
                  role="tab"
                  aria-selected={shown === k}
                  data-tab={k}
                  onClick={() => onTab(k)}
                  className={`-mb-px border-b-2 px-3 py-1.5 text-xs font-medium ${shown === k ? 'border-indigo-600 text-indigo-700' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
                >
                  {label}
                </button>
              ))}
            </div>
          )}
          {shown === 'evidence' ? <EvidenceView a={a} /> : <AuditDetail a={a} c={a.caseId ? caseOf.get(a.caseId) : undefined} />}
        </>
      ) : r.error ? (
        <LoadError error={r.error} what="감사 기록" />
      ) : (
        <Empty>{r.loading ? '불러오는 중…' : '기록을 찾을 수 없습니다'}</Empty>
      )}
    </Sheet>
  );
}

function AuditDetail({ a, c }: { a: AuditEntry; c: Case | undefined }) {
  const name = a.event.containerName;
  return (
    <div className="text-sm">
      <Section title="위반">
        <dl className="grid grid-cols-[5rem_1fr] gap-x-3 gap-y-1.5">
          <dt className="text-slate-500">탐지 결과</dt>
          <dd>
            <VerdictBadge v={a} />
          </dd>
          <dt className="text-slate-500">시각</dt>
          <dd className="num">{fmtDateTime(a.event.timestamp)}</dd>
          <dt className="text-slate-500">사유</dt>
          <dd data-testid="audit-reason">{a.reason ?? '—'}</dd>
          <SequenceRow v={a} />
          {a.enforceError && (
            <>
              <dt className="text-slate-500">격리 오류</dt>
              <dd className="text-red-600">{a.enforceError}</dd>
            </>
          )}
          <dt className="text-slate-500">규칙</dt>
          <dd className="font-mono text-xs">{a.ruleId}</dd>
          <dt className="text-slate-500">상세</dt>
          <dd className="font-mono text-xs break-all" data-part="detail">
            {detailOf(a.event)}
          </dd>
          <DnsRow e={a.event} />
          {a.install && (
            <>
              <dt className="text-slate-500">패키지</dt>
              <dd className="font-mono text-xs">{a.install.label}</dd>
            </>
          )}
          <dt className="text-slate-500">컨테이너</dt>
          <dd className="break-all">{name}</dd>
          <dt className="text-slate-500">컨테이너 ID</dt>
          <dd className="font-mono text-xs">{shortId(a.event.containerId)}</dd>
          <dt className="text-slate-500">이미지</dt>
          <dd className="font-mono text-xs break-all">{a.event.imageName}</dd>
        </dl>
      </Section>
      <PolicyStarts event={a.event} ruleId={a.ruleId} />
      <Section title="판정">
        {!a.caseId ? (
          <p className="text-xs text-slate-500">판정할 건에 속하지 않음 (경고만 있는 런타임 위반 등)</p>
        ) : !c ? (
          <p className="text-xs text-slate-400">건 {a.caseId}</p>
        ) : (
          <div className="grid gap-1.5 text-xs">
            <div className="flex items-center gap-2">
              <DecisionBadge decision={c.decision} />
              {c.decidedBy && (
                <span className="text-slate-500">
                  {c.decidedBy} · {c.decidedAt ? fmtDateTime(c.decidedAt) : ''}
                </span>
              )}
            </div>
            {c.note && <p className="text-slate-600">메모: {c.note}</p>}
            <div className="flex gap-3">
              {a.install || (c.installId && isInstallContainer(name)) ? (
                <Link {...installDest(a.install?.id ?? c.installId ?? '')} className="text-indigo-600 hover:underline">
                  설치 검사에서 보기 →
                </Link>
              ) : (
                <Link {...topologyDest(name)} className="text-indigo-600 hover:underline">
                  토폴로지에서 보기 →
                </Link>
              )}
              {c.proposalId && (
                <Link to={`/policies?proposal=${encodeURIComponent(c.proposalId)}`} className="text-indigo-600 hover:underline">
                  정책 제안 →
                </Link>
              )}
            </div>
          </div>
        )}
      </Section>
    </div>
  );
}

// 판정 · 정책 변경 이력 — 판정(건)과 변경(Change)을 한 시간축에
function History({ cases, since, until, filtered, onClear }: { cases: Case[] | null; since: string; until: string; filtered: boolean; onClear: () => void }) {
  const load = useCallback(() => api.changes(500), []);
  const changes = useLoad(load);
  const failing = !!changes.error && !changes.data;
  useAutoRetry(failing, changes.error, changes.reload);
  const s = since ? new Date(since).getTime() : -Infinity;
  const u = until ? new Date(until).getTime() : Infinity;
  const inRange = (iso: string) => {
    const t = new Date(iso).getTime();
    return t >= s && t <= u;
  };
  const items = [
    ...(cases ?? [])
      .filter((c) => c.decidedAt && c.decision !== 'pending')
      .map((c) => ({
        key: `case:${c.id}`,
        at: c.decidedAt!,
        kind: '판정',
        badge: <DecisionBadge decision={c.decision} />,
        text: `${SOURCE_LABEL[c.source] ?? c.source} ${caseLabel(c)} — ${DECISION_LABEL[c.decision]}${c.note ? ` · ${c.note}` : ''}`,
        href: scanHref(c),
        by: c.decidedBy ?? '—',
        reason: '',
      })),
    ...(changes.data ?? []).map((ch) => ({
      key: `chg:${ch.id}`,
      at: ch.at,
      kind: CHANGE_KIND_LABEL[ch.kind] ?? ch.kind,
      badge: null,
      text: ch.summary,
      href: null as string | null,
      by: ch.by,
      reason: ch.reason ?? '',
    })),
  ]
    .filter((x) => inRange(x.at))
    .sort((a, b) => b.at.localeCompare(a.at));

  return (
    <>
      {!!changes.error && !!changes.data && <LoadError error={changes.error} what="변경 이력" compact />}
      <div data-fill="" className="min-h-0 flex-1 overflow-auto" data-testid="history">
        {failing ? (
          <ListError error={changes.error} what="변경 이력" onRetry={changes.reload} retrying={changes.loading} />
        ) : !changes.data ? (
          <Skeleton rows={6} />
        ) : items.length === 0 ? (
          filtered ? (
            <EmptyState icon={SearchX} title="이 기간의 판정 · 변경 기록 없음" actions={<ClearFiltersButton onClick={onClear} />} />
          ) : (
            <EmptyState icon={HistoryIcon} title="판정 · 변경 기록 없음" hint="판정 · 제안 적용 · 정책 편집 · 차단 해제가 여기에 남습니다." />
          )
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10 bg-slate-50 text-left text-xs text-slate-500">
              <tr>
                {['시각', '종류', '내용', '처리자'].map((h) => (
                  <th key={h} className="px-3 py-2 font-semibold whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((x) => (
                <tr key={x.key} className="border-b border-slate-100" data-history={x.key}>
                  <td className="num px-3 py-2 font-mono text-xs whitespace-nowrap text-slate-600">{fmtDateTime(x.at)}</td>
                  <td className="px-3 py-2 text-xs whitespace-nowrap">
                    <span className="flex items-center gap-1.5">
                      <span className="rounded bg-slate-100 px-1.5 py-0.5 text-slate-600">{x.kind}</span>
                      {x.badge}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-slate-700">
                    {x.text}
                    {x.href && (
                      <>
                        {' '}
                        <Link to={x.href} className="text-xs text-indigo-600 hover:underline">
                          검사 결과 보기
                        </Link>
                      </>
                    )}
                    {x.reason && (
                      <div className="mt-0.5 text-xs text-slate-500" data-reason="">
                        사유: {x.reason}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs whitespace-nowrap text-slate-500">{x.by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// CSV 내보내기(10/20 D) — 기간(시작 · 끝)이 있어야 한다. 지금 필터 그대로, 최대 10,000행, BOM
function ExportCsv({ filters, caseOf }: { filters: Filters; caseOf: Map<string, Case> }) {
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!filters.since || !filters.until) {
      setErr('기간(시작 · 끝)을 먼저 고르세요 — 내보내기는 기간 안의 기록만 담습니다');
      return;
    }
    setErr('');
    setBusy(true);
    try {
      const q: AuditParams = { kind: filters.kind, action: filters.action, rule: filters.rule, container: filters.container, since: toIso(filters.since), until: toIso(filters.until) };
      const all: AuditEntry[] = [];
      let before: number | undefined;
      while (all.length < CSV_MAX) {
        const page = await api.audit({ ...q, limit: CSV_PAGE, before });
        all.push(...page);
        if (page.length < CSV_PAGE) break;
        before = page[page.length - 1].id;
      }
      const day = (v: string) => v.slice(0, 10).replace(/-/g, '');
      downloadCSV(`supplyguard-audit-${day(filters.since)}-${day(filters.until)}.csv`, [
        ['id', '시각', '컨테이너', '이미지', '종류', '상세', '규칙', '탐지 결과', '판정', '사유'],
        ...all.slice(0, CSV_MAX).map((a) => {
          const c = a.caseId ? caseOf.get(a.caseId) : undefined;
          return [a.id, a.event.timestamp, a.install ? a.install.label : a.event.containerName, a.event.imageName, a.event.kind, detailOf(a.event), a.ruleId ?? '', LEVEL_LABEL[levelOf(a)], c ? DECISION_LABEL[c.decision] : '', a.reason ?? ''];
        }),
      ]);
    } catch (e) {
      setErr(`내보내기 실패 — ${errorText(e)}`);
    } finally {
      setBusy(false);
    }
  };
  return (
    <span className="ml-auto flex items-center gap-2">
      {err && (
        <span className="max-w-72 truncate text-xs text-red-600" data-part="export-error" role="alert" title={err}>
          {err}
        </span>
      )}
      <button
        type="button"
        data-action="export-csv"
        disabled={busy}
        onClick={() => void run()}
        title="지금 필터 · 기간의 위반 기록을 CSV 로"
        className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-600 hover:bg-slate-100 disabled:opacity-50"
      >
        <Download className="size-3.5" aria-hidden /> CSV 내보내기
      </button>
    </span>
  );
}
