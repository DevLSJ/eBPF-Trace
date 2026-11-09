import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DecisionBadge } from '../../components/Badges';
import { DnsRow } from '../../components/DnsRow';
import { SequenceRow } from '../../components/SequenceRow';
import { downloadCSV } from '../../components/list/csv';
import { rowKeys, rowState, useAutoRetry, useBusy } from '../../components/list/hooks';
import { AppliedFilters, EmptyState, ListError, NoResults, PagerSlot, Skeleton } from '../../components/list/ListStates';
import { TimeText, TwoLine } from '../../components/list/cells';
import { fmtLog } from '../../components/list/cell-format';
import { FilterBar, SearchField } from '../../components/list/SearchField';
import { ScreenNote } from '../../components/ScreenNote';
import { Select } from '../../components/Select';
import { TableToolbar } from '../../components/TableToolbar';
import { ScreenHead } from '../../components/ScreenHead';
import { GridCells, SortHead, StatusPill, TablePager, TableScroll } from '../../components/DataTable';
import { actionTone } from '../../lib/actionTone';
import { changeName } from '../policies/changeView';
import { COL_W, useTableKit, type Column, type TableKit } from '../../hooks/useTableKit';
import { KindBadge } from '../../components/KindBadge';
import { PageActions } from '../../components/PageActions';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { PolicyStarts } from '../../components/PolicyStarts';
import { Section, Sheet } from '../../components/Sheet';
import { sheetNav, type SheetNav } from '../../components/sheet-nav';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useCases } from '../../hooks/cases-context';
import { useFilters } from '../../hooks/useFilters';
import { useLoad } from '../../hooks/useLoad';
import { api, failText, type AuditParams } from '../../lib/api';
import { FIELD } from '../../lib/fieldNames';
import { shortId } from '../../lib/format';
import { scanHref, SOURCE_LABEL } from '../../lib/guide';
import { installDest, topologyDest } from '../../lib/nav';
import { isInstallContainer } from '../../lib/topology';
import { caseLabel, DECISION_LABEL, detailOf, KIND_LONG, KINDS, LEVEL_LABEL, levelOf, type AuditEntry, type Case } from '../../lib/types';
import { EvidenceView } from './EvidenceView';

// 입력 글자 13.5 · 포커스 링은 전역 규칙 하나(11/09 SPEC §1)
const ctl = 'h-8 rounded-[var(--r-md)] border border-slate-300 bg-field px-2';
const FILTERS = ['kind', 'action', 'rule', 'container', 'since', 'until'] as const;
type FilterKey = (typeof FILTERS)[number];
type Filters = Record<FilterKey, string>;

// datetime-local(로컬 시각) → RFC3339
const toIso = (v: string) => (v ? new Date(v).toISOString() : '');
const fdt = (v: string) => v.replace('T', ' ');
const ACTION_KO: Record<string, string> = { alert: '경고', kill: '격리' };
const KIND_OPTIONS = KINDS.map((k) => ({ value: k as string, label: k === 'dns' ? `dns (${KIND_LONG.dns})` : k }));
const ACTION_OPTIONS = [
  { value: 'alert', label: '경고 (alert)' },
  { value: 'kill', label: '격리 (kill)' },
];
const LEVEL_RANK: Record<string, number> = { killed: 0, held: 1, alert: 2, normal: 3 };
// 판정 · 변경 이력 한 줄 — 표 칸(R4 11/04): 머리 클릭 정렬, 기본은 시각 내림(받은 목록 안).
// 11/09 표 도구: 칸 보이기 · 폭 · 순서 = supplyguard.grid.audit-history.v1, CSV = 보이는 칸 · 화면 글
interface HistoryItem {
  key: string;
  at: string;
  kind: string;
  badge: ReactNode;
  // CSV 용 배지 글
  badgeText: string;
  text: string;
  href: string | null;
  by: string;
  reason: string;
}
const HISTORY_COLUMNS: Column<HistoryItem>[] = [
  { key: 'at', label: '시각', sort: (x) => x.at, short: true, width: COL_W.log, cellClass: 'text-slate-600', cell: (x) => <TimeText value={x.at} kind="log" />, csv: (x) => fmtLog(x.at) },
  {
    key: 'kind',
    label: '종류',
    sort: (x) => x.kind,
    short: true,
    cellClass: 'text-xs',
    // 동작 태그 색은 끝말로(lib/actionTone — 해제 = 위험 · 적용 = 정보 · 수정 = 주의 · 등록 = 정상 · 그 밖 회색)
    cell: (x) => (
      <span className="flex items-center gap-1.5">
        <StatusPill tone={actionTone(x.kind)} data-action-tone={actionTone(x.kind)}>
          {x.kind}
        </StatusPill>
        {x.badge}
      </span>
    ),
    csv: (x) => (x.badgeText ? `${x.kind} · ${x.badgeText}` : x.kind),
  },
  {
    key: 'text',
    label: '내용',
    sort: (x) => x.text,
    cellClass: 'text-slate-700',
    cell: (x) => (
      <>
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
      </>
    ),
    csv: (x) => (x.reason ? `${x.text} · 사유: ${x.reason}` : x.text),
  },
  { key: 'by', label: FIELD.by, sort: (x) => x.by, short: true, cellClass: 'text-xs text-slate-500', cell: (x) => x.by, csv: (x) => x.by },
];
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

  const [shownIds, setShownIds] = useState<number[]>([]); // 지금 쪽에 보이는 행 — 상세 패널의 이전/다음(11/05)
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
          !!filters.rule && { key: 'rule', label: `${FIELD.policy}: ${filters.rule}`, clear: () => clearKeys(['rule']) },
          !!filters.container && { key: 'container', label: `컨테이너: ${filters.container}`, clear: () => clearKeys(['container']) },
          periodChip,
        ]
      : [periodChip];
  const filtered = chips.some(Boolean);

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <ScreenHead screen="audit" />
      <div className="flex min-h-0 flex-1 gap-4">
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
            {/* 거르기 줄(11/09): 선택 상자 = 공통 Select(「○○ 전체」), 글 = 검색칸(Enter · 칸 벗어날 때 적용). 조건 지우기는 「적용된 필터」 줄 하나 */}
            {view === 'violations' && (
              <FilterBar name="audit" active={false} onClear={() => clearKeys(FILTERS)}>
                <SearchField label={`${FIELD.policy} 검색`} placeholder={FIELD.policyId} width={180} value={filters.rule} onApply={(v) => setFilter('rule', v)} />
                <SearchField label="컨테이너 검색" placeholder="컨테이너 이름" width={200} value={filters.container} onApply={(v) => setFilter('container', v)} />
                <Select name="kind" label="종류" value={filters.kind} options={KIND_OPTIONS} onChange={(v) => setFilter('kind', v)} />
                <Select name="action" label="대응" value={filters.action} options={ACTION_OPTIONS} onChange={(v) => setFilter('action', v)} />
              </FilterBar>
            )}
            <label className="flex items-center gap-1.5 text-slate-500">
              기간
              <input type="datetime-local" className={ctl} value={filters.since} onChange={(e) => setFilter('since', e.target.value)} aria-label="기간 시작" />
              ~
              <input type="datetime-local" className={ctl} value={filters.until} onChange={(e) => setFilter('until', e.target.value)} aria-label="기간 끝" />
            </label>
          </div>
          <AppliedFilters items={chips} onClearAll={() => clearKeys(FILTERS)} />
          {view === 'violations' ? (
            <Violations
              filters={debounced}
              current={filters}
              caseOf={caseOf}
              selectedId={id}
              edge={!id}
              filtered={filtered}
              autoOpen={tab === 'evidence' && !id}
              onClear={() => clearKeys(FILTERS)}
              onOpen={(rid, auto) => set('id', String(rid), auto)}
              onRows={setShownIds}
            />
          ) : (
            <History cases={cases} since={debounced.since} until={debounced.until} filtered={filtered} onClear={() => clearKeys(FILTERS)} />
          )}
        </div>
      </Panel>
      {view === 'violations' && id && (
        <AuditSheetLoader id={Number(id)} caseOf={caseOf} tab={tab} onTab={(t) => set('tab', t === 'evidence' ? 'evidence' : '', true)} onClose={() => clearKeys([])} nav={sheetNav(shownIds, Number(id), (x) => set('id', String(x)))} />
      )}
      </div>
      <ScreenNote screen="audit" />
    </div>
  );
}

// 시트는 목록에서 찾는다(목록 상태를 공유하려고 전역 캐시에 둔다)
const rowCache = new Map<number, AuditEntry>();

// 쪽 번호(R4 11/04 — 목업 11/04e 감사 로그): offset + total 로 쪽을 받는다(GET /api/audit?offset=&limit= → {items, total}).
// total 이 없는 옛 응답(배열)이면 이전/다음만 — before 커서(쪽마다 마지막 id). 정렬은 받은 쪽 안에서만(사용자 결정). 「더 보기」 단추는 없앴다
interface Req {
  filters: Filters;
  page: number;
  size: number;
}
interface Got {
  rows: AuditEntry[];
  total: number | null;
  page: number;
  size: number;
  hasNext: boolean;
}

function Violations({
  filters,
  current,
  caseOf,
  selectedId,
  edge,
  filtered,
  autoOpen,
  onClear,
  onOpen,
  onRows,
}: {
  filters: Filters;
  // 지금 입력 칸의 값(디바운스 전) — 내보내기는 이 값 그대로
  current: Filters;
  caseOf: Map<string, Case>;
  selectedId: string | null;
  // 표 패널이 화면 오른쪽 끝인가(시트 닫힘) — 바닥줄이 도우미 단추를 비켜 간다
  edge: boolean;
  filtered: boolean;
  // 「증거 보기」 링크(?tab=evidence + state 의 컨테이너 필터)로 들어오면 격리된 첫 행(없으면 첫 행)을 연다
  autoOpen: boolean;
  onClear: () => void;
  onOpen: (id: number, auto?: boolean) => void;
  onRows?: (ids: number[]) => void;
}) {
  // 필터가 바뀌면 첫 쪽부터(렌더 중 맞춤)
  const [req, setReq] = useState<Req>({ filters, page: 1, size: 20 });
  if (req.filters !== filters) setReq({ filters, page: 1, size: req.size });
  const [got, setGot] = useState<Got | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const loaded = got !== null;
  const seq = useRef(0);
  // 옛 백엔드(배열)로 확인되면 커서 방식 — cursors[p-1] = p쪽 마지막 id(다음 쪽 before)
  const legacy = useRef(false);
  const cursors = useRef<number[]>([]);

  const run = useCallback(async (r: Req) => {
    const my = ++seq.current;
    setLoading(true);
    try {
      const base: AuditParams = { ...r.filters, since: toIso(r.filters.since), until: toIso(r.filters.until), limit: r.size };
      const q: AuditParams = legacy.current ? { ...base, before: r.page > 1 ? cursors.current[r.page - 2] : undefined } : { ...base, offset: (r.page - 1) * r.size };
      const res = await api.auditPage(q);
      if (my !== seq.current) return;
      const old = Array.isArray(res);
      if (old) legacy.current = true;
      const items = old ? res : res.items;
      items.forEach((x) => rowCache.set(x.id, x));
      if (items.length) cursors.current[r.page - 1] = items[items.length - 1].id;
      setGot({ rows: items, total: old ? null : res.total, page: r.page, size: r.size, hasNext: old ? items.length === r.size : (r.page - 1) * r.size + items.length < res.total });
      setError(null);
    } catch (e) {
      if (my === seq.current) setError(e);
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const t = window.setTimeout(() => void run(req), 0);
    return () => window.clearTimeout(t);
  }, [req, run]);

  const failing = !!error && !loaded;
  const retry = useCallback(() => void run(req), [run, req]);
  useAutoRetry(failing, error, retry);
  // 재조회: 이전 행은 그대로, 머리 위 2px 진행 띠
  const busy = useBusy(loading && loaded);

  // 11/09 SPEC §4: 기록류 — 시각이 맨 앞(YYYY-MM-DD HH:mm:ss 고정폭). 표 도구: 칸 보이기 · 폭 · 순서 = supplyguard.grid.audit.v1,
  // CSV 내보내기 = 보이는 칸 · 화면 글(기간 안 전체 — 이미지 · 사유는 숨긴 칸을 켜면 함께 나간다)
  const columns = useMemo<Column<AuditEntry>[]>(
    () => [
      { key: 'time', label: '시각', sort: (a) => Date.parse(a.event.timestamp), short: true, width: COL_W.log, cellClass: 'text-slate-600', cell: (a) => <TimeText value={a.event.timestamp} kind="log" />, csv: (a) => fmtLog(a.event.timestamp) },
      { key: 'id', label: '#', num: true, sort: (a) => a.id, short: true, cellClass: 'num text-xs text-slate-400', cell: (a) => a.id },
      {
        key: 'container',
        label: '컨테이너 · 패키지',
        sort: (a) => (a.install ? a.install.label : a.event.containerName),
        width: 220,
        // 두 줄 칸(11/09 G9) — 위 이름 · 아래 컨테이너 ID 12자. 행 48 을 지키려고 위아래 여백 6(.sg-table td 8 을 이 칸만 덮음)
        cellClass: 'py-1.5!',
        cell: (a) => (
          <TwoLine
            title={`${a.install ? a.install.label : a.event.containerName} · ${a.event.containerId}`}
            top={
              a.install ? (
                <>
                  <span className="mr-1.5 rounded bg-indigo-50 px-1.5 text-xs leading-4 text-accent-text">설치 검사</span>
                  <span className="font-mono text-slate-800">{a.install.label}</span>
                </>
              ) : (
                <span className="text-slate-800">{a.event.containerName}</span>
              )
            }
            sub={shortId(a.event.containerId)}
          />
        ),
        csv: (a) => (a.install ? a.install.label : a.event.containerName),
      },
      { key: 'kind', label: '종류', sort: (a) => a.event.kind, short: true, cell: (a) => <KindBadge kind={a.event.kind} />, csv: (a) => a.event.kind },
      { key: 'detail', label: '상세', sort: (a) => detailOf(a.event), fill: true, cellClass: 'font-mono text-xs text-slate-600', cell: (a) => <span title={detailOf(a.event)}>{detailOf(a.event)}</span>, csv: (a) => detailOf(a.event) },
      { key: 'rule', label: FIELD.policy, sort: (a) => a.ruleId, short: true, cellClass: 'font-mono text-xs', cell: (a) => a.ruleId },
      { key: 'level', label: '탐지 결과', sort: (a) => LEVEL_RANK[levelOf(a)], short: true, cell: (a) => <VerdictBadge v={a} />, csv: (a) => LEVEL_LABEL[levelOf(a)] },
      {
        key: 'decision',
        label: '판정',
        sort: (a) => (a.caseId ? (caseOf.get(a.caseId)?.decision ?? null) : null),
        short: true,
        cell: (a) => {
          const c = a.caseId ? caseOf.get(a.caseId) : undefined;
          return c ? <DecisionBadge decision={c.decision} /> : null;
        },
        csv: (a) => {
          const c = a.caseId ? caseOf.get(a.caseId) : undefined;
          return c ? DECISION_LABEL[c.decision] : null;
        },
      },
      { key: 'image', label: '이미지', hidden: true, sort: (a) => a.event.imageName, short: true, cellClass: 'font-mono text-xs', cell: (a) => a.event.imageName },
      { key: 'reason', label: '사유', hidden: true, sort: (a) => a.reason ?? null, cellClass: 'text-xs text-slate-600', cell: (a) => a.reason ?? null },
    ],
    [caseOf],
  );
  const kit = useTableKit({ columns, sort: { key: 'id', dir: 'desc' }, grid: 'audit' });
  const exp = useAuditExport(current, kit);
  const { sorted } = kit;
  const rows = useMemo(() => (got ? sorted(got.rows) : []), [got, sorted]);
  useEffect(() => {
    onRows?.(rows.map((a) => a.id));
  }, [rows, onRows]);

  const opened = useRef(false);
  useEffect(() => {
    if (!autoOpen || opened.current || !got || !got.rows.length) return;
    opened.current = true;
    const first = got.rows.find((r) => levelOf(r) === 'killed') ?? got.rows[0];
    onOpen(first.id, true);
  }, [autoOpen, got, onOpen]);

  const from = got && got.rows.length ? (got.page - 1) * got.size + 1 : 0;
  const to = got ? (got.page - 1) * got.size + got.rows.length : 0;

  return (
    <>
      {!!error && loaded && <LoadError error={error} what="감사 로그" compact />}
      {got && (
        <TableToolbar name="audit" total={got.total ?? got.rows.length} kit={kit} onRefresh={retry} refreshing={busy} onExport={exp.run} exportLabel="CSV 내려받기(지금 조건 · 기간)">
          {exp.err && (
            <span className="max-w-80 truncate text-xs text-red-600" data-part="export-error" role="alert" title={exp.err}>
              {exp.err}
            </span>
          )}
          {exp.busy && <span className="text-xs">내보내는 중…</span>}
        </TableToolbar>
      )}
      <TableScroll data-fill="" className="min-h-0 flex-1 overflow-auto" testId="audit-scroll">
        {failing ? (
          <ListError error={error} what="감사 로그" onRetry={retry} retrying={loading} />
        ) : !got ? (
          <Skeleton rows={8} />
        ) : got.rows.length === 0 ? (
          filtered ? (
            <NoResults onClear={onClear} />
          ) : (
            <EmptyState what="위반 기록" hint="정책에 걸린 행동이 있으면 여기에 쌓입니다." />
          )
        ) : (
          <table className="sg-table" data-table="audit">
            <SortHead kit={kit} />
            <tbody>
              {rows.map((a) => {
                const level = levelOf(a);
                return (
                  <tr key={a.id} {...rowKeys(() => onOpen(a.id))} {...rowState({ open: String(a.id) === selectedId })} data-audit={a.id} data-level={level} onClick={() => onOpen(a.id)} className="cursor-pointer">
                    {/* 11/04e 막대: 격리된 행만(위험색) — 첫 칸 */}
                    <GridCells kit={kit} row={a} bar={level === 'killed' && 'danger'} />
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </TableScroll>
      {got && (
        <PagerSlot edge={edge}>
          <TablePager
            name="audit"
            total={got.total}
            from={from}
            to={to}
            page={got.page}
            size={got.size}
            hasPrev={got.page > 1}
            hasNext={got.hasNext}
            onPage={(page) => setReq((r) => ({ ...r, page: Math.max(1, page) }))}
            onSize={(size) => setReq((r) => ({ ...r, page: 1, size }))}
          />
        </PagerSlot>
      )}
    </>
  );
}

function AuditSheetLoader({
  id,
  caseOf,
  tab,
  onTab,
  onClose,
  nav,
}: {
  id: number;
  caseOf: Map<string, Case>;
  tab: 'detail' | 'evidence';
  onTab: (t: 'detail' | 'evidence') => void;
  onClose: () => void;
  nav?: SheetNav;
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
    <Sheet kind="audit" nav={nav} title={`감사 기록 #${id}`} onClose={onClose}>
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
                  className={`-mb-px border-b-2 px-3 py-1.5 text-xs font-medium ${shown === k ? 'border-indigo-600 text-accent-text' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
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
          <dd>
            <TimeText value={a.event.timestamp} kind="log" />
          </dd>
          <dt className="text-slate-500">사유</dt>
          <dd data-testid="audit-reason">{a.reason ?? ''}</dd>
          <SequenceRow v={a} />
          {a.enforceError && (
            <>
              <dt className="text-slate-500">격리 오류</dt>
              <dd className="text-red-600">{a.enforceError}</dd>
            </>
          )}
          <dt className="text-slate-500">{FIELD.policy}</dt>
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
                  {c.decidedBy} · <TimeText value={c.decidedAt} kind="log" />
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
  const kit = useTableKit({ columns: HISTORY_COLUMNS, sort: { key: 'at', dir: 'desc' }, grid: 'audit-history' });
  const busy = useBusy(changes.loading && !!changes.data);
  const s = since ? new Date(since).getTime() : -Infinity;
  const u = until ? new Date(until).getTime() : Infinity;
  const inRange = (iso: string) => {
    const t = new Date(iso).getTime();
    return t >= s && t <= u;
  };
  const items: HistoryItem[] = [
    ...(cases ?? [])
      .filter((c) => c.decidedAt && c.decision !== 'pending')
      .map((c) => ({
        key: `case:${c.id}`,
        at: c.decidedAt!,
        kind: '판정',
        badge: <DecisionBadge decision={c.decision} />,
        badgeText: DECISION_LABEL[c.decision],
        text: `${SOURCE_LABEL[c.source] ?? c.source} ${caseLabel(c)}${c.note ? ` · ${c.note}` : ''}`,
        href: scanHref(c) as string | null,
        by: c.decidedBy ?? '',
        reason: '',
      })),
    ...(changes.data ?? []).map((ch) => ({
      key: `chg:${ch.id}`,
      at: ch.at,
      // 동작 이름은 정책 변경 이력 화면과 한 곳(changeName — 정책 저장 = 「정책 수정」 · 새 정책 = 「정책 생성」)
      kind: changeName(ch),
      badge: null,
      badgeText: '',
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
      {changes.data && <TableToolbar name="history" total={items.length} kit={kit} onRefresh={changes.reload} refreshing={busy} onExport={() => downloadCSV('supplyguard-changes.csv', kit.csv(items))} />}
      <TableScroll data-fill="" className="min-h-0 flex-1 overflow-auto" testId="history">
        {failing ? (
          <ListError error={changes.error} what="변경 이력" onRetry={changes.reload} retrying={changes.loading} />
        ) : !changes.data ? (
          <Skeleton rows={6} />
        ) : items.length === 0 ? (
          filtered ? (
            <NoResults onClear={onClear} />
          ) : (
            <EmptyState what="판정 · 변경 기록" hint="판정 · 제안 적용 · 정책 편집 · 차단 해제가 여기에 남습니다." />
          )
        ) : (
          <table className="sg-table" data-table="history">
            <SortHead kit={kit} />
            <tbody>
              {kit.sorted(items).map((x) => (
                <tr key={x.key} data-history={x.key} data-kit-row="">
                  <GridCells kit={kit} row={x} />
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </TableScroll>
    </>
  );
}

// CSV 내보내기(10/20 D · 11/09 표 도구) — 기간(시작 · 끝)이 있어야 한다. 지금 조건 그대로, 최대 10,000행, BOM.
// 칸은 표에 보이는 칸 · 순서 · 화면 글(11/09 G13) — 이미지 · 사유가 필요하면 칸 고르기로 켠다
function useAuditExport(filters: Filters, kit: TableKit<AuditEntry>) {
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (busy) return;
    if (!filters.since || !filters.until) {
      setErr('기간을 먼저 고르세요.');
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
      downloadCSV(`supplyguard-audit-${day(filters.since)}-${day(filters.until)}.csv`, kit.csv(all.slice(0, CSV_MAX)));
    } catch (e) {
      setErr(failText('내보내지 못했습니다.', e));
    } finally {
      setBusy(false);
    }
  };
  return { run: () => void run(), err, busy };
}
