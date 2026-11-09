import { Copy } from 'lucide-react';
import { useCallback, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DecisionBadge, StatusBadge } from '../../components/Badges';
import { GridCells, SortHead, TablePager, TableScroll } from '../../components/DataTable';
import { FilterChips } from '../../components/FilterChips';
import { PageActions } from '../../components/PageActions';
import { Panel } from '../../components/Panel';
import { AppliedFilters, ClearFiltersButton, EmptyState, ListError, NoResults, PagerSlot, Skeleton } from '../../components/list/ListStates';
import { TimeText } from '../../components/list/cells';
import { fmtStatus } from '../../components/list/cell-format';
import { downloadCSV } from '../../components/list/csv';
import { rowKeys, rowState, useAutoRetry, useBusy } from '../../components/list/hooks';
import { ScreenNote } from '../../components/ScreenNote';
import { TableToolbar } from '../../components/TableToolbar';
import { useCases } from '../../hooks/cases-context';
import { useFilters } from '../../hooks/useFilters';
import { useCopyCommand } from '../../hooks/useCopyCommand';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { useTableKit, type Column, type TableKit } from '../../hooks/useTableKit';
import { api } from '../../lib/api';
import { ScreenHead } from '../../components/ScreenHead';
import { FIELD } from '../../lib/fieldNames';
import { fmtNum } from '../../lib/format';
import { duration, EXAMPLE_COMMAND, sessionLabel, violationTotal } from '../../lib/pkg';
import { DECISION_LABEL, INSTALL_STATUS_LABEL, INSTALL_STATUSES, MANAGERS, SCAN_VERDICT_LABEL, type InstallSession } from '../../lib/types';
import { InstallSheet } from './InstallSheet';
import { UsageGuide } from './UsageGuide';
import { sheetNav } from '../../components/sheet-nav';
import { StaticBadge } from './StaticBadge';
import { isDangerRow } from './staticScan';

// 표 칸(R4 11/04 — 목업 11/04e U.tableKit): 머리 클릭 정렬 · 기본은 시작 내림(목록 순서 그대로). 설치 결과는 위험한 것부터.
// 11/09 SPEC §4: 현황 표 — 상태(설치 결과 · 바로 뒤 정적 검사, 11/04 종합 판정)가 맨 앞, 시작은 MM-DD HH:mm + 전체 시각 툴팁
const STATUS_RANK: Record<string, number> = { isolated: 0, warned: 1, refused: 2, running: 3, failed: 4, unknown: 5, passed: 6 };
const durSec = (s: InstallSession) => {
  const end = s.finishedAt ?? s.containerExitedAt;
  return s.status === 'refused' || !end ? null : (Date.parse(end) - Date.parse(s.startedAt)) / 1000;
};

// 정적 검사 칸의 화면 글(CSV — 「화면 글 그대로」, 11/09 G13): StaticBadge 와 같은 말
const staticText = (s: InstallSession) => {
  const sc = s.scan;
  if (!sc || sc.status === 'skipped') return null;
  return sc.status === 'running' ? '검사 중…' : sc.status === 'failed' ? '실패' : SCAN_VERDICT_LABEL[sc.verdict ?? 'clean'];
};
const durText = (s: InstallSession) => (s.status === 'running' ? '진행 중' : s.status === 'refused' ? null : duration(s.startedAt, s.finishedAt ?? s.containerExitedAt));

// 결과 칩: 기본 「판정 대기」(목표 문서 완료 기준 ①), 그다음 전체 · 설치 결과별
type StatusFilter = 'pending' | 'all' | (typeof INSTALL_STATUSES)[number];

// 설치 검사 — 질문 하나: 「이 패키지는 무엇을 하려 했고, 악성인가?」
export function InstallsPage() {
  // 필터(결과 · 패키지 관리자)는 화면 상태로만, 열린 세션(id)만 주소에(10/21)
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useFilters('/installs');
  const status = (filters.status as StatusFilter) || 'pending';
  const manager = filters.manager;
  const id = params.get('id');
  const { cases } = useCases();
  const [guide, setGuide] = useState(false); // 「사용 방법」(11/09)
  const copy = useCopyCommand();

  const load = useCallback(() => api.installs({ limit: 500 }), []);
  const list = useLoad(load);
  // 첫 로드가 실패한 동안은 5초 갱신을 멈추고 30초마다 조용히 한 번 다시 부른다(10/20 D)
  const failing = !!list.error && !list.data;
  const { reload } = list;
  const poll = useCallback(() => {
    if (!failing) reload();
  }, [failing, reload]);
  useInterval(poll, 5000);
  useAutoRetry(failing, list.error, reload);

  const caseOf = useMemo(() => new Map((cases ?? []).map((c) => [c.id, c])), [cases]);
  // 11/09 표 도구: 칸 보이기 · 폭 · 순서는 이 브라우저에(supplyguard.grid.installs.v1), CSV = 보이는 칸 · 화면 글.
  // 11/04 결정: 시트가 열려 있으면 「걸린 시간」 칸을 뺀다(상세에 같은 값)
  const columns = useMemo<Column<InstallSession>[]>(
    () => [
      { key: 'status', label: '설치 결과', sort: (s) => STATUS_RANK[s.status], short: true, cell: (s) => <StatusBadge status={s.status} />, csv: (s) => INSTALL_STATUS_LABEL[s.status] },
      { key: 'static', label: '정적 검사', sort: (s) => (s.scan ? (s.scan.verdict ?? s.scan.status) : null), short: true, cell: (s) => <StaticBadge s={s} />, csv: staticText },
      { key: 'started', label: '시작', sort: (s) => Date.parse(s.startedAt), short: true, cellClass: 'text-slate-600', cell: (s) => <TimeText value={s.startedAt} kind="status" />, csv: (s) => fmtStatus(s.startedAt) },
      {
        key: 'manager',
        label: FIELD.manager,
        sort: (s) => s.manager,
        short: true,
        cell: (s) => <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-600">{s.manager}</span>,
        csv: (s) => s.manager,
      },
      { key: 'package', label: '패키지', sort: (s) => sessionLabel(s), fill: true, cellClass: 'font-mono text-slate-800', cell: (s) => <span title={sessionLabel(s)}>{sessionLabel(s)}</span>, csv: sessionLabel },
      {
        key: 'decision',
        label: '판정',
        sort: (s) => (s.caseId ? (caseOf.get(s.caseId)?.decision ?? null) : null),
        short: true,
        cell: (s) => {
          const c = s.caseId ? caseOf.get(s.caseId) : undefined;
          return c ? <DecisionBadge decision={c.decision} /> : null;
        },
        csv: (s) => {
          const c = s.caseId ? caseOf.get(s.caseId) : undefined;
          return c ? DECISION_LABEL[c.decision] : null;
        },
      },
      {
        key: 'violations',
        label: '위반',
        num: true,
        sort: (s) => violationTotal(s) ?? null,
        short: true,
        cellClass: 'num',
        cell: (s) => {
          const n = violationTotal(s);
          return n === undefined ? null : <span className={n ? 'font-semibold text-red-600' : 'text-slate-400'}>{fmtNum(n)}</span>;
        },
        csv: (s) => violationTotal(s) ?? null,
      },
      ...(id ? [] : [{ key: 'duration', label: '걸린 시간', num: true, sort: durSec, short: true, cellClass: 'num text-xs text-slate-500', cell: durText, csv: durText } satisfies Column<InstallSession>]),
    ],
    [caseOf, id],
  );
  const kit = useTableKit({ columns, sort: { key: 'started', dir: 'desc' }, grid: 'installs' });
  const busy = useBusy(list.loading && !!list.data);

  const set = (k: 'id' | 'status' | 'manager', v: string | null) => {
    if (k !== 'id') {
      kit.setPage(1); // 필터를 바꾸면 첫 쪽부터(11/04e)
      return setFilters({ [k]: v ?? '' });
    }
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next);
  };
  const clearFilters = () => {
    kit.setPage(1);
    setFilters({ status: '', manager: '' });
  };

  const sessions = useMemo(() => list.data ?? [], [list.data]);
  const isPending = useCallback((s: InstallSession) => !!s.caseId && caseOf.get(s.caseId)?.state === 'open', [caseOf]);

  const byManager = sessions.filter((s) => !manager || s.manager === manager);
  const rows = byManager.filter((s) => (status === 'all' ? true : status === 'pending' ? isPending(s) : s.status === status));

  const statusOptions = [
    { value: 'pending' as StatusFilter, label: '판정 대기', count: byManager.filter(isPending).length },
    { value: 'all' as StatusFilter, label: '전체', count: byManager.length },
    ...INSTALL_STATUSES.map((st) => ({ value: st as StatusFilter, label: INSTALL_STATUS_LABEL[st], count: byManager.filter((s) => s.status === st).length })).filter(
      (o) => o.count > 0 || o.value === status,
    ),
  ];
  // 주소 ?id= 로 들어오면 그 행이 있는 쪽(첫 데이터 한 번 — 목업 kit.reveal)
  const [revealed, setRevealed] = useState(false);
  if (!revealed && id && list.data) {
    setRevealed(true);
    kit.reveal(rows, (s) => s.id === id);
  }
  const view = kit.view(rows);

  const managerOptions = [
    { value: '', label: '전체', count: sessions.length },
    ...MANAGERS.map((m) => ({ value: m as string, label: m, count: sessions.filter((s) => s.manager === m).length })),
  ];

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <ScreenHead screen="installs" />
      <div className="flex min-h-0 flex-1 gap-4">
      <PageActions>
        <button type="button" onClick={() => setGuide(true)} className="sg-btn sg-btn-sm sg-btn-secondary">
          사용 방법
        </button>
        <button
          type="button"
          onClick={() => copy(EXAMPLE_COMMAND)}
          className="flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs text-slate-600 hover:bg-slate-100"
          title={EXAMPLE_COMMAND}
        >
          <Copy className="size-3.5" aria-hidden /> 명령 복사
        </button>
      </PageActions>

      <Panel
        className="min-w-0 flex-1"
        testId="installs"
        title="설치 세션"
      >
        <div className="flex h-full flex-col">
          {/* 거르기 이름 칸: 「패키지 관리자」(11/09 G44)가 한 줄에 들어가게 두 줄 모두 같은 폭(88) — 칩 시작 위치를 맞춘다 */}
          <div className="grid shrink-0 gap-2 border-b border-slate-100 px-4 py-2.5 [&>[role=group]>span:first-child]:w-22 [&>[role=group]>span:first-child]:whitespace-nowrap">
            <FilterChips label="결과" options={statusOptions} value={status} onChange={(v) => set('status', v === 'pending' ? null : v)} />
            <FilterChips label={FIELD.manager} options={managerOptions} value={manager} onChange={(v) => set('manager', v || null)} />
          </div>
          <AppliedFilters
            items={[
              status !== 'pending' && { key: 'status', label: `결과: ${status === 'all' ? '전체' : (INSTALL_STATUS_LABEL[status] ?? status)}`, clear: () => set('status', null) },
              !!manager && { key: 'manager', label: `${FIELD.manager}: ${manager}`, clear: () => set('manager', null) },
            ]}
            onClearAll={clearFilters}
          />
          {failing ? (
            <ListError error={list.error} what="설치 세션" onRetry={list.reload} retrying={list.loading} />
          ) : !list.data ? (
            <Skeleton rows={6} />
          ) : sessions.length === 0 ? (
            <FirstUse onCopy={() => copy(EXAMPLE_COMMAND)} onGuide={() => setGuide(true)} />
          ) : rows.length === 0 ? (
            status === 'pending' && !manager ? (
              <EmptyState what="판정 대기인 설치 검사" hint="지난 검사는 「전체」에서 볼 수 있습니다." actions={<ClearFiltersButton onClick={() => set('status', 'all')}>전체 보기</ClearFiltersButton>} />
            ) : (
              <NoResults onClear={clearFilters} />
            )
          ) : (
            <>
              <TableToolbar name="installs" total={rows.length} kit={kit} onRefresh={list.reload} refreshing={busy} onExport={() => downloadCSV('supplyguard-installs.csv', kit.csv(rows))} />
              <TableScroll data-fill="" className="min-h-0 flex-1 overflow-auto">
                <table className="sg-table" data-table="installs">
                  <SortHead kit={kit} />
                  <tbody>
                    {view.rows.map((s) => (
                      <Row key={s.id} s={s} kit={kit} pending={isPending(s)} selected={s.id === id} onOpen={() => set('id', s.id)} />
                    ))}
                  </tbody>
                </table>
              </TableScroll>
              <PagerSlot edge={!id}>
                <TablePager name="installs" total={view.total} from={view.from} to={view.to} page={view.page} size={kit.size} onPage={kit.setPage} onSize={kit.setSize} />
              </PagerSlot>
            </>
          )}
        </div>
      </Panel>
      </div>
      <ScreenNote screen="installs" />

      {id && <InstallSheet id={id} onClose={() => set('id', null)} onChanged={list.reload} nav={sheetNav(view.rows.map((s) => s.id), id, (x) => set('id', x))} />}
      {guide && <UsageGuide onClose={() => setGuide(false)} />}
    </div>
  );
}

function Row({ s, kit, pending, selected, onOpen }: { s: InstallSession; kit: TableKit<InstallSession>; pending: boolean; selected: boolean; onOpen: () => void }) {
  const danger = isDangerRow(s); // 11/04: 런타임 격리 · 경고 또는 정적 악성
  // 11/04e 막대: 판정 대기 · 격리 · 경고 · 정적 악성 행만 — 격리 · 정적 악성은 위험색, 나머지(판정 대기 · 경고)는 경고색
  const bar = s.status === 'isolated' || s.scan?.verdict === 'malicious' ? 'danger' : pending || danger ? 'warn' : null;
  return (
    <tr
      {...rowKeys(onOpen)}
      data-install={s.id}
      data-danger={danger || undefined}
      data-bar={bar ?? undefined}
      {...rowState({ open: selected })}
      onClick={onOpen}
      className="cursor-pointer"
    >
      <GridCells kit={kit} row={s} bar={bar} />
    </tr>
  );
}

// 설치 검사가 하나도 없을 때 — 첫 명령 안내
function FirstUse({ onCopy, onGuide }: { onCopy: () => void; onGuide: () => void }) {
  return (
    <EmptyState
      testId="installs-empty"
      what="설치 검사"
      hint="sg-install 명령으로 패키지를 설치하면 감시 컨테이너에서 검사가 시작됩니다."
      actions={
        <div className="flex flex-wrap items-center justify-center gap-2">
          <div className="sg-code flex items-center gap-2 px-3 py-2 font-mono text-xs">
            {EXAMPLE_COMMAND}
            <button type="button" onClick={onCopy} className="rounded p-1 text-text-3 hover:bg-surface-2 hover:text-text" aria-label="명령 복사" title="명령 복사">
              <Copy className="size-3.5" aria-hidden />
            </button>
          </div>
          <button type="button" onClick={onGuide} className="sg-btn sg-btn-sm sg-btn-secondary">
            사용 방법
          </button>
        </div>
      }
    />
  );
}
