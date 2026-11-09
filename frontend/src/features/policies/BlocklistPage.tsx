import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { GridCells, SortHead, TablePager, TableScroll } from '../../components/DataTable';
import { fmtLog } from '../../components/list/cell-format';
import { TimeText } from '../../components/list/cells';
import { downloadCSV } from '../../components/list/csv';
import { rowState, useBusy } from '../../components/list/hooks';
import { EmptyState, ListError, NoResults, PagerSlot, Skeleton } from '../../components/list/ListStates';
import { FilterBar, SearchField } from '../../components/list/SearchField';
import { ConfirmDialog } from '../../components/Modal';
import { ScreenNote } from '../../components/ScreenNote';
import { Select } from '../../components/Select';
import { TableToolbar } from '../../components/TableToolbar';
import { useAuth } from '../../hooks/auth-context';
import { useToast } from '../../hooks/toast-context';
import { useListQuery } from '../../hooks/useListQuery';
import { useLoad } from '../../hooks/useLoad';
import { COL_W, useTableKit, type Column } from '../../hooks/useTableKit';
import { api, ApiError, errorText } from '../../lib/api';
import { screenCopy } from '../../lib/screenCopy';
import type { BlockEntry, BlockList } from '../../lib/types';

// 차단 목록(11/09 정책 화면 분리 — 옛 정책 화면 아래 칸을 옮김, 기능 그대로): 악성 확정으로 막은 패키지 · 이미지 · 도메인.
//   패키지는 sg-install 이 설치 전에, 이미지는 기동 때, 도메인은 시스템 규칙 blocklist-hosts 가 막는다. 해제는 관리자(사유 → 변경 이력)
const LISTS: { value: BlockList; label: string }[] = [
  { value: 'packages', label: '패키지' },
  { value: 'images', label: '이미지' },
  { value: 'hosts', label: '도메인' },
];
const LABEL = Object.fromEntries(LISTS.map((l) => [l.value, l.label])) as Record<BlockList, string>;
// 해제하면 함께 일어나는 일(10/20 B)
const UNBLOCK_IMPACT: Record<BlockList, (v: string) => string> = {
  packages: (v) => `다음 설치부터 ${v} 를 다시 설치할 수 있습니다. 설치 검사는 그대로 감시합니다.`,
  images: (v) => `이미지 ${v} 로 시작하는 컨테이너가 다음 기동부터 다시 뜹니다.`,
  hosts: (v) => `시스템 규칙 blocklist-hosts 에서 ${v} 를 빼 바로 통신을 허용합니다.`,
};
type Row = BlockEntry & { list: BlockList };
// 기록류 시각(초까지 · 고정폭 13.5px) 칸 — 표준 160 은 안 여백 16 × 2 를 빼면 「YYYY-MM-DD HH:mm:ss」가 잘린다
const LOG_W = COL_W.log;

export function BlocklistPage() {
  const { isAdmin: canWrite } = useAuth();
  const toast = useToast();
  const lq = useListQuery({ filters: { q: '', list: '' }, validate: { list: (v) => LISTS.some((l) => l.value === v) }, sort: { key: 'at', dir: 'desc' } });
  const data = useLoad(api.blocklist);
  const busy = useBusy(data.loading && !!data.data);
  const [ask, setAsk] = useState<Row | null>(null);

  const columns = useMemo<Column<Row>[]>(
    () => [
      { key: 'list', label: '종류', width: 96, sort: (r) => r.list, cell: (r) => LABEL[r.list], csv: (r) => LABEL[r.list] },
      { key: 'value', label: '값', fill: true, sort: (r) => r.value, cell: (r) => <span className="font-mono text-[13px]" title={r.value}>{r.value}</span>, csv: (r) => r.value },
      { key: 'at', label: '차단 시각', width: LOG_W, sort: (r) => r.at, cell: (r) => <TimeText value={r.at} kind="log" />, csv: (r) => fmtLog(r.at) },
      { key: 'by', label: '처리자', width: COL_W.user, sort: (r) => r.by, cell: (r) => r.by || null },
      {
        key: 'case',
        label: '근거 건',
        width: COL_W.id,
        sort: (r) => r.caseId ?? '',
        cell: (r) =>
          r.caseId ? (
            <Link to={`/report?case=${encodeURIComponent(r.caseId)}`} className="font-mono text-[13px] text-accent-text hover:underline" onClick={(e) => e.stopPropagation()}>
              {r.caseId}
            </Link>
          ) : null,
        csv: (r) => r.caseId ?? null,
      },
      ...(canWrite
        ? [
            {
              key: 'act',
              label: '',
              fixed: true,
              stick: 'end' as const,
              cell: (r: Row) => (
                <button type="button" aria-label={`해제 — ${r.value}`} title={`해제 — ${r.value}`} onClick={() => setAsk(r)} className="sg-btn sg-btn-sm sg-btn-secondary">
                  해제
                </button>
              ),
            },
          ]
        : []),
    ],
    [canWrite],
  );
  const kit = useTableKit<Row>({ columns, grid: 'policies-blocklist', query: lq.table, sort: { key: 'at', dir: 'desc' } });
  const rows = useMemo<Row[]>(() => (data.data ? LISTS.flatMap((l) => (data.data![l.value] ?? []).map((e) => ({ ...e, list: l.value }))) : []), [data.data]);
  const f = lq.filters;
  const q = f.q.trim().toLowerCase();
  const list = rows.filter((r) => (!f.list || r.list === f.list) && (!q || r.value.toLowerCase().includes(q) || (r.by ?? '').toLowerCase().includes(q)));
  const view = kit.view(list);

  const unblock = async (r: Row, reason: string) => {
    try {
      await api.unblock(r.list, r.value, reason);
      toast(`${r.value} 차단을 해제했습니다.`, { key: `unblock:${r.value}`, tone: 'ok' });
      data.reload();
    } catch (e) {
      toast(`차단을 해제하지 못했습니다 — ${e instanceof ApiError ? e.message : errorText(e)}`, { key: `unblock:${r.value}`, tone: 'danger' });
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-3" data-screen="policies-blocklist">
      <p className="shrink-0 text-[13.5px] text-text-3" data-part="screen-copy">
        {screenCopy('policies/blocklist')}
      </p>
      <FilterBar name="blocklist" active={lq.active} onClear={lq.clearFilters}>
        <SearchField label="차단 목록 검색" placeholder="값 · 처리자" value={f.q} onApply={(v) => lq.setFilters({ q: v })} />
        <Select name="list" label="종류" value={f.list} options={LISTS} onChange={(v) => lq.setFilters({ list: v })} />
      </FilterBar>
      <div className="sg-card flex min-h-0 flex-1 flex-col overflow-hidden" data-testid="blocklist">
        <TableToolbar name="blocklist" total={data.data ? list.length : null} kit={kit} onRefresh={data.reload} refreshing={busy} onExport={() => downloadCSV(`blocklist-${new Date().toISOString().slice(0, 10)}.csv`, kit.csv(list))} />
        {data.error && !data.data ? (
          <ListError error={data.error} what="차단 목록" onRetry={data.reload} />
        ) : !data.data ? (
          <Skeleton />
        ) : !rows.length ? (
          <EmptyState what="차단 목록" hint="설치 검사 · 토폴로지에서 악성 확정한 제안을 적용하면 여기에 생깁니다." />
        ) : !list.length ? (
          <NoResults onClear={lq.clearFilters} />
        ) : (
          <TableScroll data-fill="" className="min-h-0 flex-1 overflow-auto">
            <table className="sg-table min-w-[640px]" data-table="blocklist">
              <SortHead kit={kit} />
              <tbody>
                {view.rows.map((r) => (
                  <tr key={`${r.list}:${r.value}`} data-block={`${r.list}:${r.value}`} {...rowState({})}>
                    <GridCells kit={kit} row={r} />
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
        {data.data && list.length > 0 && (
          <PagerSlot>
            <TablePager name="blocklist" total={view.total} from={view.from} to={view.to} page={view.page} size={kit.size} onPage={kit.setPage} onSize={kit.setSize} />
          </PagerSlot>
        )}
      </div>
      <ScreenNote screen="policies/blocklist" />
      {ask && (
        <ConfirmDialog
          title={`${ask.value} 차단을 해제할까요?`}
          body={`${LABEL[ask.list]} 차단 목록에서 빼고 바로 적용합니다.`}
          impact={[UNBLOCK_IMPACT[ask.list](ask.value), '변경 이력에 「차단 해제」로 남습니다.']}
          reason
          confirmLabel="해제"
          danger
          onCancel={() => setAsk(null)}
          onConfirm={(reason) => {
            const r = ask;
            setAsk(null);
            void unblock(r, reason);
          }}
        />
      )}
    </div>
  );
}
