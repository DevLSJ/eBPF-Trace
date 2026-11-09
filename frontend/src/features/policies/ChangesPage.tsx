import { ChevronDown, ChevronRight } from 'lucide-react';
import { Fragment, useCallback, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { GridCells, SortHead, TablePager, TableScroll } from '../../components/DataTable';
import { fmtLog } from '../../components/list/cell-format';
import { TimeText } from '../../components/list/cells';
import { downloadCSV } from '../../components/list/csv';
import { rowState, useBusy } from '../../components/list/hooks';
import { EmptyState, ListError, NoResults, PagerSlot, Skeleton } from '../../components/list/ListStates';
import { FilterBar, SearchField } from '../../components/list/SearchField';
import { ScreenNote } from '../../components/ScreenNote';
import { Select } from '../../components/Select';
import { TableToolbar } from '../../components/TableToolbar';
import { useListQuery } from '../../hooks/useListQuery';
import { useLoad } from '../../hooks/useLoad';
import { COL_W, useTableKit, type Column } from '../../hooks/useTableKit';
import { api } from '../../lib/api';
import { screenCopy } from '../../lib/screenCopy';
import type { Change } from '../../lib/types';
import { ActionTag, ChangeDiff } from './ChangeParts';
import { CHANGE_KIND_OPTIONS, changeHasDiff, changeName } from './changeView';

// 변경 이력(11/09 정책 화면 분리 — 옛 정책 화면 아래 칸을 옮김): 정책 · 차단 목록 · 제안 · 시연 · 연결 테스트의 변경 기록 전체(조회만).
//   기록류라 시각 먼저(초까지) · 동작 태그(끝말 색) · 대상 정책(→ 그 정책 시트의 변경 이력 탭) · 처리자 · 내용(요약 · 사유), 줄 펼침 = 바뀐 값 전/후.
//   되돌리기는 정책 상세의 변경 이력 탭 한 곳(같은 기능 두 곳 금지) — 표 아래 안내. 최근 500건(백엔드 상한)을 받아 화면에서 거른다
export function ChangesPage() {
  const lq = useListQuery({ filters: { q: '', kind: '' }, validate: { kind: (v) => CHANGE_KIND_OPTIONS.some((o) => o.value === v) }, sort: { key: 'at', dir: 'desc' } });
  const load = useCallback(() => api.changes(500), []);
  const data = useLoad(load);
  const busy = useBusy(data.loading && !!data.data);
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const toggle = (id: string) => setOpen((s) => (s.has(id) ? new Set([...s].filter((x) => x !== id)) : new Set([...s, id])));

  const columns = useMemo<Column<Change>[]>(
    () => [
      {
        key: 'at',
        label: '시각',
        width: COL_W.time + 32, // 기록류 시각(초까지 · 고정폭) — 표준 160 은 안 여백을 빼면 잘린다
        sort: (c) => c.at,
        cell: (c) => <TimeText value={c.at} kind="log" />,
        csv: (c) => fmtLog(c.at),
      },
      { key: 'action', label: '동작', width: 128, sort: (c) => changeName(c), cell: (c) => <ActionTag change={c} />, csv: (c) => changeName(c) },
      {
        key: 'target',
        label: '대상',
        width: 200,
        cell: (c) => {
          const ids = c.ruleIds ?? [];
          if (!ids.length) return null;
          return (
            <span className="flex min-w-0 items-center gap-1.5" title={ids.join(' · ')}>
              {ids.slice(0, 1).map((id) => (
                <Link key={id} to={`/policies?id=${encodeURIComponent(id)}&tab=changes`} className="truncate font-mono text-[13px] text-accent-text hover:underline">
                  {id}
                </Link>
              ))}
              {ids.length > 1 && <span className="shrink-0 text-xs text-text-3">외 {ids.length - 1}</span>}
            </span>
          );
        },
        csv: (c) => (c.ruleIds ?? []).join(' · ') || null,
      },
      { key: 'by', label: '처리자', width: COL_W.user, sort: (c) => c.by, cell: (c) => c.by || null },
      {
        key: 'summary',
        label: '내용',
        fill: true,
        cell: (c) => (
          <span className="flex min-w-0 items-center gap-1.5">
            {changeHasDiff(c) && (
              <button
                type="button"
                data-action="change-expand"
                aria-expanded={open.has(c.id)}
                aria-label={`바뀐 값 — ${c.id}`}
                title={`바뀐 값 — ${c.id}`}
                onClick={() => toggle(c.id)}
                className="shrink-0 rounded-[var(--r-sm)] p-0.5 text-text-3 hover:bg-surface-2 hover:text-text"
              >
                {open.has(c.id) ? <ChevronDown className="size-4" aria-hidden /> : <ChevronRight className="size-4" aria-hidden />}
              </button>
            )}
            <span className="truncate" title={c.reason ? `${c.summary} · 사유: ${c.reason}` : c.summary}>
              {c.summary}
              {c.reason && <span className="text-text-3"> · 사유: {c.reason}</span>}
            </span>
          </span>
        ),
        csv: (c) => (c.reason ? `${c.summary} · 사유: ${c.reason}` : c.summary),
      },
    ],
    [open],
  );
  const kit = useTableKit<Change>({ columns, grid: 'policies-changes', query: lq.table, sort: { key: 'at', dir: 'desc' } });
  const f = lq.filters;
  const q = f.q.trim().toLowerCase();
  const all = data.data ?? [];
  const list = all.filter(
    (c) => (!f.kind || c.kind === f.kind) && (!q || c.summary.toLowerCase().includes(q) || c.by.toLowerCase().includes(q) || (c.ruleIds ?? []).some((id) => id.includes(q))),
  );
  const view = kit.view(list);
  const span = kit.cols.length;

  return (
    <div className="flex h-full min-h-0 flex-col gap-3" data-screen="policies-changes">
      <p className="shrink-0 text-[13.5px] text-text-3" data-part="screen-copy">
        {screenCopy('policies/changes')}
      </p>
      <FilterBar name="changes" active={lq.active} onClear={lq.clearFilters}>
        <SearchField label="변경 이력 검색" placeholder="내용 · 처리자 · 정책 ID" value={f.q} onApply={(v) => lq.setFilters({ q: v })} />
        <Select name="kind" label="종류" value={f.kind} options={CHANGE_KIND_OPTIONS} onChange={(v) => lq.setFilters({ kind: v })} />
      </FilterBar>
      <div className="sg-card flex min-h-0 flex-1 flex-col overflow-hidden" data-testid="changes">
        <TableToolbar name="changes" total={data.data ? list.length : null} kit={kit} onRefresh={data.reload} refreshing={busy} onExport={() => downloadCSV(`changes-${new Date().toISOString().slice(0, 10)}.csv`, kit.csv(list))} />
        {data.error && !data.data ? (
          <ListError error={data.error} what="변경 이력" onRetry={data.reload} />
        ) : !data.data ? (
          <Skeleton />
        ) : !all.length ? (
          <EmptyState what="변경 이력" hint="정책을 저장하거나 제안을 적용하면 여기에 남습니다." />
        ) : !list.length ? (
          <NoResults onClear={lq.clearFilters} />
        ) : (
          <TableScroll data-fill="" className="min-h-0 flex-1 overflow-auto">
            <table className="sg-table min-w-[760px]" data-table="changes">
              <SortHead kit={kit} />
              <tbody>
                {view.rows.map((c) => (
                  <Fragment key={c.id}>
                    <tr data-change={c.id} {...rowState({ open: open.has(c.id) })}>
                      <GridCells kit={kit} row={c} />
                    </tr>
                    {open.has(c.id) && (
                      <tr data-part="change-diff-row">
                        <td colSpan={span} className="bg-surface-2">
                          <ChangeDiff change={c} forId={c.id} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
        {data.data && list.length > 0 && (
          <PagerSlot>
            <TablePager name="changes" total={view.total} from={view.from} to={view.to} page={view.page} size={kit.size} onPage={kit.setPage} onSize={kit.setSize} />
          </PagerSlot>
        )}
      </div>
      <ScreenNote screen="policies/changes" />
    </div>
  );
}
