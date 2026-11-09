import { useCallback, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { GridCells, SortHead, TablePager, TableScroll } from '../../components/DataTable';
import { fmtLog } from '../../components/list/cell-format';
import { TimeText } from '../../components/list/cells';
import { rowKeys, rowState } from '../../components/list/hooks';
import { EmptyState, ListError, PagerSlot, Skeleton } from '../../components/list/ListStates';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useLoad } from '../../hooks/useLoad';
import { COL_W, useTableKit, type Column } from '../../hooks/useTableKit';
import { api } from '../../lib/api';
import { dest } from '../../lib/nav';
import { detailOf, LEVEL_LABEL, levelOf, type AuditEntry } from '../../lib/types';

// 정책 시트 「차단 이력」 탭(11/09 — 사용자 결정: 이 정책이 판정한 위반 기록): GET /api/audit?rule=<id>&offset=&limit= → {items, total}.
//   rule 은 완전 일치(백엔드 rule_id = $). 기록류라 시각 먼저(초까지) · 컨테이너 · 결과 배지 · 요약, 행 → 감사 로그 그 기록(?id=)
const COLS: Column<AuditEntry>[] = [
  // 기록류 시각(초까지 · 고정폭) — 표준 160 은 안 여백을 빼면 잘린다
  { key: 'at', label: '시각', width: COL_W.log, cell: (a) => <TimeText value={a.event.timestamp} kind="log" />, csv: (a) => fmtLog(a.event.timestamp) },
  { key: 'container', label: '컨테이너', cell: (a) => <span className="font-mono text-[13px] whitespace-nowrap">{a.install ? a.install.label : a.event.containerName}</span> },
  { key: 'result', label: '결과', width: COL_W.status, cell: (a) => <VerdictBadge v={a} />, csv: (a) => LEVEL_LABEL[levelOf(a)] },
  { key: 'detail', label: '요약', fill: true, cell: (a) => <span title={a.reason || detailOf(a.event)}>{a.reason ? `${a.reason} — ${detailOf(a.event)}` : detailOf(a.event)}</span> },
];

export function PolicyHits({ ruleId }: { ruleId: string }) {
  const navigate = useNavigate();
  const kit = useTableKit({ columns: COLS });
  const load = useCallback(() => api.auditPage({ rule: ruleId, offset: (kit.page - 1) * kit.size, limit: kit.size }), [ruleId, kit.page, kit.size]);
  const res = useLoad(load);
  const page = useMemo(() => {
    const d = res.data;
    if (!d) return null;
    return Array.isArray(d) ? { items: d, total: null as number | null } : { items: d.items, total: d.total };
  }, [res.data]);
  if (res.error && !res.data) return <ListError error={res.error} what="차단 이력" onRetry={res.reload} />;
  if (!page) return <Skeleton rows={4} />;
  const from = (kit.page - 1) * kit.size;
  return (
    <div className="flex min-h-full flex-col" data-testid="policy-hits">
      {!page.items.length ? (
        <EmptyState what="차단 이력" hint="이 정책이 판정한 위반 기록이 아직 없습니다." />
      ) : (
        <TableScroll className="min-w-0 overflow-x-auto">
          <table className="sg-table min-w-[560px]" data-table="policy-hits">
            <SortHead kit={kit} />
            <tbody>
              {page.items.map((a) => (
                <tr key={a.id} data-audit={a.id} {...rowState({})} {...rowKeys(() => navigate(`/audit?id=${a.id}`))} onClick={() => navigate(`/audit?id=${a.id}`)} className="cursor-pointer">
                  <GridCells kit={kit} row={a} />
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}
      <div className="mt-auto">
        {page.items.length > 0 && (
          <PagerSlot>
            <TablePager
              name="policy-hits"
              total={page.total}
              from={from + 1}
              to={from + page.items.length}
              page={kit.page}
              size={kit.size}
              onPage={kit.setPage}
              onSize={kit.setSize}
              hasPrev={kit.page > 1}
              hasNext={page.items.length === kit.size}
            />
          </PagerSlot>
        )}
        <p className="px-5 py-3 text-xs">
          <Link {...dest('/audit', { rule: ruleId })} className="text-accent-text hover:underline" data-action="hits-all">
            감사 로그에서 이 정책 기록 모두 보기 ›
          </Link>
        </p>
      </div>
    </div>
  );
}
