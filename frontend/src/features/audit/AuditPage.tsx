import { RotateCw } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { KindBadge } from '../../components/KindBadge';
import { Empty, Panel } from '../../components/Panel';
import { VerdictBadge } from '../../components/VerdictBadge';
import { api, type AuditParams } from '../../lib/api';
import { fmtDateTime, shortId } from '../../lib/format';
import { detailOf, KINDS, type AuditEntry } from '../../lib/types';

const PAGE = 100;
const ctl = 'h-8 rounded-md border border-slate-300 bg-white px-2 text-sm focus:border-indigo-500 focus:outline-none';

// datetime-local(로컬 시각) → RFC3339
const toIso = (v: string) => (v ? new Date(v).toISOString() : '');

export function AuditPage() {
  const [filters, setFilters] = useState({ kind: '', action: '', rule: '', container: '', since: '', until: '' });
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchPage = useCallback(
    async (before?: number) => {
      setLoading(true);
      try {
        const p: AuditParams = { ...filters, since: toIso(filters.since), until: toIso(filters.until), limit: PAGE, before };
        const page = await api.audit(p);
        setRows((prev) => (before ? [...prev, ...page] : page));
        setHasMore(page.length === PAGE);
        setError('');
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [filters],
  );

  // 필터가 바뀌면 300ms 뒤 첫 페이지부터 다시 조회
  useEffect(() => {
    const t = window.setTimeout(() => void fetchPage(), 300);
    return () => window.clearTimeout(t);
  }, [fetchPage]);

  const set = (k: keyof typeof filters) => (e: { target: { value: string } }) => setFilters((f) => ({ ...f, [k]: e.target.value }));

  return (
    <Panel
      className="h-full min-h-[560px]"
      title="감사 로그 · 위반 판정 이력"
      actions={
        <button
          type="button"
          onClick={() => void fetchPage()}
          className="flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs text-slate-600 hover:bg-slate-100"
        >
          <RotateCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden /> 새로고침
        </button>
      }
    >
      <div className="flex h-full flex-col">
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-slate-100 px-4 py-2.5 text-sm">
          <select className={ctl} value={filters.kind} onChange={set('kind')} aria-label="Kind">
            <option value="">Kind 전체</option>
            {KINDS.map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
          <select className={ctl} value={filters.action} onChange={set('action')} aria-label="대응">
            <option value="">대응 전체</option>
            <option value="alert">alert</option>
            <option value="kill">kill</option>
          </select>
          <input className={`${ctl} w-40`} placeholder="규칙 id" value={filters.rule} onChange={set('rule')} />
          <input className={`${ctl} w-40`} placeholder="컨테이너" value={filters.container} onChange={set('container')} />
          <label className="flex items-center gap-1.5 text-slate-500">
            기간
            <input type="datetime-local" className={ctl} value={filters.since} onChange={set('since')} aria-label="시작" />
            ~
            <input type="datetime-local" className={ctl} value={filters.until} onChange={set('until')} aria-label="끝" />
          </label>
        </div>
        {error && <p className="px-4 py-2 text-sm text-red-600">조회 실패: {error}</p>}
        <div className="min-h-0 flex-1 overflow-auto">
          {rows.length === 0 && !loading ? (
            <Empty>조건에 맞는 기록 없음</Empty>
          ) : (
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-slate-50 text-left text-xs text-slate-500">
                <tr>
                  {['#', '시각', '컨테이너', 'Kind', '상세', '규칙', '판정', '사유'].map((h) => (
                    <th key={h} className="px-3 py-2 font-medium whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id} className="border-b border-slate-100 align-top hover:bg-slate-50">
                    <td className="num px-3 py-2 text-right text-xs text-slate-400">{a.id}</td>
                    <td className="num px-3 py-2 font-mono text-xs whitespace-nowrap text-slate-600">{fmtDateTime(a.event.timestamp)}</td>
                    <td className="px-3 py-2">
                      <div className="font-medium text-slate-800">{a.event.containerName}</div>
                      <div className="font-mono text-xs text-slate-400" title={a.event.imageName}>
                        {shortId(a.event.containerId)} · {a.event.imageName}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <KindBadge kind={a.event.kind} />
                    </td>
                    <td className="max-w-80 truncate px-3 py-2 font-mono text-xs text-slate-600" title={detailOf(a.event)}>
                      {detailOf(a.event)}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs whitespace-nowrap">{a.ruleId}</td>
                    <td className="px-3 py-2">
                      <VerdictBadge v={a} />
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-600">
                      {a.reason}
                      {a.enforceError && <div className="text-red-600">격리 오류: {a.enforceError}</div>}
                    </td>
                  </tr>
                ))}
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
                더 보기
              </button>
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}
