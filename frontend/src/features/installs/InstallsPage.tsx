import { Copy, PackageSearch, SearchX } from 'lucide-react';
import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DecisionBadge, StatusBadge } from '../../components/Badges';
import { FilterChips } from '../../components/FilterChips';
import { PageActions } from '../../components/PageActions';
import { Panel } from '../../components/Panel';
import { AppliedFilters, ClearFiltersButton, EmptyState, ListError, Skeleton } from '../../components/list/ListStates';
import { rowKeys, useAutoRetry } from '../../components/list/hooks';
import { useCases } from '../../hooks/cases-context';
import { useFilters } from '../../hooks/useFilters';
import { useCopyCommand } from '../../hooks/useCopyCommand';
import { useInterval, useLoad, useNow } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { fmtDateTime, fmtNum, fmtTime, isToday } from '../../lib/format';
import { duration, EXAMPLE_COMMAND, sessionLabel, violationTotal } from '../../lib/pkg';
import { INSTALL_STATUS_LABEL, INSTALL_STATUSES, MANAGERS, type Case, type InstallSession } from '../../lib/types';
import { InstallSheet } from './InstallSheet';

// 결과 칩: 기본 「판정 대기」(목표 문서 완료 기준 ①), 그다음 전체 · 설치 결과별
type StatusFilter = 'pending' | 'all' | (typeof INSTALL_STATUSES)[number];

// 설치 검사 — 질문 하나: 「이 패키지는 무엇을 하려 했고, 악성인가?」
export function InstallsPage() {
  // 필터(결과 · 매니저)는 화면 상태로만, 열린 세션(id)만 주소에(10/21)
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useFilters('/installs');
  const status = (filters.status as StatusFilter) || 'pending';
  const manager = filters.manager;
  const id = params.get('id');
  const { cases } = useCases();
  const copy = useCopyCommand();
  const now = useNow();

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

  const set = (k: 'id' | 'status' | 'manager', v: string | null) => {
    if (k !== 'id') return setFilters({ [k]: v ?? '' });
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next);
  };
  const clearFilters = () => setFilters({ status: '', manager: '' });

  const caseOf = useMemo(() => new Map((cases ?? []).map((c) => [c.id, c])), [cases]);
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
  const managerOptions = [
    { value: '', label: '전체', count: sessions.length },
    ...MANAGERS.map((m) => ({ value: m as string, label: m, count: sessions.filter((s) => s.manager === m).length })),
  ];

  return (
    <div className="flex h-full min-h-0 gap-4">
      <PageActions>
        <button
          type="button"
          onClick={() => copy(EXAMPLE_COMMAND)}
          className="flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs text-slate-600 hover:bg-slate-100"
          title={EXAMPLE_COMMAND}
        >
          <Copy className="size-3.5" aria-hidden /> 명령 복사
        </button>
        <span className="truncate text-xs text-slate-400">설치는 CLI(sg-install)로만 실행합니다</span>
      </PageActions>

      <Panel
        className="min-w-0 flex-1"
        testId="installs"
        title={
          <span>
            설치 세션 <span className="num ml-1 font-normal text-slate-400">{fmtNum(rows.length)}건</span>
          </span>
        }
      >
        <div className="flex h-full flex-col">
          <div className="grid shrink-0 gap-2 border-b border-slate-100 px-4 py-2.5">
            <FilterChips label="결과" options={statusOptions} value={status} onChange={(v) => set('status', v === 'pending' ? null : v)} />
            <FilterChips label="매니저" options={managerOptions} value={manager} onChange={(v) => set('manager', v || null)} />
          </div>
          <AppliedFilters
            items={[
              status !== 'pending' && { key: 'status', label: `결과: ${status === 'all' ? '전체' : (INSTALL_STATUS_LABEL[status] ?? status)}`, clear: () => set('status', null) },
              !!manager && { key: 'manager', label: `매니저: ${manager}`, clear: () => set('manager', null) },
            ]}
            onClearAll={clearFilters}
          />
          {failing ? (
            <ListError error={list.error} what="설치 세션" onRetry={list.reload} retrying={list.loading} />
          ) : !list.data ? (
            <Skeleton rows={6} />
          ) : sessions.length === 0 ? (
            <FirstUse onCopy={() => copy(EXAMPLE_COMMAND)} />
          ) : rows.length === 0 ? (
            status === 'pending' && !manager ? (
              <EmptyState icon={PackageSearch} title="판정 대기인 설치가 없습니다" hint="「전체」에서 지난 검사를 볼 수 있습니다" actions={<ClearFiltersButton onClick={() => set('status', 'all')}>전체 보기</ClearFiltersButton>} />
            ) : (
              <EmptyState icon={SearchX} title="조건에 맞는 세션 없음" actions={<ClearFiltersButton onClick={clearFilters} />} />
            )
          ) : (
            <div className="min-h-0 flex-1 overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 z-10 bg-slate-50 text-left text-xs text-slate-500">
                  <tr>
                    {['시작', '매니저', '패키지', '설치 결과', '판정', '위반', '걸린 시간'].map((h) => (
                      <th key={h} className="px-3 py-2 font-semibold whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((s) => (
                    <Row key={s.id} s={s} now={now} c={s.caseId ? caseOf.get(s.caseId) : undefined} selected={s.id === id} onOpen={() => set('id', s.id)} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Panel>

      {id && <InstallSheet id={id} onClose={() => set('id', null)} onChanged={list.reload} />}
    </div>
  );
}

function Row({ s, c, now, selected, onOpen }: { s: InstallSession; c: Case | undefined; now: number; selected: boolean; onOpen: () => void }) {
  const n = violationTotal(s);
  const danger = s.status === 'isolated' || s.status === 'warned';
  return (
    <tr
      {...rowKeys(onOpen)}
      data-install={s.id}
      aria-selected={selected}
      onClick={onOpen}
      className={`cursor-pointer border-b border-slate-100 hover:bg-slate-50 focus:outline-2 focus:-outline-offset-2 focus:outline-indigo-500 ${
        selected ? 'bg-indigo-50' : ''
      } ${danger ? 'shadow-[inset_3px_0_0_var(--color-red-500)]' : ''}`}
    >
      <td className="num px-3 py-2 font-mono text-xs whitespace-nowrap text-slate-600" title={fmtDateTime(s.startedAt)}>
        {isToday(s.startedAt, now) ? fmtTime(s.startedAt) : fmtDateTime(s.startedAt)}
      </td>
      <td className="px-3 py-2">
        <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-600">{s.manager}</span>
      </td>
      <td className="w-full max-w-0 truncate px-3 py-2 font-mono text-slate-800" title={sessionLabel(s)}>
        {sessionLabel(s)}
      </td>
      <td className="px-3 py-2">
        <StatusBadge status={s.status} />
      </td>
      <td className="px-3 py-2">{c ? <DecisionBadge decision={c.decision} /> : <span className="text-xs text-slate-300">—</span>}</td>
      <td className={`num px-3 py-2 text-right whitespace-nowrap ${n ? 'font-semibold text-red-600' : 'text-slate-400'}`}>{n === undefined ? '—' : fmtNum(n)}</td>
      <td className="num px-3 py-2 text-xs whitespace-nowrap text-slate-500">
        {s.status === 'running' ? '진행 중' : s.status === 'refused' ? '—' : duration(s.startedAt, s.finishedAt ?? s.containerExitedAt)}
      </td>
    </tr>
  );
}

// 설치 검사가 하나도 없을 때 — 첫 명령 안내
function FirstUse({ onCopy }: { onCopy: () => void }) {
  return (
    <EmptyState
      testId="installs-empty"
      icon={PackageSearch}
      title="아직 설치 검사가 없습니다"
      hint="개발자가 패키지를 설치할 때 감시 컨테이너에서 실행합니다. 위반이면 설치가 끝나기 전에 격리됩니다."
      actions={
        <div className="sg-code flex items-center gap-2 px-3 py-2 font-mono text-xs">
          {EXAMPLE_COMMAND}
          <button type="button" onClick={onCopy} className="rounded p-1 text-text-3 hover:bg-surface-2 hover:text-text" aria-label="명령 복사">
            <Copy className="size-3.5" />
          </button>
        </div>
      }
    />
  );
}
