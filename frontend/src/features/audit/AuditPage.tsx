import { RotateCw } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DecisionBadge } from '../../components/Badges';
import { KindBadge } from '../../components/KindBadge';
import { PageActions } from '../../components/PageActions';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { PolicyStarts } from '../../components/PolicyStarts';
import { Section, Sheet } from '../../components/Sheet';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useCases } from '../../hooks/cases-context';
import { useLoad } from '../../hooks/useLoad';
import { api, type AuditParams } from '../../lib/api';
import { fmtDateTime, shortId } from '../../lib/format';
import { isInstallContainer } from '../../lib/topology';
import { caseLabel, DECISION_LABEL, detailOf, KINDS, type AuditEntry, type Case } from '../../lib/types';

const PAGE = 100;
const ctl = 'h-8 rounded-md border border-slate-300 bg-white px-2 text-sm focus:border-indigo-500 focus:outline-none';
const FILTERS = ['kind', 'action', 'rule', 'container', 'since', 'until'] as const;
type Filters = Record<(typeof FILTERS)[number], string>;

// datetime-local(로컬 시각) → RFC3339
const toIso = (v: string) => (v ? new Date(v).toISOString() : '');

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
  const filtersKey = FILTERS.map((k) => params.get(k) ?? '').join('\u0000');
  const filters = useMemo(() => Object.fromEntries(FILTERS.map((k, i) => [k, filtersKey.split('\u0000')[i]])) as Filters, [filtersKey]);
  const debounced = useDebounced(filters, 300);
  const { cases } = useCases();
  const caseOf = useMemo(() => new Map((cases ?? []).map((c) => [c.id, c])), [cases]);

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: k !== 'id' });
  };

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
                  <select className={ctl} value={filters.kind} onChange={(e) => set('kind', e.target.value)}>
                    <option value="">전체</option>
                    {KINDS.map((k) => (
                      <option key={k}>{k}</option>
                    ))}
                  </select>
                </label>
                <label className="flex items-center gap-1.5 text-slate-500">
                  대응
                  <select className={ctl} value={filters.action} onChange={(e) => set('action', e.target.value)}>
                    <option value="">전체</option>
                    <option value="alert">경고 (alert)</option>
                    <option value="kill">격리 (kill)</option>
                  </select>
                </label>
                <label className="flex items-center gap-1.5 text-slate-500">
                  규칙
                  <input className={`${ctl} w-32`} placeholder="규칙 id" value={filters.rule} onChange={(e) => set('rule', e.target.value)} />
                </label>
                <label className="flex items-center gap-1.5 text-slate-500">
                  컨테이너
                  <input className={`${ctl} w-32`} placeholder="이름" value={filters.container} onChange={(e) => set('container', e.target.value)} />
                </label>
              </>
            )}
            <label className="flex items-center gap-1.5 text-slate-500">
              기간
              <input type="datetime-local" className={ctl} value={filters.since} onChange={(e) => set('since', e.target.value)} aria-label="기간 시작" />
              ~
              <input type="datetime-local" className={ctl} value={filters.until} onChange={(e) => set('until', e.target.value)} aria-label="기간 끝" />
            </label>
          </div>
          {view === 'violations' ? (
            <Violations filters={debounced} caseOf={caseOf} selectedId={id} onOpen={(rid) => set('id', String(rid))} />
          ) : (
            <History cases={cases} since={debounced.since} until={debounced.until} />
          )}
        </div>
      </Panel>
      {view === 'violations' && id && <AuditSheetLoader id={Number(id)} caseOf={caseOf} onClose={() => set('id', '')} />}
    </div>
  );
}

// 시트는 목록에서 찾는다(목록 상태를 공유하려고 전역 캐시에 둔다)
const rowCache = new Map<number, AuditEntry>();

function Violations({
  filters,
  caseOf,
  selectedId,
  onOpen,
}: {
  filters: Filters;
  caseOf: Map<string, Case>;
  selectedId: string | null;
  onOpen: (id: number) => void;
}) {
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
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

  return (
    <>
      {!!error && <LoadError error={error} what="감사 로그" compact />}
      <div className="min-h-0 flex-1 overflow-auto" data-testid="audit-scroll">
        {rows.length === 0 && !loading ? (
          <Empty>조건에 맞는 기록 없음</Empty>
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10 bg-slate-50 text-left text-xs text-slate-500">
              <tr>
                {['#', '시각', '컨테이너 · 패키지', '종류', '상세', '규칙', '탐지 결과', '판정'].map((h) => (
                  <th key={h} className="px-3 py-2 font-medium whitespace-nowrap">
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
                    tabIndex={0}
                    data-audit={a.id}
                    aria-selected={String(a.id) === selectedId}
                    onClick={() => onOpen(a.id)}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), onOpen(a.id))}
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
              <RotateCw className={`mr-1 inline size-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden />더 보기
            </button>
          </div>
        )}
      </div>
    </>
  );
}

function AuditSheetLoader({ id, caseOf, onClose }: { id: number; caseOf: Map<string, Case>; onClose: () => void }) {
  // 목록에 없으면(직접 연 주소) 그 id 바로 앞에서 한 건을 다시 찾는다
  const cached = rowCache.get(id);
  const load = useCallback(() => (cached ? Promise.resolve([cached]) : api.audit({ before: id + 1, limit: 1 })), [cached, id]);
  const r = useLoad(load);
  const a = r.data?.find((x) => x.id === id);
  return (
    <Sheet kind="audit" title={`감사 기록 #${id}`} onClose={onClose}>
      {a ? <AuditDetail a={a} c={a.caseId ? caseOf.get(a.caseId) : undefined} /> : r.error ? <LoadError error={r.error} what="감사 기록" /> : <Empty>{r.loading ? '불러오는 중…' : '기록을 찾을 수 없습니다'}</Empty>}
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
          {a.enforceError && (
            <>
              <dt className="text-slate-500">격리 오류</dt>
              <dd className="text-red-600">{a.enforceError}</dd>
            </>
          )}
          <dt className="text-slate-500">규칙</dt>
          <dd className="font-mono text-xs">{a.ruleId}</dd>
          <dt className="text-slate-500">상세</dt>
          <dd className="font-mono text-xs break-all">{detailOf(a.event)}</dd>
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
                <Link to={`/installs?status=all&id=${encodeURIComponent(a.install?.id ?? c.installId ?? '')}`} className="text-indigo-600 hover:underline">
                  설치 검사에서 보기 →
                </Link>
              ) : (
                <Link to={`/topology?container=${encodeURIComponent(name)}&node=${encodeURIComponent(`c:${name}`)}`} className="text-indigo-600 hover:underline">
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
function History({ cases, since, until }: { cases: Case[] | null; since: string; until: string }) {
  const load = useCallback(() => api.changes(500), []);
  const changes = useLoad(load);
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
        text: `${c.source === 'install' ? '설치 검사' : '런타임'} ${caseLabel(c)} — ${DECISION_LABEL[c.decision]}${c.note ? ` · ${c.note}` : ''}`,
        by: c.decidedBy ?? '—',
      })),
    ...(changes.data ?? []).map((ch) => ({
      key: `chg:${ch.id}`,
      at: ch.at,
      kind: ch.kind === 'proposal_applied' ? '제안 적용' : ch.kind === 'policy_edit' ? '정책 편집' : ch.kind === 'policy_replace' ? 'YAML 교체' : ch.kind,
      badge: null,
      text: ch.summary,
      by: ch.by,
    })),
  ]
    .filter((x) => inRange(x.at))
    .sort((a, b) => b.at.localeCompare(a.at));

  return (
    <>
      {!!changes.error && <LoadError error={changes.error} what="변경 이력" compact />}
      <div className="min-h-0 flex-1 overflow-auto" data-testid="history">
        {items.length === 0 ? (
          <Empty>판정 · 변경 기록 없음</Empty>
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10 bg-slate-50 text-left text-xs text-slate-500">
              <tr>
                {['시각', '종류', '내용', '처리자'].map((h) => (
                  <th key={h} className="px-3 py-2 font-medium whitespace-nowrap">
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
                  <td className="px-3 py-2 text-slate-700">{x.text}</td>
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
