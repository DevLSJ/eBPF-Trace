import { Network, Radar, SearchX } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DnsRow } from '../../components/DnsRow';
import { SequenceRow } from '../../components/SequenceRow';
import { EventFeed, PauseToggle } from '../../components/EventFeed';
import { AppliedFilters, ClearFiltersButton, EmptyState, ListError, Skeleton } from '../../components/list/ListStates';
import { useAutoRetry } from '../../components/list/hooks';
import { PageActions } from '../../components/PageActions';
import { Panel } from '../../components/Panel';
import { CodeWindow } from '../../components/CodeWindow';
import { PolicyStarts } from '../../components/PolicyStarts';
import { Section, Sheet } from '../../components/Sheet';
import { sheetNav, type SheetNav } from '../../components/sheet-nav';
import { VerdictBadge } from '../../components/VerdictBadge';
import { KindBadge } from '../../components/KindBadge';
import { useStream } from '../../hooks/stream-context';
import { useFilters } from '../../hooks/useFilters';
import { dest, topologyDest } from '../../lib/nav';
import type { StreamVerdict } from '../../hooks/useEventStream';
import { api } from '../../lib/api';
import { fmtDateTime, fmtNum } from '../../lib/format';
import { isInstallContainer } from '../../lib/topology';
import { detailOf, KIND_LONG, KINDS, levelOf, type Rule } from '../../lib/types';

// 탐지 결과 필터 — 기본은 위반 전체. 「정상 포함」 토글을 켜야 정상 이벤트가 보인다.
type LevelFilter = '' | 'alert' | 'kill';
const levelOptions: { value: LevelFilter; label: string }[] = [
  { value: '', label: '전체' },
  { value: 'alert', label: '경고' },
  { value: 'kill', label: '격리 (대상 포함)' },
];

const ctl = 'h-8 rounded-md border border-slate-300 bg-white px-2 text-sm focus:border-indigo-500 focus:outline-none';

const LEVEL_TEXT: Record<string, string> = { alert: '경고', kill: '격리 (대상 포함)' };

// 이벤트 — 질문 하나: 「지금 무엇이 걸리고 있나?」 실시간만(기간 조회는 감사 로그)
export function EventsPage() {
  // 첫 로드 상태는 셸 스트림 값으로(W20) — 따로 다시 부르지 않는다. 오류 칸의 다시 시도 · 30초 자동 재시도 모두 retryLoad
  const { verdicts, paused, pause, resume, recentLoading, recentError, retryLoad } = useStream();
  const failing = verdicts.length === 0 && recentError != null;
  useAutoRetry(failing, recentError, retryLoad);
  // 필터는 화면 상태로만, 열린 이벤트(id)만 주소에(10/21)
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useFilters('/events');
  const { kind, container } = filters;
  const level = (filters.level as LevelFilter) || '';
  const withNormal = filters.normal === '1';
  const id = params.get('id');

  const set = (k: 'id' | 'kind' | 'level' | 'normal' | 'container', v: string) => {
    if (k !== 'id') return setFilters({ [k]: v });
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next);
  };
  const clearFilters = () => setFilters({ kind: '', level: '', container: '', normal: '' });
  const filtered = !!(kind || level || container || withNormal);

  const rows = useMemo(() => {
    const q = container.toLowerCase();
    return verdicts.filter((v) => {
      if (kind && v.event.kind !== kind) return false;
      if (q && !v.event.containerName.toLowerCase().includes(q)) return false;
      const lv = levelOf(v);
      if (lv === 'normal') return withNormal && level === '';
      if (level === 'alert') return lv === 'alert';
      if (level === 'kill') return lv === 'killed' || lv === 'held';
      return true;
    });
  }, [verdicts, kind, container, level, withNormal]);

  const selected = id ? verdicts.find((v) => String(v.key) === id) : undefined;

  return (
    <div className="flex h-full min-h-0 gap-4">
      <PageActions>
        {/* 머리 칸이 좁으면(768px 등) 일시정지는 목록 필터 줄로 옮긴다(W20) */}
        <PauseToggle paused={paused} onPause={pause} onResume={resume} className="hidden lg:flex" />
        <span className="hidden text-xs whitespace-nowrap text-slate-400 xl:inline">실시간 · 지난 기록은 감사 로그</span>
      </PageActions>
      <Panel
        className="min-w-0 flex-1"
        testId="events"
        title={
          <span>
            실시간 {withNormal ? '이벤트' : '위반'} <span className="num ml-1 font-normal text-slate-400">{fmtNum(rows.length)}건</span>
          </span>
        }
      >
        <div className="flex h-full flex-col">
          <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-slate-100 px-4 py-2.5 text-sm">
            <label className="flex min-w-0 items-center gap-1.5 whitespace-nowrap text-slate-500">
              종류
              <select className={ctl} value={kind} onChange={(e) => set('kind', e.target.value)}>
                <option value="">전체</option>
                {KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k === 'dns' ? `dns (${KIND_LONG.dns})` : k}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex min-w-0 items-center gap-1.5 whitespace-nowrap text-slate-500">
              탐지 결과
              <select className={ctl} value={level} onChange={(e) => set('level', e.target.value)}>
                {levelOptions.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex min-w-0 items-center gap-1.5 whitespace-nowrap text-slate-500">
              컨테이너
              <input className={`${ctl} w-44 min-w-0`} placeholder="이름 검색" value={container} onChange={(e) => set('container', e.target.value)} />
            </label>
            <label className="ml-auto flex cursor-pointer items-center gap-2 text-slate-600 select-none">
              <input type="checkbox" className="accent-indigo-600" checked={withNormal} onChange={(e) => set('normal', e.target.checked ? '1' : '')} />
              정상 포함
            </label>
            <PauseToggle paused={paused} onPause={pause} onResume={resume} className="lg:hidden" />
          </div>
          <AppliedFilters
            items={[
              !!kind && { key: 'kind', label: `종류: ${kind}`, clear: () => set('kind', '') },
              !!level && { key: 'level', label: `탐지 결과: ${LEVEL_TEXT[level] ?? level}`, clear: () => set('level', '') },
              !!container && { key: 'container', label: `컨테이너: ${container}`, clear: () => set('container', '') },
              withNormal && { key: 'normal', label: '정상 포함', clear: () => set('normal', '') },
            ]}
            onClearAll={clearFilters}
          />
          <div className="min-h-0 flex-1">
            {failing ? (
              <ListError error={recentError} what="최근 이벤트" onRetry={retryLoad} />
            ) : verdicts.length === 0 && recentLoading ? (
              <Skeleton rows={8} />
            ) : rows.length === 0 ? (
              verdicts.length && filtered ? (
                <EmptyState icon={SearchX} title={withNormal ? '조건에 맞는 이벤트 없음' : '조건에 맞는 위반 없음'} actions={<ClearFiltersButton onClick={clearFilters} />} />
              ) : (
                <EmptyState
                  icon={Radar}
                  title={withNormal ? '아직 받은 이벤트가 없습니다' : '지금 걸리는 위반 없음'}
                  hint={withNormal ? '감시 중인 컨테이너에서 이벤트가 들어오면 여기에 바로 보입니다' : '「정상 포함」을 켜면 모든 이벤트가 보입니다'}
                />
              )
            ) : (
              <EventFeed full showImage={!id} verdicts={rows} selectedKey={selected?.key} onSelect={(v) => set('id', String(v.key))} />
            )}
          </div>
        </div>
      </Panel>
      {id && <EventSheet v={selected} onClose={() => set('id', '')} nav={sheetNav(rows.map((v) => String(v.key)), id, (k) => set('id', k))} />}
    </div>
  );
}

function EventSheet({ v, onClose, nav }: { v: StreamVerdict | undefined; onClose: () => void; nav?: SheetNav }) {
  return (
    <Sheet kind="event" nav={nav} title="이벤트 상세" onClose={onClose}>
      {!v ? <p className="p-4 text-sm text-slate-500">이 이벤트는 실시간 목록(최근 500건)에서 빠졌습니다. 지난 기록은 감사 로그에서 찾으세요.</p> : <EventDetail v={v} />}
    </Sheet>
  );
}

function EventDetail({ v }: { v: StreamVerdict }) {
  // undefined = 불러오는 중, null = 현재 정책 목록에 없음
  const [found, setFound] = useState<{ id: string; rule: Rule | null } | null>(null);
  const rule = found && found.id === v.ruleId ? found.rule : undefined;
  useEffect(() => {
    const rid = v.ruleId;
    if (!rid) return;
    let cancelled = false;
    api
      .listRules()
      .then((rs) => !cancelled && setFound({ id: rid, rule: rs.find((r) => r.id === rid) ?? null }))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [v.ruleId]);

  const { key: _key, ...verdict } = v;
  void _key;
  const name = v.event.containerName;
  const install = isInstallContainer(name);

  return (
    <div className="text-sm">
      <Section title="요약">
        <dl className="grid grid-cols-[5rem_1fr] gap-x-3 gap-y-1.5">
          <dt className="text-slate-500">탐지 결과</dt>
          <dd>
            <VerdictBadge v={v} />
          </dd>
          <dt className="text-slate-500">시각</dt>
          <dd className="num">{fmtDateTime(v.event.timestamp)}</dd>
          <dt className="text-slate-500">컨테이너</dt>
          <dd className="break-all">{name}</dd>
          <dt className="text-slate-500">이미지</dt>
          <dd className="font-mono text-xs break-all">{v.event.imageName}</dd>
          <dt className="text-slate-500">종류</dt>
          <dd>
            <KindBadge kind={v.event.kind} />
          </dd>
          <dt className="text-slate-500">상세</dt>
          <dd className="font-mono text-xs break-all" data-part="detail">
            {detailOf(v.event)}
          </dd>
          <DnsRow e={v.event} />
          <dt className="text-slate-500">사유</dt>
          <dd>{v.reason ?? '—'}</dd>
          <SequenceRow v={v} />
          {v.enforceError && (
            <>
              <dt className="text-slate-500">격리 오류</dt>
              <dd className="text-red-600">{v.enforceError}</dd>
            </>
          )}
        </dl>
        <div className="mt-3">
          {install ? (
            <Link {...dest('/installs', { status: 'all' })} className="inline-flex items-center gap-1.5 rounded-md border border-indigo-200 px-2.5 py-1 text-xs text-indigo-700 hover:bg-indigo-50">
              설치 검사에서 보기 →
            </Link>
          ) : (
            <Link
              {...topologyDest(name)}
              className="inline-flex items-center gap-1.5 rounded-md border border-indigo-200 px-2.5 py-1 text-xs text-indigo-700 hover:bg-indigo-50"
            >
              <Network className="size-3.5" aria-hidden /> 토폴로지에서 보기
            </Link>
          )}
        </div>
      </Section>
      {v.ruleId && (
        <Section title="관련 정책">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-slate-600">{v.ruleId}</span>
            <Link to={`/policies?id=${encodeURIComponent(v.ruleId)}`} className="text-xs text-indigo-600 hover:underline">
              정책 편집
            </Link>
          </div>
          {rule?.description && <p className="mt-1 text-xs text-slate-500">{rule.description}</p>}
          {rule === null && <p className="mt-1 text-xs text-slate-400">현재 정책 목록에 없음 (삭제·변경됨)</p>}
        </Section>
      )}
      {v.matched && <PolicyStarts event={v.event} ruleId={v.ruleId} />}
      <Section title="원본 JSON">
        {/* 11/04f 코드 창(R1 11/04) — event.json · JSON · 가로 스크롤 */}
        <CodeWindow name="event.json">{JSON.stringify(verdict, null, 2)}</CodeWindow>
      </Section>
    </div>
  );
}
