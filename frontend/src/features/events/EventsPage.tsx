import { Network } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { EventFeed, PauseToggle } from '../../components/EventFeed';
import { PageActions } from '../../components/PageActions';
import { Panel } from '../../components/Panel';
import { PolicyStarts } from '../../components/PolicyStarts';
import { Section, Sheet } from '../../components/Sheet';
import { VerdictBadge } from '../../components/VerdictBadge';
import { KindBadge } from '../../components/KindBadge';
import { useStream } from '../../hooks/stream-context';
import type { StreamVerdict } from '../../hooks/useEventStream';
import { api } from '../../lib/api';
import { fmtDateTime, fmtNum } from '../../lib/format';
import { isInstallContainer } from '../../lib/topology';
import { detailOf, KINDS, levelOf, type Rule } from '../../lib/types';

// 탐지 결과 필터 — 기본은 위반 전체. 「정상 포함」 토글을 켜야 정상 이벤트가 보인다.
type LevelFilter = '' | 'alert' | 'kill';
const levelOptions: { value: LevelFilter; label: string }[] = [
  { value: '', label: '전체' },
  { value: 'alert', label: '경고' },
  { value: 'kill', label: '격리 (대상 포함)' },
];

const ctl = 'h-8 rounded-md border border-slate-300 bg-white px-2 text-sm focus:border-indigo-500 focus:outline-none';

// 이벤트 — 질문 하나: 「지금 무엇이 걸리고 있나?」 실시간만(기간 조회는 감사 로그)
export function EventsPage() {
  const { verdicts, paused, pause, resume } = useStream();
  const [params, setParams] = useSearchParams();
  const kind = params.get('kind') ?? '';
  const level = (params.get('level') as LevelFilter) || '';
  const withNormal = params.get('normal') === '1';
  const container = params.get('container') ?? '';
  const id = params.get('id');

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: k !== 'id' });
  };

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
        <PauseToggle paused={paused} onPause={pause} onResume={resume} />
        <span className="text-xs text-slate-400">실시간 · 지난 기록은 감사 로그</span>
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
            <label className="flex items-center gap-1.5 text-slate-500">
              종류
              <select className={ctl} value={kind} onChange={(e) => set('kind', e.target.value)}>
                <option value="">전체</option>
                {KINDS.map((k) => (
                  <option key={k}>{k}</option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-1.5 text-slate-500">
              탐지 결과
              <select className={ctl} value={level} onChange={(e) => set('level', e.target.value)}>
                {levelOptions.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-1.5 text-slate-500">
              컨테이너
              <input className={`${ctl} w-44`} placeholder="이름 검색" value={container} onChange={(e) => set('container', e.target.value)} />
            </label>
            <label className="ml-auto flex cursor-pointer items-center gap-2 text-slate-600 select-none">
              <input type="checkbox" className="accent-indigo-600" checked={withNormal} onChange={(e) => set('normal', e.target.checked ? '1' : '')} />
              정상 포함
            </label>
          </div>
          <div className="min-h-0 flex-1">
            <EventFeed
              full
              showImage={!id}
              verdicts={rows}
              selectedKey={selected?.key}
              onSelect={(v) => set('id', String(v.key))}
              empty={withNormal ? '조건에 맞는 이벤트 없음' : '지금 걸리는 위반 없음 — 「정상 포함」을 켜면 모든 이벤트가 보입니다'}
            />
          </div>
        </div>
      </Panel>
      {id && <EventSheet v={selected} onClose={() => set('id', '')} />}
    </div>
  );
}

function EventSheet({ v, onClose }: { v: StreamVerdict | undefined; onClose: () => void }) {
  return (
    <Sheet kind="event" title="이벤트 상세" onClose={onClose}>
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
          <dd className="font-mono text-xs break-all">{detailOf(v.event)}</dd>
          <dt className="text-slate-500">사유</dt>
          <dd>{v.reason ?? '—'}</dd>
          {v.enforceError && (
            <>
              <dt className="text-slate-500">격리 오류</dt>
              <dd className="text-red-600">{v.enforceError}</dd>
            </>
          )}
        </dl>
        <div className="mt-3">
          {install ? (
            <Link to="/installs?status=all" className="inline-flex items-center gap-1.5 rounded-md border border-indigo-200 px-2.5 py-1 text-xs text-indigo-700 hover:bg-indigo-50">
              설치 검사에서 보기 →
            </Link>
          ) : (
            <Link
              to={`/topology?container=${encodeURIComponent(name)}&node=${encodeURIComponent(`c:${name}`)}`}
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
        <pre className="overflow-x-auto rounded-md bg-slate-900 p-3 font-mono text-xs leading-relaxed text-slate-100">{JSON.stringify(verdict, null, 2)}</pre>
      </Section>
    </div>
  );
}
