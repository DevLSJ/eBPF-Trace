import { X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { EventFeed, PauseToggle } from '../../components/EventFeed';
import { Panel } from '../../components/Panel';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useStream } from '../../hooks/stream-context';
import type { StreamVerdict } from '../../hooks/useEventStream';
import { api } from '../../lib/api';
import { fmtDateTime, fmtNum } from '../../lib/format';
import { KINDS, levelOf, type Rule } from '../../lib/types';

type VerdictFilter = 'all' | 'normal' | 'violation' | 'alert' | 'kill';
type Period = 'live' | '1h' | '24h';

const verdictOptions: { value: VerdictFilter; label: string }[] = [
  { value: 'all', label: '전체' },
  { value: 'normal', label: '정상' },
  { value: 'violation', label: '위반 전체' },
  { value: 'alert', label: '경고' },
  { value: 'kill', label: '격리 (대상 포함)' },
];

const select = 'h-8 rounded-md border border-slate-300 bg-white px-2 text-sm focus:border-indigo-500 focus:outline-none';

export function EventsPage() {
  const { verdicts, paused, pause, resume } = useStream();
  const [params, setParams] = useSearchParams();
  const kind = params.get('kind') ?? '';
  const verdict = (params.get('verdict') as VerdictFilter) || 'all';
  const container = params.get('container') ?? '';
  const period = (params.get('period') as Period) || 'live';
  const [selected, setSelected] = useState<StreamVerdict | null>(null);
  const [history, setHistory] = useState<StreamVerdict[]>([]);
  const [error, setError] = useState('');

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v && v !== 'all' && v !== 'live') next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };

  // 1h/24h: 감사 로그(위반만 저장됨)에서 조회
  useEffect(() => {
    if (period === 'live') return;
    const since = new Date(Date.now() - (period === '1h' ? 3600e3 : 86400e3)).toISOString();
    let cancelled = false;
    api
      .audit({ since, kind, container, limit: 500, action: verdict === 'alert' || verdict === 'kill' ? verdict : '' })
      .then((rows) => {
        if (cancelled) return;
        setHistory(rows.map((r) => ({ ...r, key: -r.id })));
        setError('');
      })
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [period, kind, container, verdict]);

  const rows = useMemo(() => {
    const src = period === 'live' ? verdicts : history;
    const q = container.toLowerCase();
    return src.filter((v) => {
      if (kind && v.event.kind !== kind) return false;
      if (q && !v.event.containerName.toLowerCase().includes(q)) return false;
      const level = levelOf(v);
      switch (verdict) {
        case 'normal':
          return level === 'normal';
        case 'violation':
          return level !== 'normal';
        case 'alert':
          return level === 'alert';
        case 'kill':
          return level === 'killed' || level === 'held';
      }
      return true;
    });
  }, [period, verdicts, history, kind, container, verdict]);

  return (
    <div className="flex h-full min-h-[560px] gap-4">
      <Panel
        className="min-w-0 flex-1"
        title={
          <span>
            이벤트 · 판정 스트림 <span className="num ml-1 font-normal text-slate-400">{fmtNum(rows.length)}건</span>
          </span>
        }
        actions={period === 'live' && <PauseToggle paused={paused} onPause={pause} onResume={resume} />}
      >
        <div className="flex h-full flex-col">
          <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-slate-100 px-4 py-2.5 text-sm">
            <label className="flex items-center gap-1.5 text-slate-500">
              Kind
              <select className={select} value={kind} onChange={(e) => set('kind', e.target.value)}>
                <option value="">전체</option>
                {KINDS.map((k) => (
                  <option key={k}>{k}</option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-1.5 text-slate-500">
              판정
              <select className={select} value={verdict} onChange={(e) => set('verdict', e.target.value)}>
                {verdictOptions.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <input
              className={`${select} w-44`}
              placeholder="컨테이너 검색"
              value={container}
              onChange={(e) => set('container', e.target.value)}
            />
            <div className="ml-auto flex rounded-md border border-slate-300 p-0.5" role="group" aria-label="기간">
              {(['live', '1h', '24h'] as Period[]).map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => set('period', p)}
                  className={`rounded px-3 py-1 text-xs font-medium ${period === p ? 'bg-indigo-600 text-white' : 'text-slate-600 hover:bg-slate-100'}`}
                >
                  {p === 'live' ? '실시간' : p}
                </button>
              ))}
            </div>
          </div>
          {period !== 'live' && (
            <div className="shrink-0 bg-slate-50 px-4 py-1.5 text-xs text-slate-500">
              기간 조회는 감사 로그에 저장된 위반 판정만 보여 줍니다.{error && <span className="ml-2 text-red-600">조회 실패: {error}</span>}
            </div>
          )}
          <div className="min-h-0 flex-1">
            <EventFeed
              full
              showImage={!selected}
              verdicts={rows}
              selectedKey={selected?.key}
              onSelect={setSelected}
              empty={period === 'live' ? '조건에 맞는 이벤트 없음' : '해당 기간 위반 없음'}
            />
          </div>
        </div>
      </Panel>
      {selected && <DetailPanel v={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function DetailPanel({ v, onClose }: { v: StreamVerdict; onClose: () => void }) {
  // undefined = 불러오는 중, null = 현재 정책 목록에 없음
  const [found, setFound] = useState<{ id: string; rule: Rule | null } | null>(null);
  const rule = found && found.id === v.ruleId ? found.rule : undefined;
  useEffect(() => {
    const id = v.ruleId;
    if (!id) return;
    let cancelled = false;
    api
      .listRules()
      .then((rs) => !cancelled && setFound({ id, rule: rs.find((r) => r.id === id) ?? null }))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [v.ruleId]);

  const { key: _key, ...verdict } = v;
  void _key;

  return (
    <Panel
      className="w-[400px] shrink-0"
      title="이벤트 상세"
      actions={
        <button type="button" onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700" aria-label="닫기">
          <X className="size-4" />
        </button>
      }
    >
      <div className="h-full space-y-4 overflow-y-auto p-4 text-sm">
        <dl className="grid grid-cols-[5.5rem_1fr] gap-x-3 gap-y-1.5">
          <dt className="text-slate-500">판정</dt>
          <dd>
            <VerdictBadge v={v} />
          </dd>
          <dt className="text-slate-500">시각</dt>
          <dd className="num">{fmtDateTime(v.event.timestamp)}</dd>
          <dt className="text-slate-500">컨테이너</dt>
          <dd className="break-all">{v.event.containerName}</dd>
          <dt className="text-slate-500">사유</dt>
          <dd>{v.reason ?? '—'}</dd>
          {v.enforceError && (
            <>
              <dt className="text-slate-500">격리 오류</dt>
              <dd className="text-red-600">{v.enforceError}</dd>
            </>
          )}
        </dl>
        {v.ruleId && (
          <div className="rounded-md border border-slate-200 p-3">
            <div className="mb-1 flex items-center justify-between">
              <span className="font-medium">관련 정책</span>
              <Link to={`/policies?id=${encodeURIComponent(v.ruleId)}`} className="text-xs text-indigo-600 hover:underline">
                정책 편집
              </Link>
            </div>
            <div className="font-mono text-xs text-slate-600">{v.ruleId}</div>
            {rule?.description && <p className="mt-1 text-xs text-slate-500">{rule.description}</p>}
            {rule === null && <p className="mt-1 text-xs text-slate-400">현재 정책 목록에 없음 (삭제·변경됨)</p>}
          </div>
        )}
        <div>
          <div className="mb-1 font-medium">원본 JSON</div>
          <pre className="overflow-x-auto rounded-md bg-slate-900 p-3 font-mono text-xs leading-relaxed text-slate-100">
            {JSON.stringify(verdict, null, 2)}
          </pre>
        </div>
      </div>
    </Panel>
  );
}
