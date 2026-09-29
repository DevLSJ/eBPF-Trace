import { Link } from 'react-router-dom';
import { EventFeed, PauseToggle } from '../../components/EventFeed';
import { KpiCard } from '../../components/KpiCard';
import { Empty, Panel } from '../../components/Panel';
import { TrendChart } from '../../components/TrendChart';
import { useStream } from '../../hooks/stream-context';
import { fmtNum, fmtTime } from '../../lib/format';

export function DashboardPage() {
  const { verdicts, stats, paused, pause, resume } = useStream();
  const risk = stats?.riskScore ?? 0;
  const top = stats?.topContainers ?? [];
  const maxTop = Math.max(1, ...top.map((c) => c.violations));
  const lastKilled = stats?.killed[0];

  return (
    <div className="flex h-full min-h-[640px] flex-col gap-4">
      <div className="grid shrink-0 grid-cols-4 gap-4">
        <KpiCard label="총 이벤트 (1분)" value={fmtNum(stats?.eventsLastMinute ?? 0)} hint={`누적 ${fmtNum(stats?.totalEvents ?? 0)}`} />
        <KpiCard
          label="위반 건수"
          value={fmtNum(stats?.totalViolations ?? 0)}
          tone={stats?.totalViolations ? 'warn' : 'default'}
          hint="서버 기동 이후 누적"
        />
        <KpiCard
          label="격리된 컨테이너"
          value={fmtNum(stats?.killedCount ?? 0)}
          tone={stats?.killedCount ? 'danger' : 'default'}
          hint={
            lastKilled
              ? `최근 ${lastKilled.name} · ${fmtTime(lastKilled.at)}`
              : stats && !stats.enforceKill
                ? 'dry-run — 종료하지 않고 알림만'
                : '격리 기록 없음'
          }
        />
        <KpiCard
          label="위험 점수"
          value={
            <>
              {risk}
              <span className="text-base font-normal text-slate-400"> / 100</span>
            </>
          }
          tone={risk >= 60 ? 'danger' : risk >= 20 ? 'warn' : 'default'}
          hint="최근 5분 위반 가중합 (격리 20 · 격리 대상 12 · 경고 5)"
        />
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)] gap-4">
        <Panel
          title="실시간 이벤트 피드"
          actions={
            <div className="flex items-center gap-3">
              <Link to="/events" className="text-xs text-indigo-600 hover:underline">
                전체 보기
              </Link>
              <PauseToggle paused={paused} onPause={pause} onResume={resume} />
            </div>
          }
        >
          <EventFeed verdicts={verdicts} />
        </Panel>

        <div className="grid min-h-0 grid-rows-[minmax(0,3fr)_minmax(0,2fr)] gap-4">
          <Panel title="시스템콜 추이 (최근 5분)">
            <div className="h-full p-2">
              <TrendChart data={stats?.trend} />
            </div>
          </Panel>
          <Panel title="위반 Top 컨테이너">
            {top.length === 0 ? (
              <Empty>위반 없음</Empty>
            ) : (
              <ul className="space-y-2.5 overflow-y-auto p-4">
                {top.map((c) => (
                  <li key={c.name}>
                    <Link
                      to={`/topology?container=${encodeURIComponent(c.name)}`}
                      className="group grid grid-cols-[8rem_1fr_3rem] items-center gap-3 text-sm"
                      title="토폴로지에서 보기"
                    >
                      <span className="truncate font-medium text-slate-700 group-hover:text-indigo-600">{c.name}</span>
                      <span className="h-2.5 rounded-full bg-slate-100">
                        <span
                          className="block h-full rounded-full bg-red-500"
                          style={{ width: `${(c.violations / maxTop) * 100}%` }}
                        />
                      </span>
                      <span className="num text-right text-slate-600">{fmtNum(c.violations)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
