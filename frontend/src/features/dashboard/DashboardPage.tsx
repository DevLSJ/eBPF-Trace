import { ChevronRight, CircleCheck, FileText } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { Overview } from './Overview';
import { DemoPanel } from './DemoPanel';
import { SignalPills } from './SignalPills';
import { LevelBadge } from '../../components/VerdictBadge';
import { useAuth } from '../../hooks/auth-context';
import { useCases } from '../../hooks/cases-context';
import { useStream } from '../../hooks/stream-context';
import { fmtNum, fmtTime } from '../../lib/format';
import { scanHref, SOURCE_LABEL } from '../../lib/guide';
import { installDest, topologyDest } from '../../lib/nav';
import { caseLabel, type Case } from '../../lib/types';

// 대시보드 — 「지금 처리할 일이 있나?」(판정 대기) + 「지금까지 무엇을 수집 · 탐지했나?」(eBPF 수집 종합, 10/16)
// 낮은 화면(768px 폭 등)에서는 판정 대기가 최소 7rem 을 지키고 수집 종합이 제 칸 안에서 스크롤한다(W20)
// 10/30: 맨 위 상태 신호등 한 줄(계약 §5) · 그 아래 「시연」 카드(관리자 + /api/info.demo 일 때만, §4) · 판정 대기 · 종합
export function DashboardPage() {
  const { cases, error } = useCases();
  const { info } = useStream();
  const { isAdmin } = useAuth();
  const demo = isAdmin && info?.demo === true;

  const pending = (cases ?? []).filter((c) => c.state === 'open').sort((a, b) => b.openedAt.localeCompare(a.openedAt));
  const awaitingApply = (cases ?? []).filter((c) => c.state === 'decided').length;

  return (
    <div className={`grid h-full min-h-0 gap-4 ${demo ? 'grid-rows-[auto_auto_minmax(7rem,1fr)_minmax(0,auto)]' : 'grid-rows-[auto_minmax(7rem,1fr)_minmax(0,auto)]'}`}>
      <SignalPills />
      {demo && <DemoPanel />}
      <Panel
        testId="pending"
        title={
          <span className="flex items-baseline gap-2">
            판정 대기
            <b className={`num text-lg ${pending.length ? 'text-amber-600' : 'text-slate-400'}`} data-testid="pending-count">
              {cases ? pending.length : '—'}
            </b>
          </span>
        }
        actions={
          awaitingApply > 0 && (
            <Link to="/policies" className="text-xs text-indigo-600 hover:underline" data-testid="awaiting-apply">
              적용 대기 제안 {awaitingApply}건 → 정책
            </Link>
          )
        }
      >
        {error && !cases ? (
          <LoadError error={error} what="건(판정 대기)" />
        ) : !cases ? (
          <Empty>불러오는 중…</Empty>
        ) : pending.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 text-slate-500" data-testid="nothing-to-do">
            <CircleCheck className="size-8 text-emerald-500" aria-hidden />
            <b className="text-base text-slate-700">처리할 일 없음</b>
            <span className="text-sm">설치 검사 · 런타임 감시가 계속 돌고 있습니다.</span>
          </div>
        ) : (
          <ul data-fill="" className="h-full overflow-y-auto" data-testid="pending-list">
            {pending.map((c) => (
              <PendingRow key={c.id} c={c} />
            ))}
          </ul>
        )}
      </Panel>

      <Overview />
    </div>
  );
}

function PendingRow({ c }: { c: Case }) {
  const sh = scanHref(c);
  const to = c.source === 'install' && c.installId ? installDest(c.installId, 'pending') : sh ? { to: sh } : topologyDest(c.container);
  const chip = c.source === 'install' ? 'bg-indigo-50 text-indigo-700' : c.source === 'scan' ? 'bg-amber-50 text-amber-800' : 'bg-teal-50 text-teal-700';
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-center border-b border-slate-100">
      <Link {...to} className="grid grid-cols-[4.5rem_minmax(0,1fr)_auto_1rem] items-center gap-3 px-4 py-3 text-sm hover:bg-slate-50 md:grid-cols-[4.5rem_minmax(0,1fr)_auto_3.5rem_4.5rem_1rem]" data-case={c.id} data-source={c.source}>
        <span className={`rounded px-1.5 py-0.5 text-center text-[11px] font-medium whitespace-nowrap ${chip}`}>{SOURCE_LABEL[c.source] ?? c.source}</span>
        <span className="min-w-0">
          <span className="block truncate font-mono font-medium text-slate-800">{caseLabel(c)}</span>
          <span className="block truncate text-xs text-slate-500">{c.ruleIds.join(' · ')}</span>
        </span>
        <LevelBadge level={c.level} />
        <span className="num hidden text-right text-xs text-slate-500 md:inline">위반 {fmtNum(c.violations)}</span>
        <span className="num hidden text-right font-mono text-xs text-slate-500 md:inline">{fmtTime(c.openedAt)}</span>
        <ChevronRight className="size-4 text-slate-400" aria-hidden />
      </Link>
      {/* 건 보고서 1장(10/30 계약 §5) — 행 메뉴 「보고서」 */}
      <Link
        to={`/report?case=${encodeURIComponent(c.id)}`}
        data-action="report"
        title="건 보고서 1장"
        className="mr-2 inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-500 hover:bg-slate-100 hover:text-slate-800"
      >
        <FileText className="size-3.5" aria-hidden /> 보고서
      </Link>
    </li>
  );
}
