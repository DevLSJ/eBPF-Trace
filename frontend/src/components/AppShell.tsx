import { Bell, FileClock, LayoutDashboard, ListTree, Network, PackageSearch, ScanSearch, ShieldCheck, SlidersHorizontal, type LucideIcon } from 'lucide-react';
import { useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useCases } from '../hooks/cases-context';
import { useStream } from '../hooks/stream-context';
import { HeaderSlotContext } from './header-slot';
import { WsStatus } from './WsStatus';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

// 사이드바는 시나리오별 묶음 (10/15 확정): 대시보드 / 설치 검사 / 런타임 감시 / 설정 · 기록
const groups: { label?: string; items: NavItem[] }[] = [
  { items: [{ to: '/', label: '대시보드', icon: LayoutDashboard, end: true }] },
  {
    label: '설치 검사',
    items: [
      { to: '/installs', label: '설치 검사', icon: PackageSearch },
      { to: '/scans', label: '공급망 검사', icon: ScanSearch },
    ],
  },
  {
    label: '런타임 감시',
    items: [
      { to: '/events', label: '이벤트', icon: ListTree },
      { to: '/topology', label: '토폴로지', icon: Network },
    ],
  },
  {
    label: '설정 · 기록',
    items: [
      { to: '/policies', label: '정책', icon: SlidersHorizontal },
      { to: '/audit', label: '감사 로그', icon: FileClock },
    ],
  },
];

const TITLES: Record<string, string> = {
  '/': '대시보드',
  '/installs': '설치 검사',
  '/scans': '공급망 검사',
  '/events': '이벤트',
  '/topology': '토폴로지',
  '/policies': '정책',
  '/audit': '감사 로그',
};

export function AppShell() {
  const { info, stats, unseenAlerts, ackAlerts } = useStream();
  const { cases } = useCases();
  const { pathname } = useLocation();
  const [slot, setSlot] = useState<HTMLElement | null>(null);
  const enforce = stats?.enforceKill ?? info?.enforceKill;
  const source = stats?.source ?? info?.source;
  const pending = cases?.filter((c) => c.state === 'open').length ?? 0;

  return (
    <div className="flex h-full min-w-[1024px] overflow-hidden">
      <aside className="flex w-52 shrink-0 flex-col bg-slate-900 text-slate-300">
        <Link to="/" className="flex h-14 items-center gap-2 px-5 text-white">
          <ShieldCheck className="size-5 text-indigo-400" aria-hidden />
          <span className="font-semibold tracking-tight">SupplyGuard</span>
        </Link>
        <nav className="flex flex-col gap-3 px-2 py-3" aria-label="화면">
          {groups.map((g, gi) => (
            <div key={gi} className="flex flex-col gap-0.5" data-nav-group={g.label ?? 'home'}>
              {g.label && <div className="px-3 pb-1 text-[11px] font-medium tracking-wide text-slate-500">{g.label}</div>}
              {g.items.map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    `flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                      isActive ? 'bg-slate-800 text-white' : 'hover:bg-slate-800/60 hover:text-white'
                    }`
                  }
                >
                  <Icon className="size-4" aria-hidden />
                  <span className="flex-1">{label}</span>
                  {to === '/' && pending > 0 && (
                    <span className="num rounded-full bg-amber-400 px-1.5 text-[11px] font-semibold text-slate-900" aria-label={`판정 대기 ${pending}건`}>
                      {pending}
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="mt-auto space-y-1 border-t border-slate-800 px-5 py-4 text-xs">
          <div className="flex justify-between">
            <span className="text-slate-500">수집</span>
            <span className="text-slate-200">{source === 'mock' ? 'Mock 데모' : source === 'gadget' ? 'eBPF 가젯' : '—'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">격리</span>
            <span className={enforce ? 'text-red-400' : 'text-amber-300'}>
              {enforce === undefined ? '—' : enforce ? '자동 종료' : 'dry-run'}
            </span>
          </div>
          {info?.gadgetVersion && (
            <div className="flex justify-between">
              <span className="text-slate-500">IG</span>
              <span className="num text-slate-200">{info.gadgetVersion}</span>
            </div>
          )}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-4 border-b border-slate-200 bg-white px-6">
          <h1 className="shrink-0 text-lg font-semibold text-slate-900" data-testid="page-title">
            {TITLES[pathname] ?? ''}
          </h1>
          <div ref={setSlot} className="flex min-w-0 flex-1 items-center gap-3" data-testid="page-actions" />
          <WsStatus />
          <Link
            to="/events"
            onClick={ackAlerts}
            className="relative rounded-md p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
            aria-label={`새 위반 ${unseenAlerts}건`}
          >
            <Bell className="size-5" aria-hidden />
            {unseenAlerts > 0 && (
              <span className="num absolute -top-1 -right-1.5 min-w-5 rounded-full bg-red-600 px-1 text-center text-[11px] leading-5 font-semibold text-white">
                {unseenAlerts > 99 ? '99+' : unseenAlerts}
              </span>
            )}
          </Link>
        </header>
        <main className="min-h-0 flex-1 overflow-hidden p-6">
          <HeaderSlotContext.Provider value={slot}>
            <Outlet />
          </HeaderSlotContext.Provider>
        </main>
      </div>
    </div>
  );
}
