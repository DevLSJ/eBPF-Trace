import { Bell, FileClock, LayoutDashboard, ListTree, Network, ShieldCheck, SlidersHorizontal } from 'lucide-react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import { useStream } from '../hooks/stream-context';
import { WsStatus } from './WsStatus';

const nav = [
  { to: '/', label: '대시보드', icon: LayoutDashboard, end: true },
  { to: '/events', label: '이벤트', icon: ListTree },
  { to: '/topology', label: '토폴로지', icon: Network },
  { to: '/policies', label: '정책', icon: SlidersHorizontal },
  { to: '/audit', label: '감사 로그', icon: FileClock },
];

export function AppShell() {
  const { info, stats, unseenAlerts, ackAlerts } = useStream();
  const enforce = stats?.enforceKill ?? info?.enforceKill;
  const source = stats?.source ?? info?.source;

  return (
    <div className="flex h-full min-w-[1024px]">
      <aside className="flex w-52 shrink-0 flex-col bg-slate-900 text-slate-300">
        <Link to="/" className="flex h-14 items-center gap-2 px-5 text-white">
          <ShieldCheck className="size-5 text-indigo-400" aria-hidden />
          <span className="font-semibold tracking-tight">SupplyGuard</span>
        </Link>
        <nav className="flex flex-col gap-0.5 px-2 py-3">
          {nav.map(({ to, label, icon: Icon, end }) => (
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
              {label}
            </NavLink>
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
        <header className="flex h-14 shrink-0 items-center justify-end gap-5 border-b border-slate-200 bg-white px-6">
          <WsStatus />
          <Link
            to="/events?verdict=violation"
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
        <main className="min-h-0 flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
