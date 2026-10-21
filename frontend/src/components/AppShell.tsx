import { ChevronsLeft, ChevronsRight, CircleHelp, FileClock, LayoutDashboard, ListTree, Network, PackageSearch, ScanSearch, Settings, ShieldCheck, SlidersHorizontal, X, type LucideIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useCases } from '../hooks/cases-context';
import { useStream } from '../hooks/stream-context';
import { AccountMenu } from './AccountMenu';
import { Assistant } from './Assistant';
import { HeaderSlotContext } from './header-slot';
import { HelpDialog } from './shell/HelpDialog';
import { NoticeCenter } from './shell/NoticeCenter';
import { SearchBox } from './shell/SearchBox';
import { StreamBanners } from './shell/StreamBanners';
import { useSidebar } from './shell/useSidebar';
import { WsStatus } from './WsStatus';
import { dialogOpen, typingTarget } from '../lib/shell';

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
      { to: '/settings', label: '설정', icon: Settings },
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
  '/settings': '설정',
};

// W19(10/20 C · D · E): 알림 센터(종) · 통합 검색(/) · 사이드바 접기([, 1100px 이하 자동) · ? 도움말 · 실시간 끊김 배너.
// 폭 고정(min-w-[1024px])을 없앴다 — 좁은 화면은 사이드바가 56px 로 접히고, 펼치면 본문 위에 겹쳐 뜬다(본문을 밀지 않음)
export function AppShell() {
  const { info, stats } = useStream();
  const { cases } = useCases();
  const { pathname } = useLocation();
  const [slot, setSlot] = useState<HTMLElement | null>(null);
  const [help, setHelp] = useState(false);
  const { collapsed, narrow, toggle } = useSidebar(pathname);
  const enforce = stats?.enforceKill ?? info?.enforceKill;
  const source = stats?.source ?? info?.source;
  const pending = cases?.filter((c) => c.state === 'open').length ?? 0;
  const overlay = narrow && !collapsed;

  // 토스트(toast-context)가 사이드바 바로 옆에 붙도록 본문이 차지하는 사이드바 폭을 알린다(10/20). 겹쳐 뜬 펼침은 접힌 폭 기준
  useEffect(() => {
    document.documentElement.style.setProperty('--sg-sidebar-w', collapsed || overlay ? '3.5rem' : '13rem');
  }, [collapsed, overlay]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '?' || e.metaKey || e.ctrlKey || e.altKey || typingTarget(e) || dialogOpen()) return;
      e.preventDefault();
      setHelp(true);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="flex h-full overflow-hidden">
      {/* 좁은 화면에서 펼친 사이드바는 겹쳐 뜬다 — 자리는 접힌 폭(56px)만 */}
      {overlay && <div className="w-14 shrink-0" aria-hidden />}
      <aside
        data-part="sidebar"
        data-collapsed={String(collapsed)}
        className={`flex shrink-0 flex-col bg-slate-900 text-slate-300 ${collapsed ? 'w-14' : 'w-52'} ${overlay ? 'fixed inset-y-0 left-0 z-40 shadow-2xl' : ''}`}
      >
        <Link to="/" className={`flex h-14 shrink-0 items-center gap-2 text-white ${collapsed ? 'justify-center' : 'px-5'}`} title="SupplyGuard">
          <ShieldCheck className="size-5 shrink-0 text-indigo-400" aria-hidden />
          <span className={collapsed ? 'sr-only' : 'font-semibold tracking-tight'}>SupplyGuard</span>
        </Link>
        <div className={collapsed ? 'px-2' : 'px-3'}>
          <SearchBox collapsed={collapsed} />
        </div>
        <nav className="flex min-h-0 flex-col gap-3 overflow-y-auto px-2 py-3" aria-label="화면">
          {groups.map((g, gi) => (
            <div key={gi} className="flex flex-col gap-0.5" data-nav-group={g.label ?? 'home'}>
              {g.label &&
                (collapsed ? (
                  <div className="mx-2 mb-1 border-t border-slate-800" aria-hidden />
                ) : (
                  <div className="px-3 pb-1 text-[11px] font-medium tracking-wide text-slate-500">{g.label}</div>
                ))}
              {g.items.map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  title={collapsed ? label : undefined}
                  className={({ isActive }) =>
                    `relative flex items-center gap-3 rounded-md py-2 text-sm transition-colors ${collapsed ? 'justify-center px-0' : 'px-3'} ${
                      isActive ? 'bg-slate-800 text-white' : 'hover:bg-slate-800/60 hover:text-white'
                    }`
                  }
                >
                  <Icon className="size-4 shrink-0" aria-hidden />
                  <span className={collapsed ? 'sr-only' : 'flex-1'}>{label}</span>
                  {to === '/' && pending > 0 && (
                    <span
                      className={`num rounded-full bg-amber-400 px-1.5 text-[11px] font-semibold text-slate-900 ${collapsed ? 'absolute -top-0.5 right-0.5 px-1 text-[10px] leading-4' : ''}`}
                      aria-label={`판정 대기 ${pending}건`}
                    >
                      {pending}
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        {!collapsed && (
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
        )}
        <button
          type="button"
          onClick={toggle}
          aria-label={collapsed ? '사이드바 펼치기' : '사이드바 접기'}
          title="사이드바 접기 · 펼치기 ([)"
          className={`flex h-10 shrink-0 items-center border-t border-slate-800 text-slate-500 hover:text-white ${collapsed ? 'mt-auto justify-center' : 'justify-end px-4'}`}
        >
          {collapsed ? <ChevronsRight className="size-4" aria-hidden /> : <ChevronsLeft className="size-4" aria-hidden />}
        </button>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-4 border-b border-slate-200 bg-white px-6">
          <h1 className="shrink-0 text-lg font-semibold text-slate-900" data-testid="page-title">
            {TITLES[pathname] ?? ''}
          </h1>
          <div ref={setSlot} className="flex min-w-0 flex-1 items-center gap-3" data-testid="page-actions" />
          <WsStatus />
          <NoticeCenter />
          <button
            type="button"
            onClick={() => setHelp(true)}
            aria-label="사용 안내 (?)"
            title="사용 안내 (?)"
            className="rounded-md p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
          >
            <CircleHelp className="size-5" aria-hidden />
          </button>
          <AccountMenu />
        </header>
        <StreamBanners />
        <DnsBanner />
        <main className="min-h-0 flex-1 overflow-hidden p-6">
          <HeaderSlotContext.Provider value={slot}>
            <Outlet />
          </HeaderSlotContext.Provider>
        </main>
      </div>
      <Assistant />
      {help && <HelpDialog onClose={() => setHelp(false)} />}
    </div>
  );
}

// 「도메인 판단 꺼짐」(10/20) — /api/info dnsResolve === 'off' 일 때. 닫으면 이 탭(sessionStorage) 동안 숨긴다
const DNS_KEY = 'supplyguard.banner.dns';
function DnsBanner() {
  const { info } = useStream();
  const [dismissed, setDismissed] = useState(() => {
    try {
      return sessionStorage.getItem(DNS_KEY) === '1';
    } catch {
      return false;
    }
  });
  if (info?.dnsResolve !== 'off' || dismissed) return null;
  return (
    <div data-banner="dns" role="alert" className="flex shrink-0 items-center gap-2 border-b border-amber-200 bg-amber-50 px-6 py-2 text-[13px] text-amber-900">
      <span className="min-w-0 flex-1">
        <b>도메인 판단 꺼짐</b> — trace_dns 가 뜨지 않아 도메인 기준 규칙(allowHosts · denyHosts · 차단 도메인)이 통과 처리됩니다. IP · 포트 규칙만 동작합니다.{' '}
        <Link to="/settings" className="text-amber-800 underline">
          서버 설정 보기 →
        </Link>
      </span>
      <button
        type="button"
        aria-label="닫기"
        className="rounded p-0.5 text-amber-800 hover:bg-amber-100"
        onClick={() => {
          try {
            sessionStorage.setItem(DNS_KEY, '1');
          } catch {
            /* 저장 차단 */
          }
          setDismissed(true);
        }}
      >
        <X className="size-4" />
      </button>
    </div>
  );
}
