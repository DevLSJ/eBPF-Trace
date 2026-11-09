import { ChartColumn, ChevronsLeft, ChevronsRight, CircleHelp, FileClock, LayoutDashboard, ListTree, Menu, MonitorPlay, Network, Plug, PackageSearch, ScanSearch, Settings, ShieldCheck, SlidersHorizontal, X, type LucideIcon } from 'lucide-react';
import { useEffect, useState, type CSSProperties } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/auth-context';
import { useCases } from '../hooks/cases-context';
import { useStream } from '../hooks/stream-context';
import { AccountMenu } from './AccountMenu';
import { Assistant } from './Assistant';
import { HeaderSlotContext, SheetHostContext } from './header-slot';
import { HelpDialog } from './shell/HelpDialog';
import { NoticeCenter } from './shell/NoticeCenter';
import { SearchBox } from './shell/SearchBox';
import { StreamBanners } from './shell/StreamBanners';
import { useSidebar } from './shell/useSidebar';
import { useSortable } from '../hooks/useSortable';
import { WsStatus } from './WsStatus';
import { FRESH } from '../lib/nav';
import { dialogOpen, typingTarget } from '../lib/shell';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

// 사이드바는 시나리오별 묶음 (10/15 확정): 대시보드 / 설치 검사 / 런타임 감시 / 설정 · 기록
// id = 순서 저장(localStorage supplyguard.layout sidebar.<id>)의 키(R1 11/04 — 목업과 같은 이름). 항목 id = 경로에서 / 를 뗀 것
const groups: { id?: 'install' | 'runtime' | 'records'; label?: string; items: NavItem[] }[] = [
  { items: [{ to: '/', label: '대시보드', icon: LayoutDashboard, end: true }] },
  {
    id: 'install',
    label: '설치 검사',
    items: [
      { to: '/installs', label: '설치 검사', icon: PackageSearch },
      { to: '/scans', label: '공급망 검사', icon: ScanSearch },
      { to: '/evaluation', label: '평가', icon: ChartColumn }, // 11/04 — 공급망 검사 · 설치 검사를 재는 화면이라 같은 묶음 끝
    ],
  },
  {
    id: 'runtime',
    label: '런타임 감시',
    items: [
      { to: '/events', label: '이벤트', icon: ListTree },
      { to: '/topology', label: '토폴로지', icon: Network },
    ],
  },
  {
    id: 'records',
    label: '설정 · 기록',
    items: [
      { to: '/policies', label: '정책', icon: SlidersHorizontal },
      { to: '/audit', label: '감사 로그', icon: FileClock },
      { to: '/settings', label: '설정', icon: Settings },
    ],
  },
];

// R3 11/04: 「시연」 — 대시보드 바로 아래 고정(home 줄 — 길게 눌러 옮기기 · 순서 저장 대상 아님), 관리자 + /api/info.demo 일 때만 groups 에 끼운다
const DEMO_ITEM: NavItem = { to: '/demo', label: '시연', icon: MonitorPlay };
// 11/06: 「연동」 — 모두에게(연결 테스트 버튼만 관리자), 대시보드 바로 아래 고정(home 줄)
const INTEGRATION_ITEM: NavItem = { to: '/integration', label: '연동', icon: Plug };

const TITLES: Record<string, string> = {
  '/': '대시보드',
  '/integration': '연동',
  '/demo': '시연',
  '/installs': '설치 검사',
  '/scans': '공급망 검사',
  '/evaluation': '평가',
  '/events': '이벤트',
  '/topology': '토폴로지',
  '/policies': '정책',
  '/audit': '감사 로그',
  '/settings': '설정',
  '/report': '건 보고서', // 10/30 — 사이드바에는 없고 시트 · 판정 카드 · 판정 대기 행에서 연다
};

// W19(10/20 C · D · E): 알림 센터(종) · 통합 검색(/) · 사이드바 접기([, 1100px 이하 자동) · ? 도움말 · 실시간 끊김 배너.
// 폭 고정(min-w-[1024px])을 없앴다 — 좁은 화면은 사이드바가 56px 로 접히고, 펼치면 본문 위에 겹쳐 뜬다(본문을 밀지 않음)
export function AppShell() {
  const { info, stats } = useStream();
  const { cases } = useCases();
  const { isAdmin } = useAuth();
  const demoOn = isAdmin && info?.demo === true;
  const { pathname } = useLocation();
  const [slot, setSlot] = useState<HTMLElement | null>(null);
  const [sheetHost, setSheetHost] = useState<HTMLElement | null>(null); // 상세 패널 자리(11/05) — main 위에 겹친다
  const [help, setHelp] = useState(false);
  const { collapsed, narrow, mobile, mobileOpen, toggle, openMobile, closeMobile } = useSidebar(pathname);
  const enforce = stats?.enforceKill ?? info?.enforceKill;
  const source = stats?.source ?? info?.source;
  const pending = cases?.filter((c) => c.state === 'open').length ?? 0;
  const overlay = narrow && !mobile && !collapsed;

  // 토스트(toast-context)가 사이드바 바로 옆에 붙도록 본문이 차지하는 사이드바 폭을 알린다(10/20). 겹쳐 뜬 펼침은 접힌 폭 기준, 서랍(768 미만)은 0
  useEffect(() => {
    document.documentElement.style.setProperty('--sg-sidebar-w', mobile ? '0px' : collapsed || overlay ? 'var(--sidebar-w-collapsed)' : 'var(--sidebar-w)');
  }, [collapsed, overlay, mobile]);

  // 서랍은 Esc 로 닫힌다
  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.preventDefault();
      closeMobile();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [mobileOpen, closeMobile]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '?' || e.metaKey || e.ctrlKey || e.altKey || typingTarget(e) || dialogOpen()) return;
      e.preventDefault();
      setHelp(true);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const showAside = !mobile || mobileOpen;
  return (
    <div className="flex h-full overflow-hidden">
      {/* 좁은 화면에서 펼친 사이드바는 겹쳐 뜬다 — 자리는 접힌 폭(56px)만 */}
      {overlay && <div className="w-[var(--sidebar-w-collapsed)] shrink-0" aria-hidden />}
      {/* 768 미만 서랍의 배경 dim — 누르면 닫힘 */}
      {mobile && mobileOpen && <div data-part="sidebar-dim" className="fixed inset-0 z-40 bg-black/40" onClick={closeMobile} aria-hidden />}
      {showAside && (
        <aside
          data-part="sidebar"
          data-collapsed={String(collapsed)}
          className={`flex shrink-0 flex-col border-r border-border bg-surface text-text-2 ${collapsed ? 'w-[var(--sidebar-w-collapsed)]' : 'w-[var(--sidebar-w)]'} ${
            overlay || mobile ? 'fixed inset-y-0 left-0 z-50 shadow-[var(--sh-2)]' : ''
          } ${mobile ? 'sg-drawer' : ''}`}
        >
          <Link to="/" className={`flex h-[var(--header-h)] shrink-0 items-center gap-2 text-text ${collapsed ? 'justify-center' : 'px-5'}`} title="SupplyGuard">
            <ShieldCheck className="size-5 shrink-0 text-accent" aria-hidden />
            <span className={collapsed ? 'sr-only' : 'font-semibold tracking-tight'}>SupplyGuard</span>
            {mobile && (
              <button type="button" onClick={closeMobile} aria-label="메뉴 닫기" className="ml-auto rounded-md p-1.5 text-text-3 hover:bg-surface-2 hover:text-text">
                <X className="size-4" aria-hidden />
              </button>
            )}
          </Link>
          <div className={collapsed ? 'px-2' : 'px-3'}>
            <SearchBox collapsed={collapsed} />
          </div>
          <nav className="flex min-h-0 flex-col gap-3 overflow-y-auto px-2 py-3" aria-label="화면">
            {groups.map((g, gi) => (
              <NavGroup key={gi} g={!g.id ? { ...g, items: [...g.items, INTEGRATION_ITEM, ...(demoOn ? [DEMO_ITEM] : [])] } : g} collapsed={collapsed} pending={pending} />
            ))}
          </nav>
          {!collapsed && (
            <div className="mt-auto space-y-1 border-t border-border px-5 py-4 text-xs">
              <div className="flex justify-between">
                <span className="text-text-3">수집</span>
                <span className="text-text">{source === 'mock' ? 'Mock 데모' : source === 'gadget' ? 'eBPF 가젯' : '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-3">격리</span>
                <span className={enforce ? 'text-danger-text' : 'text-warn-text'}>
                  {enforce === undefined ? '—' : enforce ? '자동 종료' : 'dry-run'}
                </span>
              </div>
              {info?.gadgetVersion && (
                <div className="flex justify-between">
                  <span className="text-text-3">IG</span>
                  <span className="num text-text">{info.gadgetVersion}</span>
                </div>
              )}
            </div>
          )}
          {!mobile && (
            <button
              type="button"
              onClick={toggle}
              aria-label={collapsed ? '사이드바 펼치기' : '사이드바 접기'}
              title="사이드바 접기 · 펼치기 ([)"
              className={`flex h-10 shrink-0 items-center border-t border-border text-text-3 hover:text-text ${collapsed ? 'mt-auto justify-center' : 'justify-end px-4'}`}
            >
              {collapsed ? <ChevronsRight className="size-4" aria-hidden /> : <ChevronsLeft className="size-4" aria-hidden />}
            </button>
          )}
        </aside>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header data-part="header" className="flex h-[var(--header-h)] shrink-0 items-center gap-3 border-b border-border bg-surface px-4 md:gap-4 md:px-6">
          {mobile && (
            <button type="button" onClick={openMobile} aria-label="메뉴" aria-expanded={mobileOpen} className="rounded-md p-1.5 text-text-2 hover:bg-surface-2 hover:text-text">
              <Menu className="size-5" aria-hidden />
            </button>
          )}
          <h1 className="shrink-0 text-[1.65rem] leading-tight font-semibold tracking-[-0.02em] text-text" data-testid="page-title">
            {TITLES[pathname] ?? ''}
          </h1>
          {/* 768 미만: 머리 칸의 화면 버튼은 가로로 넘기며 본다(머리 높이 56px 유지) */}
          <div ref={setSlot} className="flex min-w-0 flex-1 items-center gap-3 max-md:overflow-x-auto max-md:[scrollbar-width:none]" data-testid="page-actions" />
          <WsStatus />
          <NoticeCenter />
          <button
            type="button"
            onClick={() => setHelp(true)}
            aria-label="사용 안내 (?)"
            title="사용 안내 (?)"
            className="hidden rounded-md p-1.5 text-text-3 hover:bg-surface-2 hover:text-text md:inline-flex"
          >
            <CircleHelp className="size-5" aria-hidden />
          </button>
          <AccountMenu />
        </header>
        <StreamBanners />
        <DnsBanner />
        <main className="relative min-h-0 flex-1 overflow-hidden p-4 md:p-6">
          <HeaderSlotContext.Provider value={slot}>
            <SheetHostContext.Provider value={sheetHost}>
              {/* 화면 전환: fade + 4px 상승(경로가 바뀔 때만 — 같은 화면의 ?id= 는 그대로). 바깥 칸이 움직이는 4px 를 잘라 본문 넘침이 생기지 않는다 */}
              <div className="h-full min-h-0 overflow-hidden">
                <div key={pathname} data-part="screen" className="sg-screen h-full min-h-0">
                  <Outlet />
                </div>
              </div>
            </SheetHostContext.Provider>
          </HeaderSlotContext.Provider>
          {/* 상세 패널 자리: 비어 있으면 클릭을 통과시킨다 */}
          <div ref={setSheetHost} data-part="sheet-host" className="sg-sheet-host" />
        </main>
      </div>
      <Assistant />
      {help && <HelpDialog onClose={() => setHelp(false)} />}
    </div>
  );
}

// 사이드바 묶음 — 길게 눌러(또는 Alt+↑/↓) 묶음 안에서만 순서를 바꾼다(11/04d, R1 11/04). 대시보드 줄(묶음 제목 없음)은 고정 · 묶음 순서 그대로
function NavGroup({ g, collapsed, pending }: { g: (typeof groups)[number]; collapsed: boolean; pending: number }) {
  const byId = new Map(g.items.map((it) => [it.to.slice(1), it]));
  const { ref, order, containerClass, itemProps, pickedClass } = useSortable<HTMLDivElement>({ scope: `sidebar.${g.id ?? 'home'}`, ids: g.items.map((it) => it.to.slice(1)), labelOf: (id) => byId.get(id)?.label ?? id });
  const list = g.id ? order.map((id) => byId.get(id)!).filter(Boolean) : g.items;
  return (
    <div ref={g.id ? ref : undefined} className={`flex flex-col gap-0.5 ${g.id ? containerClass : ''}`} data-nav-group={g.label ?? 'home'}>
      {g.label &&
        (collapsed ? (
          <div className="mx-2 mb-1 border-t border-border" aria-hidden />
        ) : (
          <div className="px-3 pb-1 text-[11px] font-medium tracking-wide text-text-3">{g.label}</div>
        ))}
      {list.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          state={FRESH}
          end={end}
          title={collapsed ? label : undefined}
          {...(g.id ? itemProps(to.slice(1)) : {})}
          className={({ isActive }) =>
            `relative flex items-center gap-3 rounded-[var(--r-sm)] py-2 text-sm transition-colors duration-[var(--t-fast)] ${collapsed ? 'justify-center px-0' : 'px-3'} ${
              isActive ? 'bg-accent-soft font-medium text-accent-text' : 'hover:bg-surface-2 hover:text-text'
            } ${g.id ? pickedClass(to.slice(1)) : ''}`
          }
        >
          <Icon className="size-4 shrink-0" aria-hidden />
          <span className={collapsed ? 'sr-only' : 'flex-1'}>{label}</span>
          {to === '/' && pending > 0 && (
            <span
              className={`num rounded-full bg-warn px-1.5 text-[11px] font-semibold text-text-inverse ${collapsed ? 'absolute -top-0.5 right-0.5 px-1 text-[10px] leading-4' : ''}`}
              aria-label={`판정 대기 ${pending}건`}
            >
              {pending}
            </span>
          )}
        </NavLink>
      ))}
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
    <div data-banner="dns" role="alert" style={{ '--banner-color': 'var(--warn)' } as CSSProperties} className="sg-banner flex shrink-0 items-center gap-2 border-b border-amber-200 bg-amber-50 px-4 py-2 text-[13px] text-amber-900 md:px-6">
      <span className="min-w-0 flex-1">
        <b>도메인 판단 꺼짐</b> — trace_dns 가 뜨지 않아 도메인 기준 규칙(allowHosts · denyHosts · 차단 도메인)과 DNS 질의 규칙(kind: dns)이 통과 처리됩니다. IP · 포트 규칙만 동작합니다.{' '}
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
