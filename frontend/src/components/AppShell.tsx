import { ChartColumn, ChevronDown, ChevronsLeft, ChevronsRight, CircleHelp, FileClock, LayoutDashboard, ListTree, Menu, MonitorPlay, Network, Plug, PackageSearch, ScanSearch, Settings, ShieldCheck, SlidersHorizontal, X, type LucideIcon } from 'lucide-react';
import { useEffect, useRef, useState, type CSSProperties } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/auth-context';
import { useCases } from '../hooks/cases-context';
import { useStream } from '../hooks/stream-context';
import { AccountMenu, LicenseChip } from './AccountMenu';
import { Assistant } from './Assistant';
import { SheetHostContext } from './header-slot';
import { ActionSlotProvider } from './PageActions';
import { HelpDialog } from './shell/HelpDialog';
import { NoticeCenter } from './shell/NoticeCenter';
import { SearchBox } from './shell/SearchBox';
import { StreamBanners } from './shell/StreamBanners';
import { useSidebar } from './shell/useSidebar';
import { ThemeToggle } from './ThemeToggle';
import { useSortable } from '../hooks/useSortable';
import { WsStatus } from './WsStatus';
import './shell.css';
import { FRESH } from '../lib/nav';
import { dialogOpen, loadJSON, saveJSON, screenOf, typingTarget } from '../lib/shell';

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
  // 하위 메뉴(11/09 정책 화면 분리) — 있으면 이 칸은 묶음 제목 + 하위 링크(묶음째 길게 눌러 옮김)
  children?: { to: string; label: string }[];
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
      // 11/09 사용자 결정 「사이드바 하위 메뉴」 — 정책 아래 정책 · 차단 목록 · 변경 이력(페이지별)
      {
        to: '/policies',
        label: '정책',
        icon: SlidersHorizontal,
        children: [
          { to: '/policies', label: '정책' },
          { to: '/policies/blocklist', label: '차단 목록' },
          { to: '/policies/changes', label: '변경 이력' },
        ],
      },
      { to: '/audit', label: '감사 로그', icon: FileClock },
      { to: '/settings', label: '설정', icon: Settings },
    ],
  },
];

// R3 11/04: 「시연」 — 대시보드 바로 아래 고정(home 줄 — 길게 눌러 옮기기 · 순서 저장 대상 아님), 관리자 + /api/info.demo 일 때만 groups 에 끼운다
const DEMO_ITEM: NavItem = { to: '/demo', label: '시연', icon: MonitorPlay };
// 11/06: 「연동」 — 모두에게(연결 테스트 버튼만 관리자), 대시보드 바로 아래 고정(home 줄).
// 11/09 밤 사용자 결정: 하위 메뉴 3개(연동 · 환경 점검 · 감시 중 컨테이너)를 가진 묶음 — 정책 묶음과 같은 모양
const INTEGRATION_ITEM: NavItem = {
  to: '/integration',
  label: '연동',
  icon: Plug,
  children: [
    { to: '/integration', label: '연동' },
    { to: '/integration/env', label: '환경 점검' },
    { to: '/integration/watch', label: '감시 중 컨테이너' },
  ],
};

// 화면 제목 · 하위 화면의 상위(「정책 ›」)는 lib/shell SCREENS 한 곳(통합 검색 「화면」과 같은 이름).
// 건 보고서(/report)는 사이드바에는 없고 시트 · 판정 카드 · 판정 대기 행에서 연다
// 사이드바 아래 상태 칸(11/09 G38): 내부 이름은 툴팁으로만
const SOURCE_KO: Record<string, string> = { mock: '모의 재생', gadget: '실시간 수집(eBPF)' };

// W19(10/20 C · D · E): 알림 센터(종) · 통합 검색(/) · 사이드바 접기([) · ? 도움말 · 실시간 끊김 배너.
// 11/10 셸 배치(참고 사이트의 배치 원리 — 값 · 원리만, shell.css):
//   [왼쪽 칸: 사이드바] [본문 단: 맨 위 고정 제목 줄 + 배너 + 본문] [오른쪽 여백]. 본문 단 = 좌우 1px 세로선 · 최대 --content-max,
//   넓은 화면은 남는 폭을 왼쪽 칸 · 오른쪽 여백이 반씩 받아 사이드바 + 본문 단이 함께 가운데(사이드바는 본문 단 바로 옆).
//   폭 단계: 1280 이상 글자 있는 사이드바 · 768~1279 아이콘만(펼치면 본문 위에 겹쳐 뜬다 — 본문을 밀지 않음) · 768 미만 서랍.
//   제목 줄 = 화면 제목(하위 화면은 「정책 ›」) + 오른쪽 끝 작은 상태 묶음(실시간 · 종 · 해/달 · ? · 라이선스). 계정은 사이드바 맨 아래
export function AppShell() {
  const { info, stats } = useStream();
  const { cases } = useCases();
  const { isAdmin } = useAuth();
  const demoOn = isAdmin && info?.demo === true;
  const { pathname } = useLocation();
  const [sheetHost, setSheetHost] = useState<HTMLElement | null>(null); // 상세 패널 자리(11/05) — main 위에 겹친다
  const [help, setHelp] = useState(false);
  const { collapsed, narrow, mobile, mobileOpen, toggle, openMobile, closeMobile } = useSidebar(pathname);
  const enforce = stats?.enforceKill ?? info?.enforceKill;
  const source = stats?.source ?? info?.source;
  const pending = cases?.filter((c) => c.state === 'open').length ?? 0;
  const overlay = narrow && !mobile && !collapsed;
  const screen = screenOf(pathname);
  const parent = screen?.parent ? screenOf(screen.parent) : undefined;
  const sideName = collapsed ? '사이드바 펼치기 ([)' : '사이드바 접기 ([)';

  // 토스트(toast-context)가 사이드바 바로 옆에 붙도록 사이드바 오른쪽 끝을 알린다(10/20). 겹쳐 뜬 펼침은 접힌 폭 기준, 서랍(768 미만)은 0.
  // 넓은 화면은 사이드바 + 본문 단이 가운데로 오므로 남는 폭의 절반을 더한다(shell.css 큰 틀과 같은 계산 — 본문 단 바깥 여백 -1 × 2 포함)
  useEffect(() => {
    const w = collapsed || overlay ? 'var(--sidebar-w-collapsed)' : 'var(--sidebar-w)';
    document.documentElement.style.setProperty('--sg-sidebar-w', mobile ? '0px' : `calc(${w} + max(0px, (100vw - ${w} - var(--content-max) + 2px) / 2))`);
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
  const sideToggle = (
    <button type="button" onClick={toggle} aria-label={sideName} title={sideName} className="sg-nav-item grid size-9 shrink-0 place-items-center text-text-3 hover:text-text">
      {collapsed ? <ChevronsRight className="size-5" aria-hidden /> : <ChevronsLeft className="size-5" aria-hidden />}
    </button>
  );
  return (
    <div data-part="shell" className="sg-shell">
      {/* 768 미만 서랍의 배경 dim — 누르면 닫힘 */}
      {mobile && mobileOpen && <div data-part="sidebar-dim" className="fixed inset-0 z-40 bg-black/40" onClick={closeMobile} aria-hidden />}
      <div data-part="rail" className="sg-shell-rail">
        {/* 좁은 화면에서 펼친 사이드바는 겹쳐 뜬다 — 자리는 접힌 폭(56px)만 */}
        {overlay && <div className="w-[var(--sidebar-w-collapsed)] shrink-0" aria-hidden />}
        {showAside && (
          <aside
            data-part="sidebar"
            data-collapsed={String(collapsed)}
            className={`sg-side flex h-full shrink-0 flex-col text-text ${collapsed ? 'w-[var(--sidebar-w-collapsed)]' : 'w-[var(--sidebar-w)]'} ${
              overlay || mobile ? 'fixed inset-y-0 left-0 z-50 shadow-[var(--sh-2)]' : ''
            } ${mobile ? 'sg-drawer' : ''}`}
          >
            {/* 로고 줄(제목 줄과 같은 높이) — 펼침: 오른쪽 끝에 접기 단추 · 서랍: 닫기 단추. 접힘: 로고만, 펼치기 단추는 바로 아래 */}
            <div className={`flex h-[var(--shell-title-h)] shrink-0 items-center ${collapsed ? 'justify-center' : 'gap-1 pr-2 pl-2'}`}>
              <Link to="/" title="SupplyGuard" className={`sg-nav-item flex items-center gap-2 text-text ${collapsed ? 'size-12 justify-center' : 'min-w-0 flex-1 px-2 py-1.5'}`}>
                <ShieldCheck className="size-7 shrink-0 text-accent" aria-hidden />
                <span className={collapsed ? 'sr-only' : 'truncate text-[17px] font-bold tracking-tight'}>SupplyGuard</span>
              </Link>
              {mobile ? (
                <button type="button" onClick={closeMobile} aria-label="메뉴 닫기" title="메뉴 닫기" className="sg-nav-item grid size-9 shrink-0 place-items-center text-text-3 hover:text-text">
                  <X className="size-5" aria-hidden />
                </button>
              ) : (
                !collapsed && sideToggle
              )}
            </div>
            {!mobile && collapsed && <div className="flex shrink-0 justify-center pb-1">{sideToggle}</div>}
            <div className={`shrink-0 pb-2 ${collapsed ? 'px-1' : 'px-3'}`}>
              <SearchBox collapsed={collapsed} />
            </div>
            <nav className={`flex min-h-0 flex-col gap-2 overflow-y-auto py-1 ${collapsed ? 'px-1' : 'px-2'}`} aria-label="화면">
              {groups.map((g, gi) => (
                <NavGroup key={gi} g={!g.id ? { ...g, items: [...g.items, INTEGRATION_ITEM, ...(demoOn ? [DEMO_ITEM] : [])] } : g} collapsed={collapsed} pending={pending} />
              ))}
            </nav>
            {/* 맨 아래: 수집 · 격리 상태(펼침만) → 계정(표시 이름 · 역할, 메뉴는 위로) */}
            <div className="mt-auto shrink-0 pt-2">
              {!collapsed && (
                <div data-part="side-status" className="space-y-1 px-5 pb-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-text-3">수집</span>
                    <span className="text-text" title={source}>
                      {SOURCE_KO[source ?? ''] ?? ''}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-text-3">격리</span>
                    <span className={enforce ? 'text-danger-text' : 'text-warn-text'}>
                      {enforce === undefined ? '' : enforce ? '자동 종료' : '알림만(dry-run)'}
                    </span>
                  </div>
                  {info?.gadgetVersion && (
                    <div className="flex justify-between">
                      <span className="text-text-3" title="Inspektor Gadget">
                        수집기 버전
                      </span>
                      <span className="num text-text">{info.gadgetVersion}</span>
                    </div>
                  )}
                </div>
              )}
              <AccountMenu collapsed={collapsed} />
            </div>
          </aside>
        )}
      </div>

      <div data-part="column" className="sg-shell-col">
        <header data-part="header" className="sg-titlebar flex shrink-0 items-center gap-3 px-4 md:gap-4 md:px-6">
          {mobile && (
            <button type="button" onClick={openMobile} aria-label="메뉴" title="메뉴" aria-expanded={mobileOpen} className="sg-title-icon p-1.5 text-text-2 hover:text-text">
              <Menu className="size-5" aria-hidden />
            </button>
          )}
          {/* 화면 제목 21/700(--fs-xl, 11/09 G43). 하위 화면(정책 › 차단 목록 · 변경 이력)은 앞에 상위 화면 링크(11/09 G17) */}
          <div className="flex min-w-0 shrink-0 items-baseline gap-1.5 text-[length:var(--fs-xl)] leading-tight font-bold tracking-[-0.02em]">
            {parent && (
              <>
                <Link to={parent.to} state={FRESH} data-part="title-parent" className="text-text-3 hover:text-accent-text">
                  {parent.label}
                </Link>
                <span data-part="title-sep" aria-hidden className="font-normal text-text-3">
                  ›
                </span>
              </>
            )}
            <h1 className="text-text" data-testid="page-title">
              {screen?.label ?? ''}
            </h1>
          </div>
          {/* 제목 줄 = 제목 + 상태 표시만. 화면 주 버튼은 본문 맨 위 설명 줄 오른쪽 끝(ScreenHead · PageActions, 11/09 밤 ③) */}
          <div className="min-w-0 flex-1" aria-hidden />
          <div data-part="title-status" className="flex shrink-0 items-center gap-1 md:gap-2">
            <WsStatus />
            <NoticeCenter />
            {/* 테마 = 해/달 단추 하나(11/09 G01) */}
            <ThemeToggle />
            <button type="button" onClick={() => setHelp(true)} aria-label="사용 안내 (?)" title="사용 안내 (?)" className="sg-title-icon hidden p-1.5 text-text-3 hover:text-text md:inline-flex">
              <CircleHelp className="size-5" aria-hidden />
            </button>
            <LicenseChip />
          </div>
        </header>
        <StreamBanners />
        <DnsBanner />
        <main className="relative min-h-0 flex-1 overflow-hidden p-4 md:p-6">
          <ActionSlotProvider>
            <SheetHostContext.Provider value={sheetHost}>
              {/* 화면 전환: fade + 4px 상승(경로가 바뀔 때만 — 같은 화면의 ?id= 는 그대로). 바깥 칸이 움직이는 4px 를 잘라 본문 넘침이 생기지 않는다 */}
              <div className="h-full min-h-0 overflow-hidden">
                <div key={pathname} data-part="screen" className="sg-screen h-full min-h-0">
                  <Outlet />
                </div>
              </div>
            </SheetHostContext.Provider>
          </ActionSlotProvider>
          {/* 상세 패널 자리: 비어 있으면 클릭을 통과시킨다 */}
          <div ref={setSheetHost} data-part="sheet-host" className="sg-sheet-host" />
        </main>
      </div>
      <div data-part="pad" className="sg-shell-pad" aria-hidden />
      <Assistant />
      {help && <HelpDialog onClose={() => setHelp(false)} />}
    </div>
  );
}

// 사이드바 묶음 — 길게 눌러(또는 Alt+↑/↓) 묶음 안에서만 순서를 바꾼다(11/04d, R1 11/04). 대시보드 줄(묶음 제목 없음)은 고정 · 묶음 순서 그대로
// 메뉴 줄(11/10): 아이콘 24 + 글자 16/500 · 지금 화면 700 + 강조 글자색(아이콘 선도 굵게) · 상자 없음, hover = 알약(shell.css .sg-nav-item).
//   접힘(아이콘만) = 48 원 안에 아이콘, 이름은 접근성 이름 · 툴팁
function NavGroup({ g, collapsed, pending }: { g: (typeof groups)[number]; collapsed: boolean; pending: number }) {
  const byId = new Map(g.items.map((it) => [it.to.slice(1), it]));
  // 하위 메뉴 칸(묶음 제목 div)은 링크가 아니라 초점을 따로 받는다(Alt+↑/↓ 로 묶음째 옮기기) — focusable: false 면 칸마다 tabIndex 0
  const { ref, order, containerClass, itemProps, pickedClass } = useSortable<HTMLDivElement>({
    scope: `sidebar.${g.id ?? 'home'}`,
    ids: g.items.map((it) => it.to.slice(1)),
    labelOf: (id) => byId.get(id)?.label ?? id,
    focusable: !g.items.some((it) => it.children),
  });
  const list = g.id ? order.map((id) => byId.get(id)!).filter(Boolean) : g.items;
  return (
    <div ref={g.id ? ref : undefined} className={`flex flex-col gap-0.5 ${g.id ? containerClass : ''}`} data-nav-group={g.label ?? 'home'}>
      {g.label &&
        (collapsed ? (
          <div className="mx-3 mb-1 border-t border-border" aria-hidden />
        ) : (
          <div className="px-3 pt-1 pb-0.5 text-xs font-medium tracking-wide text-text-3">{g.label}</div>
        ))}
      {list.map(({ to, label, icon: Icon, end, children }) =>
        children ? (
          <SubNav key={to} id={to.slice(1)} label={label} icon={Icon} items={children} collapsed={collapsed} sortProps={g.id ? itemProps(to.slice(1)) : {}} pickedClass={g.id ? pickedClass(to.slice(1)) : ''} />
        ) : (
        <NavLink
          key={to}
          to={to}
          state={FRESH}
          end={end}
          title={collapsed ? label : undefined}
          {...(g.id ? itemProps(to.slice(1)) : {})}
          className={({ isActive }) =>
            `sg-nav-item relative flex items-center ${collapsed ? 'mx-auto size-12 shrink-0 justify-center' : 'gap-4 px-3 py-2'} ${
              isActive ? 'font-bold text-accent-text' : 'font-medium text-text'
            } ${g.id ? pickedClass(to.slice(1)) : ''}`
          }
        >
          {({ isActive }) => (
            <>
              <Icon className="size-6 shrink-0" strokeWidth={isActive ? 2.5 : 2} aria-hidden />
              <span data-part="nav-label" className={collapsed ? 'sr-only' : 'min-w-0 flex-1 truncate leading-6'}>
                {label}
              </span>
              {to === '/' && pending > 0 && (
                <span
                  className={`num rounded-full bg-warn px-1.5 text-[11px] leading-5 font-semibold text-text-inverse ${collapsed ? 'absolute top-0.5 right-0.5 px-1 text-[10px] leading-4' : ''}`}
                  aria-label={`판정 대기 ${pending}건`}
                >
                  {pending}
                </span>
              )}
            </>
          )}
        </NavLink>
        ),
      )}
    </div>
  );
}

// 하위 메뉴(11/09 정책 화면 분리, SPEC-1109 §5): 펼친 사이드바 · 서랍 = 묶음 머리 + 들여 쓴 링크(11/10: 선 없이 머리 글자 줄에 맞춰 들여 씀 · 15/500, 지금 화면 700).
// 접힌 사이드바(56px) = 아이콘만, 올리면 120ms 뒤 · 초점이 들어오면 바로 오른쪽에 하위 메뉴만 겹쳐 뜬다(나가면 150ms 뒤 닫힘 — 틈을 건너는 동안)
// 접고 펴기(11/09 밤 사용자 결정): 펼친 사이드바 · 서랍에서 묶음 머리를 누르면(Enter · Space) 하위 메뉴가 접히고 펴진다(--dur-base, 동작 줄이기면 바로).
//   지금 화면이 속한 묶음은 늘 펼침(눌러도 접히지 않음 · 저장하지 않음), 다른 묶음은 마지막 상태를 이 브라우저에 기억 · 처음엔 접힘.
//   머리는 role="button" 칸 — 진짜 <button> 이면 useSortable 이 칸 안 단추로 보고 길게 눌러 옮기기를 막는다
const NAV_OPEN_KEY = 'supplyguard.nav.open.v1'; // { 묶음 id: 펼침 여부 } — 막혀 있거나 깨졌으면 처음처럼
function navOpenMap(): Record<string, unknown> {
  const v = loadJSON<unknown>(NAV_OPEN_KEY, {});
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
const subLink = ({ isActive }: { isActive: boolean }) =>
  `sg-nav-item sg-nav-sub flex items-center px-3 py-1.5 leading-6 ${isActive ? 'font-bold text-accent-text' : 'font-medium text-text-2 hover:text-text'}`;
function SubNav({
  id,
  label,
  icon: Icon,
  items,
  collapsed,
  sortProps,
  pickedClass,
}: {
  id: string;
  label: string;
  icon: LucideIcon;
  items: { to: string; label: string }[];
  collapsed: boolean;
  sortProps: Record<string, unknown>;
  pickedClass: string;
}) {
  const { pathname } = useLocation();
  const here = items.some((x) => pathname === x.to);
  const [saved, setSaved] = useState(() => navOpenMap()[id] === true);
  const open = here || saved;
  const toggle = () => {
    if (here) return;
    setSaved(!saved);
    saveJSON(NAV_OPEN_KEY, { ...navOpenMap(), [id]: !saved });
  };
  const box = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState(false);
  const [focusIn, setFocusIn] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const timer = useRef(0);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const place = () => {
    const r = box.current?.getBoundingClientRect();
    if (r) setPos({ top: r.top, left: r.right + 6 });
  };
  const later = (fn: () => void, ms: number) => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(fn, ms);
  };
  const shown = collapsed && (hover || focusIn) && pos;
  // 묶음 칸 초점: 정렬 묶음은 useSortable 이 준 tabIndex(Alt+↑/↓), 아니면 접힌 사이드바에서만(초점으로 하위 메뉴를 띄운다)
  const tab = typeof sortProps.tabIndex === 'number' ? sortProps.tabIndex : collapsed ? 0 : undefined;
  const foldId = `sg-subnav-${id}`;
  const links = items.map((x) => (
    <NavLink
      key={x.to}
      to={x.to}
      end
      state={FRESH}
      className={subLink}
      onClick={() => {
        window.clearTimeout(timer.current);
        setHover(false);
        setFocusIn(false);
      }}
    >
      {x.label}
    </NavLink>
  ));
  return (
    <div
      ref={box}
      {...sortProps}
      tabIndex={tab}
      data-nav-sub={id}
      data-open={String(open)}
      role="group"
      aria-label={label}
      className={`relative flex flex-col rounded-[24px] ${pickedClass}`}
      onMouseEnter={() => collapsed && later(() => (place(), setHover(true)), 120)}
      onMouseLeave={() => collapsed && later(() => setHover(false), 150)}
      onFocus={() => {
        if (!collapsed) return;
        place();
        setFocusIn(true);
      }}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setFocusIn(false);
      }}
    >
      {collapsed ? (
        <div className={`sg-nav-item mx-auto flex size-12 items-center justify-center ${here ? 'font-bold text-accent-text' : 'font-medium text-text'}`} title={label}>
          <Icon className="size-6 shrink-0" strokeWidth={here ? 2.5 : 2} aria-hidden />
          <span className="sr-only">{label}</span>
        </div>
      ) : (
        <div
          role="button"
          tabIndex={0}
          data-part="subnav-toggle"
          aria-expanded={open}
          aria-controls={foldId}
          aria-disabled={here ? 'true' : undefined}
          title={here ? '지금 화면이 속한 메뉴는 접을 수 없습니다' : undefined}
          onClick={toggle}
          onKeyDown={(e) => {
            if ((e.key !== 'Enter' && e.key !== ' ') || e.altKey || e.ctrlKey || e.metaKey) return;
            e.preventDefault();
            toggle();
          }}
          className={`sg-nav-item flex items-center gap-4 py-2 pr-3 pl-3 ${here ? 'sg-nav-here cursor-default font-bold text-text' : 'cursor-pointer font-medium text-text'}`}
        >
          <Icon className="size-6 shrink-0" strokeWidth={here ? 2.5 : 2} aria-hidden />
          <span className="min-w-0 flex-1 truncate leading-6">{label}</span>
          <ChevronDown
            data-part="subnav-chevron"
            className={`size-4 shrink-0 text-text-3 transition-transform duration-[var(--dur-fast)] ease-[var(--ease-move)] motion-reduce:transition-none ${open ? 'rotate-180' : ''}`}
            aria-hidden
          />
        </div>
      )}
      {!collapsed ? (
        // 접힘 = 높이 0 + visibility hidden(초점 · 화면 읽기에서 빠진다). 펼칠 때 grid 행 0fr → 1fr
        <div
          id={foldId}
          data-part="subnav-fold"
          className={`grid transition-[grid-template-rows,visibility] duration-[var(--dur-base)] ease-[var(--ease-move)] motion-reduce:transition-none ${open ? 'visible grid-rows-[1fr]' : 'invisible grid-rows-[0fr]'}`}
        >
          <div className="min-h-0 overflow-hidden">
            {/* 위아래 · 오른쪽 여백 = 링크 초점 링(바깥 2px)이 잘리지 않게. 왼쪽 40 = 링크 글자가 머리 글자(12 + 아이콘 24 + 사이 16)와 같은 줄 */}
            <div className="flex flex-col gap-0.5 py-[3px] pr-[3px] pl-10" data-part="subnav">
              {links}
            </div>
          </div>
        </div>
      ) : (
        shown && (
          <div
            data-part="subnav-pop"
            role="group"
            aria-label={`${label} 메뉴`}
            className="tk-pop-in fixed z-[60] flex min-w-40 flex-col gap-0.5 rounded-[10px] border border-border bg-raised p-1.5 shadow-[var(--sh-2)]"
            style={{ top: pos.top, left: pos.left }}
            onMouseEnter={() => window.clearTimeout(timer.current)}
          >
            <span className="px-3 pt-0.5 pb-1 text-[11px] font-medium tracking-wide text-text-3">{label}</span>
            {links}
          </div>
        )
      )}
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
        {/* 11/09 G38: 내부 이름(trace_dns · allowHosts · denyHosts · kind: dns)은 툴팁으로만 */}
        <b>도메인 판단 꺼짐</b>{' '}
        <span title="trace_dns 가젯 · allowHosts · denyHosts · 차단 목록 도메인 · kind: dns 규칙" className="underline decoration-dotted underline-offset-2">
          도메인 조회 감시가 뜨지 않아
        </span>{' '}
        도메인 기준 규칙(허용 · 금지 · 차단 도메인)과 DNS 질의 규칙이 통과 처리됩니다. IP · 포트 규칙만 동작합니다.{' '}
        <Link to="/settings" className="text-amber-800 underline">
          서버 설정 보기 →
        </Link>
      </span>
      <button
        type="button"
        aria-label="닫기"
        title="닫기"
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
