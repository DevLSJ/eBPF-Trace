import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import './features.css';
import './analysis.css';
import './workspace.css';
import { ScenarioPanel } from './components/ScenarioPanel';
import { LiveInspectionPanel } from './components/LiveInspectionPanel';
import { EventsWorkspace } from './components/EventsWorkspace';
import { OperationsWorkspace } from './components/OperationsWorkspace';
import { Activity, ArrowDownToLine, Bell, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, CircleHelp, Clock3, FlaskConical, Globe2, Layers3, LayoutDashboard, Menu, Radio, Shield, ShieldAlert, Wifi } from 'lucide-react';
import { StatusBanner } from './components/StatusBanner';
import { OnboardingCard } from './components/OnboardingCard';
import { ToastHost } from './components/ToastHost';
import { NotificationDrawer } from './components/NotificationDrawer';
import { GUIDE_STEPS, GuideDialog } from './components/GuideDialog';
import { errorMessage, getEvents, getHealth, getMetrics, getThresholds } from './api/client';
import { CapturePanel } from './components/CapturePanel';
import { EventDetail } from './components/EventDetail';
import { ThresholdSettings } from './components/ThresholdSettings';
import { AnomalyScoreChart } from './components/AnomalyScoreChart';
import { ConnectionStatus } from './components/ConnectionStatus';
import { EventTable } from './components/EventTable';
import { MetricsPanel } from './components/MetricsPanel';
import { TrafficChart } from './components/TrafficChart';
import { useWebSocket } from './hooks/useWebSocket';
import { useSmoothScroll } from './hooks/useSmoothScroll';
import { useCountUp } from './hooks/useCountUp';
import { useNotifications } from './hooks/useNotifications';
import { useEventStore } from './store/eventStore';
import { unreadCount, useNotifyStore } from './store/notifyStore';
import type { DetectionEvent, Health, Severity } from './types';
import { ATTACK_TYPE_ORDER, SEVERITY, SEVERITY_ORDER, UNIT, attackTypeLabel, engineLabel, termTitle, withOriginal } from './labels';
import './ui.css';

// 사이드바 접힘 상태는 브라우저에 기억한다(로그인·토큰과 무관한 표시 설정).
const SIDEBAR_KEY = 'ebpf.sidebar.collapsed';
const readCollapsed = () => { try { return localStorage.getItem(SIDEBAR_KEY) === '1'; } catch { return false; } };

export default function Workspace() {
  useWebSocket();
  const [section, setSection] = useState(window.location.hash || '#overview');
  const [ipDraft, setIpDraft] = useState(''), [ip, setIp] = useState('');
  const analysisView = section === '#capture', settingsView = section === '#settings';
  const eventsView = section.startsWith('#events'), scenariosView = section.startsWith('#scenarios'), liveView = section.startsWith('#live');
  const operationsView = ['#incidents', '#operations', '#actions', '#notifications', '#assets', '#models'].includes(section.split('?')[0]);
  const overviewView = !analysisView && !settingsView && !eventsView && !scenariosView && !operationsView && !liveView;
  // 사용자 여정 순서: 로그인 없이 볼 수 있는 모니터링이 맨 위, 로그인이 필요한 위협 대응은 그 아래.
  const groups = [
    { id: 'monitor', label: '모니터링', caption: '로그인 없이 볼 수 있어요', items: [
      { href: '#overview', label: '대시보드', icon: LayoutDashboard, hint: '실시간 트래픽 · 상태 신호등 · 최근 탐지' },
      { href: '#live', label: '실시간 검사', icon: Wifi, hint: '내 와이파이·랜선 트래픽을 규칙 → AI → 대응까지 통과' },
      { href: '#events', label: '탐지 이벤트', icon: ShieldAlert, hint: '저장된 탐지 기록 검색과 검토' },
      { href: '#system', label: '시스템 상태', icon: Layers3, hint: '수집기 연결 · 서버 자원' },
    ] },
    { id: 'respond', label: '위협 대응', caption: '운영자 로그인 필요', items: [
      { href: '#incidents', label: '사건 대응', icon: ShieldAlert, hint: '사건 인수 → 조사 → 승인 → 복구' },
      { href: '#actions', label: '대응 관리', icon: Shield, hint: '승인 대기 · 실행 기록 · 자동 경로' },
      { href: '#notifications', label: '알림 센터', icon: Radio, hint: '슬랙·이메일 전달 기록' },
    ] },
    { id: 'lab', label: '실습·분석', caption: '체험하고 검증해요', items: [
      { href: '#scenarios', label: '탐지 시나리오', icon: FlaskConical, hint: '외부로 패킷을 보내지 않는 모의 탐지' },
      { href: '#capture', label: '데이터 분석', icon: Activity, hint: 'CIC-IDS-2017 정답 매칭과 모델 비교' },
      { href: '#supply', label: '공급망 안내 시연(LAB)', icon: Globe2, hint: '공급망 보안 안내 시연' },
    ] },
    { id: 'settings', label: '설정', caption: '관리자 비밀키 필요', items: [
      { href: '#settings', label: '탐지 설정', icon: Shield, hint: '탐지 임계값 조회와 변경' },
    ] },
  ];
  const navigation = groups.flatMap(group => group.items);
  const current = section.split('?')[0];
  const currentLabel = navigation.find(item => item.href === current)?.label ?? (operationsView ? '사건 대응' : '대시보드');
  const currentGroup = groups.find(group => group.items.some(item => item.href === current)) ?? (operationsView ? groups[1] : groups[0]);
  const viewKey = overviewView ? 'overview' : liveView ? 'live' : eventsView ? 'events' : scenariosView ? 'scenarios' : analysisView ? 'analysis' : settingsView ? 'settings' : 'operations';
  const flowStep = overviewView || liveView ? '#overview' : scenariosView ? '#scenarios' : eventsView ? '#events' : operationsView ? '#incidents' : analysisView ? '#capture' : '';
  useEffect(() => {
    const update = () => setSection(window.location.hash || '#overview');
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  useEffect(() => { document.title = `${currentLabel} · eBPF Trace`; }, [currentLabel]);

  // 셸: 페이지는 고정되고 본문(main)만 스크롤된다. 화면을 옮기면 본문 맨 위로.
  const mainRef = useRef<HTMLElement>(null);
  useSmoothScroll(mainRef);
  useEffect(() => {
    if (section === '#system') document.querySelector('#system')?.scrollIntoView({ block: 'start' });
    else mainRef.current?.scrollTo({ top: 0 });
  }, [section]);
  const [collapsed, setCollapsed] = useState(readCollapsed), [menuOpen, setMenuOpen] = useState(false), [guideOpen, setGuideOpen] = useState(false);
  const toggleCollapsed = () => setCollapsed(value => { const next = !value; try { localStorage.setItem(SIDEBAR_KEY, next ? '1' : '0'); } catch { /* 저장이 막힌 브라우저: 이번 세션에서만 유지 */ } return next; });
  useEffect(() => { setMenuOpen(false); }, [section]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement | null)?.closest('input, textarea, select, [contenteditable]')) return;
      if (e.key === '?') { e.preventDefault(); setGuideOpen(true); }
      else if (e.key === 'Escape') setMenuOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  // 알림 센터: 종 아이콘 배지는 읽지 않은 알림 수, 새 알림이 오면 배지가 한 번 튄다.
  const drawerOpen = useNotifyStore(s => s.drawerOpen), openDrawer = useNotifyStore(s => s.openDrawer);
  const notices = useNotifyStore(s => s.notices), bump = useNotifyStore(s => s.bump);
  const unread = unreadCount(notices), unreadEvents = notices.filter(n => !n.read && n.kind === 'event').length;
  const [bumping, setBumping] = useState(false);
  useEffect(() => { if (!bump) return; setBumping(true); const timer = setTimeout(() => setBumping(false), 600); return () => clearTimeout(timer); }, [bump]);

  const traffic = useEventStore(s => s.traffic);
  const status = useEventStore(s => s.status);
  const [rows, setRows] = useState<DetectionEvent[]>([]), [health, setHealth] = useState<Health | null>(null);
  const [healthFailed, setHealthFailed] = useState(false), [healthRetry, setHealthRetry] = useState(0);
  const [severity, setSeverity] = useState<Severity | ''>(''), [minutes, setMinutes] = useState(0);
  const [page, setPage] = useState(1), [total, setTotal] = useState(0), [loading, setLoading] = useState(true), [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0), [clock, setClock] = useState(Date.now());
  const [attackType, setAttackType] = useState(''), [selected, setSelected] = useState<number | null>(null);
  const [threshold, setThreshold] = useState(-0.1);
  useEffect(() => { const timer = setInterval(() => setClock(Date.now()), 1000); return () => clearInterval(timer); }, []);
  useEffect(() => {
    let disposed = false;
    const load = () => {
      getHealth().then(value => { if (!disposed) { setHealth(value); setHealthFailed(false); } }).catch(() => { if (!disposed) { setHealth(null); setHealthFailed(true); } });
      getMetrics().then(metric => { if (!disposed) useEventStore.getState().setMetric(metric); }).catch(() => {});
      getThresholds().then(value => { if (!disposed) setThreshold(value.anomaly_threshold); }).catch(() => {});
    };
    load(); const timer = setInterval(load, 10000); return () => { disposed = true; clearInterval(timer); };
  }, [healthRetry]);
  useNotifications(health, healthFailed);
  // "다시 시도"는 이벤트 목록과 서버 상태를 함께 다시 불러온다.
  const retry = () => { setRefresh(v => v + 1); setHealthRetry(v => v + 1); };
  const collectorState = !health ? (healthFailed ? 'error' : '') : health.collector_connected ? '' : 'warn';
  const collectorText = !health ? (healthFailed ? '서버 확인 불가' : '상태 확인 중') : health.collector_connected ? '수집기 연결됨' : '수집기 연결 대기';
  // REST remains authoritative for pagination, totals and reconnect recovery.
  useEffect(() => {
    let lastId = useEventStore.getState().events[0]?.event_id;
    let ticks = 0;
    const timer = setInterval(() => {
      const nextId = useEventStore.getState().events[0]?.event_id;
      if (nextId !== lastId || ++ticks >= 10) {
        lastId = nextId; ticks = 0; setRefresh(v => v + 1);
      }
    }, 1000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => { if (status === 'connected') setRefresh(v => v + 1); }, [status]);
  const since = useMemo(() => minutes ? Date.now() - minutes * 60000 : 0, [minutes, refresh]);
  useEffect(() => {
    const controller = new AbortController(); setLoading(true); setError('');
    getEvents({ source: 'live', page, page_size: 20, severity: severity || undefined, attack_type: attackType || undefined, ip: ip || undefined, start_time: since ? new Date(since).toISOString() : undefined }, controller.signal)
      .then(data => { setRows(data.items); setTotal(data.total); if (page > 1 && !data.items.length) setPage(Math.max(1, Math.ceil(data.total / 20))); })
      .catch(e => { if (!controller.signal.aborted) setError(errorMessage(e)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [severity, since, page, refresh, attackType, ip]);
  const filtered = rows;
  const displayTotal = total;
  const shownTotal = useCountUp(displayTotal);
  const latest = traffic.at(-1), isFresh = latest && clock - latest.timestamp < 3000;
  const waiting = <span className="stat-empty" title="최근 3초 안에 수집기로부터 받은 트래픽이 없습니다"><Clock3 size={13} aria-hidden="true"/>수집 대기</span>;
  const exportEvents = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'ebpf-events.json'; anchor.click(); URL.revokeObjectURL(url);
  };
  const filtering = Boolean(severity || minutes || attackType || ip);
  return <div className="shell">
    {menuOpen && <div className="sidebar-backdrop" onClick={() => setMenuOpen(false)} aria-hidden="true"/>}
    <aside className={`sidebar${collapsed ? ' collapsed' : ''}${menuOpen ? ' open' : ''}`} aria-label="사이드바">
      <div className="brand-row"><a className="brand" href="/" title="eBPF Trace 대시보드"><div className="brand-mark"><Shield size={23}/></div><span>eBPF <b>Trace</b><small>네트워크 위협 탐지</small></span></a><button className="sb-collapse" type="button" aria-label={collapsed ? '메뉴 펼치기' : '메뉴 접기'} aria-pressed={collapsed} title={collapsed ? '메뉴 펼치기' : '메뉴 접기'} onClick={toggleCollapsed}>{collapsed ? <ChevronsRight size={15}/> : <ChevronsLeft size={15}/>}</button></div>
      <nav aria-label="주 메뉴">{groups.map(group => <details className="nav-group" open key={group.id}><summary><span>{group.label}</span><small>{group.caption}</small></summary>{group.items.map(({ href, label, icon: Icon, hint }) => <a className={`nav-item ${current === href ? 'active' : ''}`} aria-current={current === href ? 'page' : undefined} href={href} key={href} title={collapsed ? label : hint}><Icon size={17}/><span className="nav-label">{label}</span>{href === '#events' && unreadEvents > 0 && <span className="nav-badge" aria-label={`읽지 않은 새 탐지 ${unreadEvents}건`}>{unreadEvents > 99 ? '99+' : unreadEvents}</span>}</a>)}</details>)}</nav>
      <div className="sidebar-bottom"><div className="sensor-icon"><Radio size={19}/></div><strong>커널에서 시작하는 관찰</strong><p>패킷 흐름을 실시간으로 분석하고<br/>네트워크의 이상 징후를 발견합니다.</p><span className={collectorState} title="네트워크 수집기(Collector) 연결 상태"><i/>{collectorText}</span></div>
    </aside>
    <div className="workspace">
      <header className="topbar">
        <div className="topbar-left"><button className="topbar-icon-button menu-button" type="button" aria-label="메뉴 열기" aria-expanded={menuOpen} onClick={() => setMenuOpen(v => !v)}><Menu size={18}/></button><div className="breadcrumb"><span className="crumb-root">eBPF Trace <span>/</span>{currentGroup.label} <span>/</span></span><b>{currentLabel}</b></div></div>
        <nav className="flow-rail" aria-label="사용 흐름">{GUIDE_STEPS.map((step, index) => <Fragment key={step.href}>{index > 0 && <span className="flow-sep" aria-hidden="true">›</span>}<a href={step.href} aria-current={flowStep === step.href ? 'step' : undefined} title={step.title}><i>{index + 1}</i>{step.label}</a></Fragment>)}</nav>
        <div className="topbar-right"><ConnectionStatus/><button className="topbar-icon-button" type="button" aria-label={unread ? `알림 센터 열기 · 읽지 않은 알림 ${unread}건` : '알림 센터 열기'} aria-expanded={drawerOpen} onClick={() => openDrawer(!drawerOpen)}><Bell size={17}/>{unread > 0 && <span className={`notify-count${bumping ? ' bump' : ''}`} aria-hidden="true">{unread > 99 ? '99+' : unread}</span>}</button><button className="topbar-icon-button" type="button" aria-label="사용 안내 열기" title="사용 안내 (?)" onClick={() => setGuideOpen(true)}><CircleHelp size={17}/></button><span className="avatar" title="공개 관측 화면 · 운영자 로그인은 사건 대응 메뉴에서">N</span></div>
      </header>
      <nav className="mobile-nav" aria-label="모바일 메뉴">{navigation.filter(item => item.href !== '#system').map(item => <a href={item.href} key={item.href} className={current === item.href ? 'active' : ''} aria-current={current === item.href ? 'page' : undefined}>{item.label}</a>)}</nav>
      <main id="overview" ref={mainRef} className={overviewView ? 'fixed-view' : undefined}><div className={`page page-enter view-${viewKey}`} key={viewKey}>
        {overviewView && <><div className="page-heading"><div><div className="eyebrow">실시간 모니터링</div><h1>네트워크 대시보드</h1><p>트래픽의 흐름부터 위협의 징후까지, 한눈에 확인하세요.</p></div><div className="date"><Globe2 size={15}/>{new Date(clock).toLocaleDateString('ko-KR', { year:'numeric', month:'long', day:'numeric' })}</div></div>
        {!health && !healthFailed ? <div className="health-banner" role="status">서버 상태를 확인하는 중…</div>
          : !health ? <StatusBanner level="error" title="서버에 연결할 수 없어요." cause="분석 서버가 상태 응답을 주지 않습니다. 네트워크 연결이나 서버 실행 상태를 확인한 뒤 다시 시도하세요." action={{ label: '다시 시도', onClick: retry }}/>
          : !health.collector_connected ? <StatusBanner level="warn" title="네트워크 수집기(Collector)가 아직 연결되지 않았어요." cause="잠시 기다리거나 아래에서 상태를 확인하세요. 연결될 때까지 실시간 그래프는 비어 있고, 저장된 탐지 기록은 계속 볼 수 있습니다." action={{ label: '상태 확인', href: '#system' }}/>
          : health.redis !== 'ok' ? <StatusBanner level="warn" title="실시간 저장소(Redis) 연결이 불안정해요." cause="규칙 탐지는 계속 동작합니다. 저장소가 복구되면 자동으로 정상 상태로 돌아옵니다." action={{ label: '상태 확인', href: '#system' }}/>
          : <StatusBanner level="ok" title="실시간으로 관찰하고 있어요." cause={`수집기 연결됨 · 저장소 정상 · 분석 엔진 ${engineLabel(health.detection_mode) || health.detection_mode}`}/>}
        <OnboardingCard/>
        <div className="summary-grid">{[
          { label: '저장된 탐지 이벤트', value: shownTotal.toLocaleString(), suffix: '건', icon: ShieldAlert, color: 'blue', note: filtering ? '현재 검색 조건 기준' : 'LIVE 탐지 기록' },
          { label: '실시간 초당 패킷', title: termTitle(UNIT.pps), value: isFresh ? Math.round(latest.pkt_rate).toLocaleString() : waiting, suffix: isFresh ? 'pps' : '', icon: Activity, color: 'teal', note: isFresh ? '최근 1초 수집량' : '최근 3초간 수신된 트래픽이 없습니다' },
          { label: '실시간 초당 전송량', title: termTitle(UNIT.mbps), value: isFresh ? (latest.byte_rate * 8 / 1e6).toFixed(2) : waiting, suffix: isFresh ? 'Mbps' : '', icon: ArrowDownToLine, color: 'purple', note: isFresh ? '수신 트래픽 기준' : '최근 3초간 수신된 트래픽이 없습니다' },
          { label: '분석 엔진', title: '탐지를 판단하는 방식', value: health ? engineLabel(health.detection_mode) || health.detection_mode : '연결 대기', suffix: '', icon: Shield, color: 'amber', note: health?.detection_mode === 'hybrid' ? '규칙 + 이상 탐지 AI(Isolation Forest)' : '연결 폭주 · 포트 스캔 등 규칙 탐지' },
        ].map(({ label, title, value, suffix, icon: Icon, color, note }) => <section className="summary-card" key={label}><div className="summary-top"><span className="term" title={title}>{label}</span><div className={`stat-icon ${color}`}><Icon size={18}/></div></div><div className="stat-value">{value}<small>{suffix}</small></div><div className="stat-note">{note}</div></section>)}</div>
        <a className="scenario-entry" href="#scenarios"><div className="scenario-entry-icon"><FlaskConical size={24}/></div><div><span>탐지 시나리오 체험</span><strong>공격 징후가 탐지 기록이 되는 순간</strong><p>포트 탐색부터 대량 전송까지 · 실제 엔진과 DB로 확인하는 모의 시나리오</p></div><b>시나리오 열기 ↗</b></a>
        <div className="charts-grid" id="system"><TrafficChart collector={health ? health.collector_connected : undefined}/><div className="right-panels"><AnomalyScoreChart threshold={threshold} mode={health?.detection_mode}/><MetricsPanel/></div></div>
        {error && <div className="error-banner" role="alert">{error}<button onClick={retry}>다시 시도</button></div>}
        <section className="panel events-panel" id="events"><div className="panel-heading"><div><h2>탐지 이벤트 <span className="count-pill">{displayTotal}</span></h2><p>실시간으로 탐지된 이상 트래픽과 위협 기록 · 행을 눌러 판단 근거를 확인하세요</p></div><button className="outline-button" onClick={exportEvents} disabled={!filtered.length || loading}><ArrowDownToLine size={14}/>현재 페이지 내보내기</button></div>
          <div className="filters"><label>심각도<select aria-label="심각도" value={severity} onChange={e => { setSeverity(e.target.value as Severity | ''); setPage(1); }}><option value="">전체 심각도</option>{SEVERITY_ORDER.map(value => <option key={value} value={value}>{withOriginal(SEVERITY[value])}</option>)}</select></label><label>기간<select aria-label="기간" value={minutes} onChange={e => { setMinutes(Number(e.target.value)); setPage(1); }}><option value={0}>전체 기간</option><option value={5}>최근 5분</option><option value={60}>최근 1시간</option><option value={1440}>최근 24시간</option></select></label><button className="text-button" onClick={() => setRefresh(v => v + 1)}>새로고침</button><span className="table-hint"><CircleHelp size={13}/>시각은 현재 기기 시간대 기준</span></div>
          <div className="type-filter"><label>탐지 유형<select aria-label="탐지 유형" value={attackType} onChange={e => { setAttackType(e.target.value); setPage(1); }}><option value="">전체 유형</option>{ATTACK_TYPE_ORDER.map(type => <option value={type} key={type}>{attackTypeLabel(type)}</option>)}</select></label><form className="ip-search" onSubmit={e => { e.preventDefault(); setIp(ipDraft.trim()); setPage(1); }}><label htmlFor="event-ip">IP 주소</label><input id="event-ip" aria-label="IP 주소 검색" value={ipDraft} onChange={e => setIpDraft(e.target.value)} placeholder="출발지 또는 목적지 IP"/><button type="submit">검색</button>{ip && <button className="clear-search" type="button" onClick={() => { setIp(''); setIpDraft(''); setPage(1); }}>초기화</button>}</form></div>
          <EventTable events={filtered} loading={loading} onSelect={setSelected}/><div className="pagination"><span>{displayTotal.toLocaleString()}개 기록 · {page} / {Math.max(1, Math.ceil(displayTotal/20))} 페이지</span><div><button aria-label="이전 페이지" disabled={page === 1 || loading} onClick={() => setPage(v => v-1)}><ChevronLeft size={16}/></button><button aria-label="다음 페이지" disabled={page*20 >= displayTotal || loading} onClick={() => setPage(v => v+1)}><ChevronRight size={16}/></button></div></div>
        </section></>}
        {operationsView && <OperationsWorkspace hash={section}/>}
        {eventsView && <EventsWorkspace key={section} hash={section}/>}
        {scenariosView && <ScenarioPanel key={section}/>}
        {liveView && <LiveInspectionPanel key={section}/>}
        {analysisView && <CapturePanel/>}
        {settingsView && <ThresholdSettings onSaved={value => setThreshold(value.anomaly_threshold)}/>}
        <footer>eBPF Trace <span>관찰 · 판단 · 대응 · 복구</span><span className="footer-right">XDP 수집기는 관측 전용 · 대응은 별도 승인 정책으로 실행됩니다.</span></footer>
      </div></main>
    </div>
    {drawerOpen && <NotificationDrawer onClose={() => openDrawer(false)} onOpenEvent={id => setSelected(id)}/>}
    <GuideDialog open={guideOpen} onClose={() => setGuideOpen(false)}/>
    <ToastHost/>
    {selected !== null && <EventDetail key={selected} id={selected} onClose={() => setSelected(null)}/>}
  </div>;
}
