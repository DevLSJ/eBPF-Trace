import { useEffect, useMemo, useState } from 'react';
import './features.css';
import './analysis.css';
import './workspace.css';
import { ScenarioPanel } from './components/ScenarioPanel';
import { EventsWorkspace } from './components/EventsWorkspace';
import { OperationsWorkspace } from './components/OperationsWorkspace';
import { Activity, ArrowDownToLine, ChevronLeft, ChevronRight, CircleHelp, FlaskConical, Globe2, Layers3, LayoutDashboard, Radio, Shield, ShieldAlert } from 'lucide-react';
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
import { useEventStore } from './store/eventStore';
import type { DetectionEvent, Health, Severity } from './types';

export default function App() {
  useWebSocket();
  const [section, setSection] = useState(window.location.hash || '#incidents');
  const [ipDraft, setIpDraft] = useState(''), [ip, setIp] = useState('');
  const analysisView = section === '#capture', settingsView = section === '#settings';
  const eventsView = section.startsWith('#events'), scenariosView = section.startsWith('#scenarios');
  const operationsView = ['#incidents', '#operations', '#actions', '#notifications', '#assets', '#models'].includes(section.split('?')[0]);
  const overviewView = !analysisView && !settingsView && !eventsView && !scenariosView && !operationsView;
  const navigation = [
    { href: '#incidents', label: '사건 대응', icon: ShieldAlert },
    { href: '#actions', label: '대응 관리', icon: Shield },
    { href: '#notifications', label: '알림 센터', icon: Radio },
    { href: '#overview', label: '대시보드', icon: LayoutDashboard },
    { href: '#events', label: '탐지 이벤트', icon: ShieldAlert },
    { href: '#scenarios', label: '탐지 시나리오', icon: FlaskConical },
    { href: '#system', label: '시스템 상태', icon: Layers3 },
    { href: '#capture', label: '데이터 분석', icon: Activity },
    { href: '#settings', label: '탐지 설정', icon: Shield },
  ];
  useEffect(() => {
    const update = () => setSection(window.location.hash || '#incidents');
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  useEffect(() => {
    if (section === '#system') document.querySelector('#system')?.scrollIntoView();
    else window.scrollTo(0, 0);
  }, [section]);
  const traffic = useEventStore(s => s.traffic);
  const status = useEventStore(s => s.status);
  const [rows, setRows] = useState<DetectionEvent[]>([]), [health, setHealth] = useState<Health | null>(null);
  const [severity, setSeverity] = useState<Severity | ''>(''), [minutes, setMinutes] = useState(0);
  const [page, setPage] = useState(1), [total, setTotal] = useState(0), [loading, setLoading] = useState(true), [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0), [clock, setClock] = useState(Date.now());
  const [attackType, setAttackType] = useState(''), [selected, setSelected] = useState<number | null>(null);
  const [threshold, setThreshold] = useState(-0.1);
  useEffect(() => { const timer = setInterval(() => setClock(Date.now()), 1000); return () => clearInterval(timer); }, []);
  useEffect(() => {
    let disposed = false;
    const load = () => {
      getHealth().then(value => { if (!disposed) setHealth(value); }).catch(() => { if (!disposed) setHealth(null); });
      getMetrics().then(metric => { if (!disposed) useEventStore.getState().setMetric(metric); }).catch(() => {});
      getThresholds().then(value => { if (!disposed) setThreshold(value.anomaly_threshold); }).catch(() => {});
    };
    load(); const timer = setInterval(load, 10000); return () => { disposed = true; clearInterval(timer); };
  }, []);
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
  const latest = traffic.at(-1), isFresh = latest && clock - latest.timestamp < 3000;
  const exportEvents = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'ebpf-events.json'; anchor.click(); URL.revokeObjectURL(url);
  };
  return <div className="shell"><aside className="sidebar"><a className="brand" href="/"><div className="brand-mark"><Shield size={23}/></div><span>eBPF <b>Trace</b><small>NETWORK INTELLIGENCE</small></span></a>
    <div className="nav-caption">WORKSPACE</div><nav aria-label="주 메뉴">{navigation.map(({ href, label, icon: Icon }) => <a className={`nav-item ${section.split('?')[0] === href ? 'active' : ''}`} aria-current={section.split('?')[0] === href ? 'page' : undefined} href={href} key={href}><Icon size={17}/>{label}</a>)}</nav>
    <div className="sidebar-bottom"><div className="sensor-icon"><Radio size={19}/></div><strong>커널에서 시작하는 관찰</strong><p>패킷 흐름을 실시간으로 분석하고<br/>네트워크의 이상 징후를 발견합니다.</p><span><i/>{health?.collector_connected ? 'Collector 수집 중' : 'Collector 연결 대기'}</span></div>
  </aside><div className="workspace"><header className="topbar"><div className="breadcrumb">Workspace <span>/</span><b>{operationsView ? 'Incident response' : analysisView ? 'Data analysis' : settingsView ? 'Detection settings' : eventsView ? 'Detection events' : scenariosView ? 'Scenarios' : 'Overview'}</b></div><div className="topbar-right"><ConnectionStatus/><span className="avatar">N</span></div></header>
    <nav className="mobile-nav" aria-label="모바일 메뉴">{navigation.filter(item => item.href !== '#system').map(item => <a href={item.href} key={item.href} className={section.split('?')[0] === item.href ? 'active' : ''} aria-current={section.split('?')[0] === item.href ? 'page' : undefined}>{item.label}</a>)}</nav>
    <main id="overview">{overviewView && <><div className="page-heading"><div><div className="eyebrow">NETWORK OBSERVABILITY</div><h1>네트워크 대시보드</h1><p>트래픽의 흐름부터 위협의 징후까지, 한눈에 확인하세요.</p></div><div className="date"><Globe2 size={15}/>{new Date(clock).toLocaleDateString('ko-KR', { year:'numeric', month:'long', day:'numeric' })}</div></div>
      <div className="summary-grid">{[
        { label: '저장된 탐지 이벤트', value: displayTotal.toLocaleString(), suffix: '건', icon: ShieldAlert, color: 'blue', note: severity || minutes || attackType || ip ? '현재 검색 조건 기준' : 'LIVE 탐지 기록' },
        { label: '실시간 패킷', value: isFresh ? Math.round(latest.pkt_rate).toLocaleString() : '—', suffix: 'pps', icon: Activity, color: 'teal', note: '최근 1초 수집량' },
        { label: '실시간 대역폭', value: isFresh ? (latest.byte_rate * 8 / 1e6).toFixed(2) : '—', suffix: 'Mbps', icon: ArrowDownToLine, color: 'purple', note: '수신 트래픽 기준' },
        { label: '분석 엔진', value: health ? health.detection_mode === 'hybrid' ? '하이브리드' : '규칙 기반' : '연결 대기', suffix: '', icon: Shield, color: 'amber', note: health?.detection_mode === 'hybrid' ? '규칙 + Isolation Forest' : 'SYN Flood · Port Scan 탐지' },
      ].map(({ label, value, suffix, icon: Icon, color, note }) => <section className="summary-card" key={label}><div className="summary-top"><span>{label}</span><div className={`stat-icon ${color}`}><Icon size={18}/></div></div><div className="stat-value">{value}<small>{suffix}</small></div><div className="stat-note">{note}</div></section>)}</div>
      {error && <div className="error-banner" role="alert">{error}<button onClick={() => setRefresh(v => v + 1)}>다시 시도</button></div>}
      {(!health || !health.collector_connected || health.redis !== 'ok') && <div className="health-banner" role="status">{!health ? '서버 상태를 확인할 수 없습니다.' : !health.collector_connected ? 'Collector 연결 대기 · VM 수집기와 터널 상태를 확인하세요.' : 'Redis 연결 저하 · 규칙 기반 탐지는 계속 동작합니다.'}</div>}
      <a className="scenario-entry" href="#scenarios"><div className="scenario-entry-icon"><FlaskConical size={24}/></div><div><span>TRY A DETECTION SCENARIO</span><strong>공격 징후가 탐지 기록이 되는 순간</strong><p>포트 탐색부터 대량 전송까지 · 실제 엔진과 DB로 확인하는 모의 시나리오</p></div><b>시나리오 열기 ↗</b></a>
      <div className="charts-grid" id="system"><TrafficChart/><div className="right-panels"><AnomalyScoreChart threshold={threshold}/><MetricsPanel/></div></div>
      <section className="panel events-panel" id="events"><div className="panel-heading"><div><h2>탐지 이벤트 <span className="count-pill">{displayTotal}</span></h2><p>실시간으로 탐지된 이상 트래픽과 위협 기록</p></div><button className="outline-button" onClick={exportEvents} disabled={!filtered.length || loading}><ArrowDownToLine size={14}/>현재 페이지 내보내기</button></div>
        <div className="filters"><label>심각도<select aria-label="심각도" value={severity} onChange={e => { setSeverity(e.target.value as Severity | ''); setPage(1); }}><option value="">전체 심각도</option>{['critical','high','medium','low'].map(value => <option key={value}>{value}</option>)}</select></label><label>기간<select aria-label="기간" value={minutes} onChange={e => { setMinutes(Number(e.target.value)); setPage(1); }}><option value={0}>전체 기간</option><option value={5}>최근 5분</option><option value={60}>최근 1시간</option><option value={1440}>최근 24시간</option></select></label><button className="text-button" onClick={() => setRefresh(v => v + 1)}>새로고침</button><span className="table-hint"><CircleHelp size={13}/>시각은 현재 기기 시간대 기준</span></div>
        <div className="type-filter"><label>탐지 유형<select aria-label="탐지 유형" value={attackType} onChange={e => { setAttackType(e.target.value); setPage(1); }}><option value="">전체 유형</option>{['SYN_FLOOD', 'PORT_SCAN', 'TRAFFIC_SPIKE', 'LARGE_FLOW', 'ANOMALY'].map(type => <option value={type} key={type}>{type.replaceAll('_', ' ')}</option>)}</select></label><form className="ip-search" onSubmit={e => { e.preventDefault(); setIp(ipDraft.trim()); setPage(1); }}><label htmlFor="event-ip">IP 주소</label><input id="event-ip" aria-label="IP 주소 검색" value={ipDraft} onChange={e => setIpDraft(e.target.value)} placeholder="출발지 또는 목적지 IP"/><button type="submit">검색</button>{ip && <button className="clear-search" type="button" onClick={() => { setIp(''); setIpDraft(''); setPage(1); }}>초기화</button>}</form></div>
        <EventTable events={filtered} loading={loading} onSelect={setSelected}/><div className="pagination"><span>{displayTotal.toLocaleString()}개 기록 · {page} / {Math.max(1, Math.ceil(displayTotal/20))} 페이지</span><div><button aria-label="이전 페이지" disabled={page === 1 || loading} onClick={() => setPage(v => v-1)}><ChevronLeft size={16}/></button><button aria-label="다음 페이지" disabled={page*20 >= displayTotal || loading} onClick={() => setPage(v => v+1)}><ChevronRight size={16}/></button></div></div>
      </section></>}{operationsView && <OperationsWorkspace hash={section}/>} {eventsView && <EventsWorkspace key={section} hash={section}/>}{scenariosView && <ScenarioPanel key={section}/>}{analysisView && <CapturePanel/>}{settingsView && <ThresholdSettings onSaved={value => setThreshold(value.anomaly_threshold)}/>}<footer>eBPF Trace <span>관찰 · 판단 · 대응 · 복구</span><span className="footer-right">XDP 수집기는 관측 전용 · 대응은 별도 승인 정책으로 실행됩니다.</span></footer>
    </main></div>{selected !== null && <EventDetail key={selected} id={selected} onClose={() => setSelected(null)}/>}</div>;
}
