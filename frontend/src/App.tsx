import { useEffect, useMemo, useState } from 'react';
import { Activity, ArrowDownToLine, ChevronLeft, ChevronRight, CircleHelp, Globe2, Layers3, LayoutDashboard, Radio, Shield, ShieldAlert } from 'lucide-react';
import { errorMessage, getEvents, getHealth, getMetrics } from './api/client';
import { AnomalyScoreChart } from './components/AnomalyScoreChart';
import { ConnectionStatus } from './components/ConnectionStatus';
import { EventTable } from './components/EventTable';
import { MetricsPanel } from './components/MetricsPanel';
import { TrafficChart } from './components/TrafficChart';
import { useEventFilter } from './hooks/useEventFilter';
import { useWebSocket } from './hooks/useWebSocket';
import { useEventStore } from './store/eventStore';
import type { DetectionEvent, Health, Severity } from './types';

export default function App() {
  useWebSocket();
  const liveEvents = useEventStore(s => s.events), traffic = useEventStore(s => s.traffic);
  const [rows, setRows] = useState<DetectionEvent[]>([]), [health, setHealth] = useState<Health | null>(null);
  const [severity, setSeverity] = useState<Severity | ''>(''), [minutes, setMinutes] = useState(0);
  const [page, setPage] = useState(1), [total, setTotal] = useState(0), [loading, setLoading] = useState(true), [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0), [clock, setClock] = useState(Date.now());
  useEffect(() => { const timer = setInterval(() => setClock(Date.now()), 1000); return () => clearInterval(timer); }, []);
  useEffect(() => {
    let disposed = false;
    const load = () => {
      getHealth().then(value => { if (!disposed) setHealth(value); }).catch(() => { if (!disposed) setHealth(null); });
      getMetrics().then(metric => { if (!disposed) useEventStore.getState().setMetric(metric); }).catch(() => {});
    };
    load(); const timer = setInterval(load, 10000); return () => { disposed = true; clearInterval(timer); };
  }, []);
  const since = useMemo(() => minutes ? Date.now() - minutes * 60000 : 0, [minutes, refresh]);
  useEffect(() => {
    const controller = new AbortController(); setLoading(true); setError('');
    getEvents({ page, page_size: 20, severity: severity || undefined, start_time: since ? new Date(since).toISOString() : undefined }, controller.signal)
      .then(data => { setRows(data.items); setTotal(data.total); })
      .catch(e => { if (!controller.signal.aborted) setError(errorMessage(e)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [severity, since, page, refresh]);
  const combined = useMemo(() => page === 1 ? [...new Map([...liveEvents, ...rows].map(e => [e.event_id, e])).values()].sort((a,b) => b.event_id-a.event_id) : rows, [rows, liveEvents, page]);
  const filtered = useEventFilter(combined, severity, since).slice(0, 20);
  const matchingLive = useEventFilter(liveEvents, severity, since);
  const displayTotal = total + (page === 1 ? matchingLive.filter(e => e.event_id > (rows[0]?.event_id ?? 0)).length : 0);
  const latest = traffic.at(-1), isFresh = latest && clock - latest.timestamp < 3000;
  const exportEvents = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'ebpf-events.json'; anchor.click(); URL.revokeObjectURL(url);
  };
  return <div className="shell"><aside className="sidebar"><a className="brand" href="/"><div className="brand-mark"><Shield size={23}/></div><span>eBPF <b>Trace</b><small>NETWORK INTELLIGENCE</small></span></a>
    <div className="nav-caption">WORKSPACE</div><a className="nav-item active" href="#overview"><LayoutDashboard size={17}/>대시보드<span>01</span></a><a className="nav-item" href="#events"><ShieldAlert size={17}/>탐지 이벤트</a><a className="nav-item" href="#system"><Layers3 size={17}/>시스템 상태</a>
    <div className="sidebar-bottom"><div className="sensor-icon"><Radio size={19}/></div><strong>커널에서 시작하는 관찰</strong><p>패킷 흐름을 실시간으로 분석하고<br/>네트워크의 이상 징후를 발견합니다.</p><span><i/>{health?.collector_connected ? 'Collector 수집 중' : 'Collector 연결 대기'}</span></div>
  </aside><div className="workspace"><header className="topbar"><div className="breadcrumb">Workspace <span>/</span><b>Overview</b></div><div className="topbar-right"><ConnectionStatus/><span className="avatar">N</span></div></header>
    <main id="overview"><div className="page-heading"><div><div className="eyebrow">NETWORK OBSERVABILITY</div><h1>네트워크 대시보드</h1><p>트래픽의 흐름부터 위협의 징후까지, 한눈에 확인하세요.</p></div><div className="date"><Globe2 size={15}/>{new Date(clock).toLocaleDateString('ko-KR', { year:'numeric', month:'long', day:'numeric' })}</div></div>
      <div className="summary-grid">{[
        { label: '저장된 탐지 이벤트', value: displayTotal.toLocaleString(), suffix: '건', icon: ShieldAlert, color: 'blue', note: severity || minutes ? '현재 검색 조건 기준' : '전체 탐지 기록' },
        { label: '실시간 패킷', value: isFresh ? Math.round(latest.pkt_rate).toLocaleString() : '—', suffix: 'pps', icon: Activity, color: 'teal', note: '최근 1초 수집량' },
        { label: '실시간 대역폭', value: isFresh ? (latest.byte_rate * 8 / 1e6).toFixed(2) : '—', suffix: 'Mbps', icon: ArrowDownToLine, color: 'purple', note: '수신 트래픽 기준' },
        { label: '분석 엔진', value: health ? health.detection_mode === 'hybrid' ? '하이브리드' : '규칙 기반' : '연결 대기', suffix: '', icon: Shield, color: 'amber', note: health?.detection_mode === 'hybrid' ? '규칙 + Isolation Forest' : 'SYN Flood · Port Scan 탐지' },
      ].map(({ label, value, suffix, icon: Icon, color, note }) => <section className="summary-card" key={label}><div className="summary-top"><span>{label}</span><div className={`stat-icon ${color}`}><Icon size={18}/></div></div><div className="stat-value">{value}<small>{suffix}</small></div><div className="stat-note">{note}</div></section>)}</div>
      {error && <div className="error-banner" role="alert">{error}<button onClick={() => setRefresh(v => v + 1)}>다시 시도</button></div>}
      <div className="charts-grid" id="system"><TrafficChart/><div className="right-panels"><AnomalyScoreChart/><MetricsPanel/></div></div>
      <section className="panel events-panel" id="events"><div className="panel-heading"><div><h2>탐지 이벤트 <span className="count-pill">{displayTotal}</span></h2><p>실시간으로 탐지된 이상 트래픽과 위협 기록</p></div><button className="outline-button" onClick={exportEvents} disabled={!filtered.length}><ArrowDownToLine size={14}/>내보내기</button></div>
        <div className="filters"><label>심각도<select aria-label="심각도" value={severity} onChange={e => { setSeverity(e.target.value as Severity | ''); setPage(1); }}><option value="">전체 심각도</option>{['critical','high','medium','low'].map(value => <option key={value}>{value}</option>)}</select></label><label>기간<select aria-label="기간" value={minutes} onChange={e => { setMinutes(Number(e.target.value)); setPage(1); }}><option value={0}>전체 기간</option><option value={5}>최근 5분</option><option value={60}>최근 1시간</option><option value={1440}>최근 24시간</option></select></label><button className="text-button" onClick={() => setRefresh(v => v + 1)}>새로고침</button><span className="table-hint"><CircleHelp size={13}/>시각은 현재 기기 시간대 기준</span></div>
        <EventTable events={filtered} loading={loading}/><div className="pagination"><span>{displayTotal.toLocaleString()}개 기록 · {page} / {Math.max(1, Math.ceil(displayTotal/20))} 페이지</span><div><button aria-label="이전 페이지" disabled={page === 1} onClick={() => setPage(v => v-1)}><ChevronLeft size={16}/></button><button aria-label="다음 페이지" disabled={page*20 >= displayTotal} onClick={() => setPage(v => v+1)}><ChevronRight size={16}/></button></div></div>
      </section><footer>eBPF Trace <span>관찰 · 탐지 · 인사이트</span><span className="footer-right">모든 패킷은 정상 통과됩니다.</span></footer>
    </main></div></div>;
}
