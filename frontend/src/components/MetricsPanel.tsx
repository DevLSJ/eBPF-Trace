import { Cpu, MemoryStick } from 'lucide-react';
import { useEventStore } from '../store/eventStore';

export function MetricsPanel() {
  const metric = useEventStore(s => s.metric);
  return <section className="panel metrics-panel"><div className="panel-heading"><div><h2>시스템 상태</h2><p>분석 서버 리소스 · 10초 갱신</p></div></div>
    {[{ label: 'CPU 사용률', value: metric?.cpu_percent, icon: Cpu, color: '#4079ed' }, { label: '메모리 사용률', value: metric?.memory_percent, icon: MemoryStick, color: '#17a994' }].map(({ label, value, icon: Icon, color }) =>
      <div className="resource" key={label}><div className="resource-label"><span><Icon size={17}/>{label}</span><strong>{value === undefined ? '—' : `${value.toFixed(1)}%`}</strong></div><div className="meter" role="meter" aria-label={label} aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}><div style={{ width: `${value || 0}%`, background: color }}/></div></div>)}
    <div className="metric-footer"><i/>{metric ? `최근 수집 ${new Date(metric.collected_at).toLocaleTimeString('ko-KR', { hour12: false })}` : '메트릭 수신 대기 중'}</div>
  </section>;
}
