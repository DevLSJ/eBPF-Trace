import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { useEventStore } from '../store/eventStore';
import { Term } from './Term';
import { UNIT } from '../labels';

const time = (value: number) => new Date(value).toLocaleTimeString('ko-KR', { hour12: false, minute: '2-digit', second: '2-digit' });
export function TrafficChart({ collector }: { collector?: boolean }) {
  const traffic = useEventStore(s => s.traffic);
  const status = useEventStore(s => s.status);
  // 빈 상태 구분: 실시간 연결 끊김 / 수집기 미연결 → 연결 대기, 그 외 → 데이터 없음
  const waiting = status !== 'connected' || collector === false;
  const emptyText = status !== 'connected' ? '연결 대기 · 대시보드와 서버의 실시간 연결이 끊겨 있어요' : collector === false ? '연결 대기 · 네트워크 수집기가 아직 연결되지 않았어요' : '데이터 없음 · 최근 5분간 수신된 트래픽이 없어요';
  return <section className="panel traffic-panel"><div className="panel-heading"><div><h2>트래픽 현황</h2><p>최근 5분간 수집된 네트워크 흐름</p></div><span className="live-tag">LIVE</span></div>
    <div className="chart-legend"><span><i className="blue-dot"/><Term term={UNIT.pps}/></span><span><i className="teal-dot"/><Term term={UNIT.bps}/></span></div>
    <div className="chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={traffic.map(p => ({ ...p, bits: p.byte_rate * 8 }))} margin={{ top: 12, right: 8, bottom: 0, left: 0 }}>
      <defs><linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#4079ed" stopOpacity={0.24}/><stop offset="100%" stopColor="#4079ed" stopOpacity={0}/></linearGradient></defs>
      <CartesianGrid stroke="#eaf0f6" vertical={false}/><XAxis dataKey="timestamp" tickFormatter={time} minTickGap={40} tickLine={false} axisLine={false} fontSize={11}/>
      <YAxis yAxisId="pps" width={48} tickLine={false} axisLine={false} fontSize={11}/><YAxis yAxisId="bits" orientation="right" hide/>
      <Tooltip labelFormatter={value => time(Number(value))}/><Area yAxisId="pps" name="초당 패킷(pps)" type="monotone" dataKey="pkt_rate" stroke="#4079ed" strokeWidth={2} fill="url(#trafficFill)" isAnimationActive={false}/>
      <Area yAxisId="bits" name="초당 비트(bps)" type="monotone" dataKey="bits" stroke="#17a994" strokeWidth={1.5} fill="none" isAnimationActive={false}/>
    </AreaChart></ResponsiveContainer>{!traffic.length && <div className={`chart-empty${waiting ? ' waiting' : ''}`} role="status">{emptyText}</div>}</div>
  </section>;
}
