import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { useEventStore } from '../store/eventStore';

export function AnomalyScoreChart() {
  const traffic = useEventStore(s => s.traffic);
  const hasScores = traffic.some(p => p.anomaly_score !== null);
  return <section className="panel"><div className="panel-heading"><div><h2>이상 점수 추이</h2><p>점수가 낮을수록 이상 가능성 증가</p></div><span className="subtle-label">Isolation Forest</span></div>
    <div className="chart score-chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={traffic} margin={{ top: 16, right: 18, left: 0, bottom: 0 }}>
      <CartesianGrid stroke="#eaf0f6" vertical={false}/><XAxis dataKey="timestamp" tickFormatter={v => new Date(v).toLocaleTimeString('ko-KR', { minute: '2-digit', second: '2-digit' })} tickLine={false} axisLine={false} minTickGap={55} fontSize={11}/>
      <YAxis domain={[-1, 0]} width={42} tickLine={false} axisLine={false} fontSize={11}/><Tooltip/>
      <ReferenceLine y={-0.1} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: '임계값 −0.1', position: 'insideBottomRight', fontSize: 10, fill: '#b47813' }}/>
      <Line type="monotone" dataKey="anomaly_score" stroke="#8a64d6" strokeWidth={2} dot={false} isAnimationActive={false}/>
    </LineChart></ResponsiveContainer>{!hasScores && <div className="chart-empty">ML 점수 데이터가 아직 없습니다.</div>}</div>
  </section>;
}
