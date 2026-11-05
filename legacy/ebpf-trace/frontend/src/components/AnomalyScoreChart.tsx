import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { useEventStore } from '../store/eventStore';
import { Term } from './Term';
import { UNIT } from '../labels';

export function AnomalyScoreChart({ threshold = -0.1, mode }: { threshold?: number; mode?: string }) {
  const traffic = useEventStore(s => s.traffic);
  const hasScores = traffic.some(p => p.anomaly_score !== null);
  // 빈 상태 구분: 트래픽 자체가 없음 → 연결 대기, 규칙만 사용 → AI 점수 없음(정상), 그 외 → 아직 계산 전
  const waiting = !traffic.length;
  const emptyText = waiting ? '연결 대기 · 트래픽이 들어오면 점수가 표시돼요' : mode && mode !== 'hybrid' ? '데이터 없음 · 규칙만 사용 중이라 AI 점수가 없어요' : '데이터 없음 · 아직 AI 점수가 계산되지 않았어요';
  return <section className="panel"><div className="panel-heading"><div><h2><Term term={UNIT.anomalyScore}/> 추이</h2><p>0에 가까우면 정상, −1에 가까울수록 의심 · 점선은 판단 기준선</p></div><span className="subtle-label" title="이 점수보다 낮으면 이상으로 판단합니다 (anomaly_threshold)">임계값 {threshold}</span></div>
    <div className="chart score-chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={traffic} margin={{ top: 16, right: 18, left: 0, bottom: 0 }}>
      <CartesianGrid stroke="#eaf0f6" vertical={false}/><XAxis dataKey="timestamp" tickFormatter={v => new Date(v).toLocaleTimeString('ko-KR', { minute: '2-digit', second: '2-digit' })} tickLine={false} axisLine={false} minTickGap={55} fontSize={11}/>
      <YAxis domain={[-1, 0]} width={42} tickLine={false} axisLine={false} fontSize={11}/><Tooltip/>
      <ReferenceLine y={threshold} stroke="#f59e0b" strokeDasharray="4 4"/>
      <Line type="monotone" dataKey="anomaly_score" stroke="#8a64d6" strokeWidth={2} dot={false} isAnimationActive={false}/>
    </LineChart></ResponsiveContainer>{!hasScores && <div className={`chart-empty${waiting ? ' waiting' : ''}`} role="status">{emptyText}</div>}</div>
  </section>;
}
