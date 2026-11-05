import { ArrowUpRight, ShieldCheck } from 'lucide-react';
import type { DetectionEvent } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { Term } from './Term';
import { UNIT, attackTypeLabel, attackTypeTerm, termTitle } from '../labels';

export function EventTable({ events, loading, onSelect }: { events: DetectionEvent[]; loading: boolean; onSelect: (id: number) => void }) {
  return <div className="table-wrap"><table><thead><tr><th>탐지 시간</th><th>출발지 → 목적지</th><th>탐지 유형</th><th>심각도</th><th><Term term={UNIT.pps}/></th><th><Term term={UNIT.anomalyScore} short/></th></tr></thead>
    <tbody>{events.map(event => <tr key={event.event_id}><td><span className="table-time">{new Date(event.detected_at).toLocaleTimeString('ko-KR', { hour12: false })}</span><small>{new Date(event.detected_at).toLocaleDateString('ko-KR')}</small></td>
      <td><span className="address">{event.flow.src_ip}<ArrowUpRight size={13}/>{event.flow.dst_ip}</span><small>{event.flow.protocol === 6 ? 'TCP' : 'UDP'} · {event.flow.src_port} → {event.flow.dst_port}</small></td>
      <td className="attack-type"><button className="event-link" aria-label={`이벤트 ${event.event_id} 상세 보기`} title={termTitle(attackTypeTerm(event.attack_type))} onClick={() => onSelect(event.event_id)}>{attackTypeLabel(event.attack_type)}</button><small className={event.source === 'simulation' ? 'simulation-label' : ''}>{event.source === 'simulation' ? '모의(SIMULATION)' : '실제(LIVE)'} · {event.is_confirmed === true ? '정탐 확인' : event.is_confirmed === false ? '오탐 확인' : '검토 대기'}</small></td><td><SeverityBadge severity={event.severity}/></td><td className="number">{Math.round(event.features.pkt_rate).toLocaleString()}</td><td className="number">{event.anomaly_score?.toFixed(3) ?? <span className="rule-only" title="AI 점수 없이 규칙으로 탐지한 기록입니다">규칙 탐지</span>}</td></tr>)}</tbody></table>
    {/* 빈 상태 구분: 불러오는 중(스켈레톤) / 조건에 맞는 기록 없음 */}
    {!events.length && (loading
      ? <div className="table-skeleton" role="status" aria-label="탐지 기록을 불러오는 중입니다"><div/><div/><div/><div/><div/></div>
      : <div className="table-empty"><ShieldCheck size={34}/><strong>조건에 맞는 탐지 이벤트가 없습니다.</strong><p>새로운 위협이 감지되면 이곳에 표시됩니다.</p></div>)}
  </div>;
}
