import { ArrowUpRight, ShieldCheck } from 'lucide-react';
import type { DetectionEvent } from '../types';
import { SeverityBadge } from './SeverityBadge';

export function EventTable({ events, loading }: { events: DetectionEvent[]; loading: boolean }) {
  return <div className="table-wrap"><table><thead><tr><th>탐지 시간</th><th>출발지 → 목적지</th><th>탐지 유형</th><th>심각도</th><th>패킷 / s</th><th>이상 점수</th></tr></thead>
    <tbody>{events.map(event => <tr key={event.event_id}><td><span className="table-time">{new Date(event.detected_at).toLocaleTimeString('ko-KR', { hour12: false })}</span><small>{new Date(event.detected_at).toLocaleDateString('ko-KR')}</small></td>
      <td><span className="address">{event.flow.src_ip}<ArrowUpRight size={13}/>{event.flow.dst_ip}</span><small>{event.flow.protocol === 6 ? 'TCP' : 'UDP'} · {event.flow.src_port} → {event.flow.dst_port}</small></td>
      <td className="attack-type">{event.attack_type.replaceAll('_', ' ')}</td><td><SeverityBadge severity={event.severity}/></td><td className="number">{Math.round(event.features.pkt_rate).toLocaleString()}</td><td className="number">{event.anomaly_score?.toFixed(3) ?? '—'}</td></tr>)}</tbody></table>
    {!events.length && <div className="table-empty"><ShieldCheck size={34}/><strong>{loading ? '탐지 기록을 불러오는 중입니다.' : '조건에 맞는 탐지 이벤트가 없습니다.'}</strong><p>새로운 위협이 감지되면 이곳에 표시됩니다.</p></div>}
  </div>;
}
