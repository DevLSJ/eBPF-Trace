import { useEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';
import { errorMessage, getEvent } from '../api/client';
import type { DetectionEvent } from '../types';
import { SeverityBadge } from './SeverityBadge';

const featureLabels: Record<string, string> = {
  pkt_rate: '패킷 수 / s', byte_rate: '바이트 / s', syn_ratio: 'SYN 비율',
  port_entropy: '포트 엔트로피', port_cnt: '목적지 포트 수 (10초)',
  flow_duration: '플로우 지속 시간 (ms)', avg_pkt_size: '평균 패킷 크기 (bytes)',
  source_pkt_rate: '출발지 패킷 / s', source_syn_rate: '출발지 SYN / s',
};

export function EventDetail({ id, onClose }: { id: number; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [event, setEvent] = useState<DetectionEvent | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    const element = dialog.current;
    element?.showModal();
    getEvent(id, controller.signal).then(setEvent).catch(e => {
      if (!controller.signal.aborted) setError(errorMessage(e));
    });
    return () => { controller.abort(); element?.close(); };
  }, [id]);
  return <dialog ref={dialog} className="detail-dialog" onCancel={onClose} aria-labelledby="event-detail-title">
    <div className="panel-heading"><h2 id="event-detail-title">탐지 이벤트 #{id}</h2><button className="icon-button" aria-label="상세 닫기" onClick={onClose}><X size={20}/></button></div>
    {error ? <p role="alert">{error}</p> : !event ? <p role="status">상세 정보를 불러오는 중입니다.</p> : <>
      <div className="detail-intro"><SeverityBadge severity={event.severity}/><strong>{event.attack_type.replaceAll('_', ' ')}</strong><p>{new Date(event.detected_at).toLocaleString('ko-KR')}</p></div>
      <dl className="detail-grid">
        <div><dt>출발지</dt><dd>{event.flow.src_ip}:{event.flow.src_port}</dd></div>
        <div><dt>목적지</dt><dd>{event.flow.dst_ip}:{event.flow.dst_port}</dd></div>
        <div><dt>프로토콜</dt><dd>{event.flow.protocol === 6 ? 'TCP' : 'UDP'}</dd></div>
        <div><dt>ML 이상 점수</dt><dd>{event.anomaly_score?.toFixed(4) ?? '미제공 (규칙 기반)'}</dd></div>
        {Object.entries(event.features).map(([key, value]) => <div key={key}><dt>{featureLabels[key] || key}</dt><dd>{value.toLocaleString('ko-KR', { maximumFractionDigits: 4 })}</dd></div>)}
      </dl>
    </>}
  </dialog>;
}
