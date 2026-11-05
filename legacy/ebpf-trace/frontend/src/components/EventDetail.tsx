import { useEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';
import { errorMessage, getEvent, reviewEvent } from '../api/client';
import type { DetectionEvent } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { Term } from './Term';
import { SEVERITY, UNIT, attackTypeLabel, attackTypeTerm, termTitle } from '../labels';

// 사람이 읽는 한 문장 요약. 실제 관측값으로만 만들고, 값이 없으면 null(폴백 문구 표시).
const finite = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
export function summarizeEvent(event: DetectionEvent): string | null {
  const f = event.features, { src_ip, dst_ip, dst_port } = event.flow;
  const pps = finite(f.pkt_rate) ? Math.round(f.pkt_rate).toLocaleString('ko-KR') : null;
  switch (event.attack_type) {
    case 'SYN_FLOOD': return pps && finite(f.syn_ratio) ? `${src_ip}이(가) ${dst_ip}:${dst_port}로 초당 ${pps}개 패킷을 보냈고, 그중 ${Math.round(f.syn_ratio * 100)}%가 새 연결 요청(SYN)이라 연결 폭주(SYN Flood)로 판단했어요.` : null;
    case 'PORT_SCAN': return finite(f.port_cnt) ? `${src_ip}이(가) ${dst_ip}의 서로 다른 포트 ${f.port_cnt.toLocaleString('ko-KR')}개를 10초 안에 두드려 포트 스캔(Port Scan)으로 판단했어요.` : null;
    case 'LARGE_FLOW': return finite(f.byte_rate) ? `${src_ip}과(와) ${dst_ip}:${dst_port} 사이 한 연결로 초당 ${(f.byte_rate / 1e6).toFixed(1)}MB(약 ${Math.round(f.byte_rate * 8 / 1e6)}Mbps)가 오가 대용량 전송(Large Flow)으로 판단했어요.` : null;
    case 'TRAFFIC_SPIKE': return pps ? `${src_ip}에서 ${dst_ip}:${dst_port}로 초당 ${pps}개 패킷이 들어와 평소 기준을 크게 넘어 트래픽 급증(Traffic Spike)으로 판단했어요.` : null;
    case 'ANOMALY': return finite(event.anomaly_score) ? `${src_ip}에서 ${dst_ip}:${dst_port}로 가는 흐름의 AI 이상 점수가 ${event.anomaly_score.toFixed(3)}으로 기준선보다 낮아 이상 징후(AI 탐지)로 판단했어요.` : null;
    default: return null;
  }
}

const featureLabels: Record<string, string> = {
  pkt_rate: '초당 패킷(pps)', byte_rate: '초당 바이트(bytes/s)', syn_ratio: '접속 요청 비율(SYN ratio)',
  port_entropy: '포트 다양성(Port Entropy)', port_cnt: '목적지 포트 수 (10초)',
  flow_duration: '연결 지속 시간 (ms)', avg_pkt_size: '평균 패킷 크기 (bytes)',
  source_pkt_rate: '출발지 초당 패킷(pps)', source_syn_rate: '출발지 초당 접속 요청(SYN/s)',
  feature_schema_version: '관측 항목 버전(feature schema)', destination_pkt_rate: '목적지 전체 초당 패킷(pps)',
  destination_byte_rate: '목적지 전체 초당 바이트(bytes/s)', destination_syn_rate: '목적지 초당 접속 요청(SYN/s)',
  destination_source_count: '목적지 유입 출발지 수 (10초)', service_pkt_rate: '대상 서비스 초당 패킷(pps)',
  service_byte_rate: '대상 서비스 초당 바이트(bytes/s)', service_syn_rate: '대상 서비스 초당 접속 요청(SYN/s)',
  service_source_count: '대상 서비스 출발지 수 (10초)', reverse_pkt_rate: '반대 방향 초당 패킷(pps)',
  reverse_byte_rate: '반대 방향 초당 바이트(bytes/s)', bidirectional_pkt_rate: '양방향 초당 패킷(pps)',
  bidirectional_byte_rate: '양방향 초당 바이트(bytes/s)', reverse_packet_fraction: '반대 방향 패킷 비중',
  bidirectional_syn_ratio: '양방향 접속 요청 비율(SYN ratio)', source_pkt_rate_10s: '출발지 평균 초당 패킷 (10초)',
  destination_pkt_rate_10s: '목적지 평균 초당 패킷 (10초)',
};

export function EventDetail({ id, onClose }: { id: number; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [event, setEvent] = useState<DetectionEvent | null>(null);
  const [error, setError] = useState('');
  const [token, setToken] = useState(''), [note, setNote] = useState(''), [review, setReview] = useState('pending');
  const [saved, setSaved] = useState(false), [saving, setSaving] = useState(false), [saveError, setSaveError] = useState('');
  const adopt = (value: DetectionEvent) => { setEvent(value); setNote(value.note ?? ''); setReview(value.is_confirmed === true ? 'confirmed' : value.is_confirmed === false ? 'false_positive' : 'pending'); };
  const save = async () => {
    setSaving(true); setSaved(false); setSaveError('');
    try { adopt(await reviewEvent(id, review === 'pending' ? null : review === 'confirmed', note, token)); setSaved(true); } catch (e) { setSaveError(errorMessage(e)); }
    finally { setSaving(false); setToken(''); }
  };
  useEffect(() => {
    const controller = new AbortController();
    const element = dialog.current;
    element?.showModal();
    getEvent(id, controller.signal).then(adopt).catch(e => {
      if (!controller.signal.aborted) setError(errorMessage(e));
    });
    return () => { controller.abort(); element?.close(); };
  }, [id]);
  return <dialog ref={dialog} className="detail-dialog" onCancel={onClose} aria-labelledby="event-detail-title">
    <div className="panel-heading"><h2 id="event-detail-title">탐지 이벤트 #{id}</h2><button className="icon-button" aria-label="상세 닫기" onClick={onClose}><X size={20}/></button></div>
    {error ? <p role="alert">{error}</p> : !event ? <p role="status">상세 정보를 불러오는 중입니다.</p> : <>
      <div className="detail-intro"><SeverityBadge severity={event.severity}/><strong title={termTitle(attackTypeTerm(event.attack_type))}>{attackTypeLabel(event.attack_type)}</strong><p>{new Date(event.detected_at).toLocaleString('ko-KR')}</p></div>
      <div className="event-provenance"><span className={event.source === 'simulation' ? 'simulation-tag' : 'evidence-tag'}>{event.source === 'simulation' ? 'SIMULATION · 모의 탐지' : 'LIVE · 네트워크 수집기(Collector) 탐지'}</span>{event.scenario_run_id && <a href={`#scenarios?run=${event.scenario_run_id}`} onClick={onClose}>실행 그래프 ↗</a>}{event.expected_label && <p>시나리오 기대 유형: {attackTypeLabel(event.expected_label)}</p>}</div>
      <div className="event-summary"><p>{summarizeEvent(event) ?? '요약할 정보가 부족합니다. 아래 관측 항목을 확인하세요.'}</p><small>심각도 {SEVERITY[event.severity]?.label ?? event.severity}({SEVERITY[event.severity]?.original ?? ''}) · {SEVERITY[event.severity]?.description ?? ''}</small></div>
      <dl className="detail-grid">
        <div><dt>출발지</dt><dd>{event.flow.src_ip}:{event.flow.src_port}</dd></div>
        <div><dt>목적지</dt><dd>{event.flow.dst_ip}:{event.flow.dst_port}</dd></div>
        <div><dt>프로토콜</dt><dd>{event.flow.protocol === 6 ? 'TCP' : 'UDP'}</dd></div>
        <div><dt><Term term={UNIT.anomalyScore}/></dt><dd>{event.anomaly_score?.toFixed(4) ?? '미제공 (규칙 기반)'}</dd></div>
      </dl>
      {/* 원시 관측 항목(raw features)은 <details>로 접는다. 접혀 있어도 DOM에 남아 검색·e2e 텍스트 검사에 잡힌다. */}
      <details className="feature-details"><summary>관측 항목 자세히 보기 ({Object.keys(event.features).filter(key => !/^(destination_|service_|reverse_|bidirectional_)/.test(key)).length}개)</summary><dl className="detail-grid">
        {Object.entries(event.features).filter(([key]) => !/^(destination_|service_|reverse_|bidirectional_)/.test(key)).map(([key, value]) => <div key={key}><dt>{featureLabels[key] || key}</dt><dd>{value?.toLocaleString('ko-KR', { maximumFractionDigits: 4 }) ?? '미제공'}</dd></div>)}
      </dl></details>
      <details className="context-details"><summary>목적지·양방향 탐지 근거</summary><p>관측 지점에서 보인 트래픽입니다. 반대 방향 패킷이 없다는 사실만으로 연결 실패를 확정하지 않습니다.</p><dl className="detail-grid">{Object.entries(event.features).filter(([key]) => /^(destination_|service_|reverse_|bidirectional_)/.test(key)).map(([key, value]) => <div key={key}><dt>{featureLabels[key] || key}</dt><dd>{value?.toLocaleString('ko-KR', { maximumFractionDigits: 4 }) ?? '미제공'}</dd></div>)}</dl>{event.features.feature_schema_version !== 2 && <p>이 기록은 이전 Collector 피처입니다. 추가 문맥은 제공되지 않았습니다.</p>}</details>
      <form className="review-form" onSubmit={e => { e.preventDefault(); save(); }}><h3>분석가 검토</h3><p>검토 결과는 DB에 저장됩니다. 모델의 정답 레이블이나 학습 데이터로 자동 사용되지 않습니다.</p><label>판정<select aria-label="판정" value={review} onChange={e => setReview(e.target.value)}><option value="pending">검토 대기</option><option value="confirmed">정탐 확인</option><option value="false_positive">오탐 확인</option></select></label><label>검토 메모<textarea value={note} maxLength={2000} onChange={e => setNote(e.target.value)} placeholder="판단 근거를 남겨 주세요."/></label><label>검토용 관리자 토큰<input type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} disabled={!window.isSecureContext}/></label>{!window.isSecureContext && <p>검토 저장은 HTTPS 또는 localhost에서 사용할 수 있습니다.</p>}<button className="primary-button" type="submit" disabled={!window.isSecureContext || !token || saving}>검토 저장</button>{saved && <p role="status">검토 결과를 저장했습니다.</p>}{saveError && <p role="alert">{saveError}</p>}{event.reviewed_at && <small>마지막 검토: {new Date(event.reviewed_at).toLocaleString('ko-KR')}</small>}</form>
    </>}
  </dialog>;
}
