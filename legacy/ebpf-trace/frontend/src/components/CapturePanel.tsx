import { useEffect, useState } from 'react';
import { getCaptureReport, errorMessage } from '../api/client';
import type { CaptureReport } from '../types';

export function CapturePanel() {
  const [reports, setReports] = useState<CaptureReport[]>([]), [error, setError] = useState('');
  const [selected, setSelected] = useState('');
  const report = reports.find(item => item.source === selected) ?? reports[0];
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let active = true;
    getCaptureReport().then(data => { if (active) { setReports(data); setError(''); } }).catch(e => { if (active) setError(errorMessage(e)); });
    return () => { active = false; };
  }, [retry]);
  return <section className="panel capture-panel" id="capture"><div className="panel-heading"><div><h2>PCAP 오프라인 분석</h2><p>제공된 캡처를 같은 피처 계산기로 분석한 결과</p></div><span className="subtle-label">{report?.complete ? '전체 파일 분석' : '분석 자료'}</span></div>
    {error ? <div className="error-banner" role="alert">{error}<button onClick={() => setRetry(v => v + 1)}>다시 시도</button></div> : !report ? <p className="panel-message">분석 결과를 불러오는 중입니다.</p> : <div className="capture-content">
      <label>캡처 파일 <select aria-label="캡처 파일" value={report.source} onChange={e => setSelected(e.target.value)}>{reports.map(item => <option key={item.source}>{item.source}</option>)}</select></label><p>{(report.source_bytes / 1024 ** 3).toFixed(2)} GiB · {new Date(report.started_at * 1000).toLocaleString('ko-KR')} ~ {new Date(report.ended_at * 1000).toLocaleTimeString('ko-KR')}</p>
      <div className="capture-stats"><div><span>원본 패킷</span><strong>{report.counts.packets.toLocaleString()}</strong></div><div><span>TCP / UDP 분석 패킷</span><strong>{report.counts.eligible_packets.toLocaleString()}</strong></div><div><span>생성 피처 행</span><strong>{report.counts.feature_rows.toLocaleString()}</strong></div></div>
      <div className="capture-rules">{Object.entries(report.rule_detections).map(([name, count]) => <span key={name}>{name.replaceAll('_', ' ')} <b>{count.toLocaleString()}</b></span>)}</div>
      <p className="analysis-note">규칙 탐지 횟수는 피처 행 기준이며 고유 공격 수가 아닙니다. 정답 레이블이 없어 F1·오탐률은 미측정이며, ML 모델은 미검증 상태입니다.</p>
      {report.sha256 && <details><summary>파일 무결성 (SHA-256)</summary><code>{report.sha256}</code></details>}
    </div>}
  </section>;
}
