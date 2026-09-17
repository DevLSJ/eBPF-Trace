import { useEffect, useState } from 'react';
import { ArrowDownToLine, CheckCheck, Database, FileCheck2, FlaskConical, Info, ShieldCheck } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { getCaptureReport, getModelAnalysis, errorMessage } from '../api/client';
import type { CaptureReport, ModelAnalysis } from '../types';

const number = (value: number) => value.toLocaleString('ko-KR');
const percent = (value: number) => `${(value * 100).toFixed(2)}%`;
const captureTime = (value: number) => new Date(value * 1000).toLocaleTimeString('en-GB', { timeZone: 'America/Halifax', hour: '2-digit', minute: '2-digit' });
const compact = (value: number) => new Intl.NumberFormat('en', { notation: 'compact' }).format(value);

export function CapturePanel() {
  const [reports, setReports] = useState<CaptureReport[]>([]), [error, setError] = useState('');
  const [model, setModel] = useState<ModelAnalysis | null>(null), [modelError, setModelError] = useState('');
  const [selected, setSelected] = useState(''), [retry, setRetry] = useState(0);
  const report = reports.find(item => item.source === selected) ?? reports[0];
  useEffect(() => {
    let active = true;
    getCaptureReport().then(data => { if (active) { setReports(data); setError(''); } }).catch(e => { if (active) setError(errorMessage(e)); });
    getModelAnalysis().then(data => { if (active) { setModel(data); setModelError(''); } }).catch(e => { if (active) setModelError(errorMessage(e)); });
    return () => { active = false; };
  }, [retry]);
  const labels = report?.labels, evaluation = model?.evaluation;
  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify({ capture: report, model }, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${report.source.replace(/\.pcap$/, '')}-analysis.json`; anchor.click(); URL.revokeObjectURL(url);
  };
  return <div id="capture" className="analysis-workspace">
    <div className="analysis-intro"><div><span className="eyebrow">FROM PACKETS TO EVIDENCE</span><h2>CIC-IDS-2017 분석 워크스페이스</h2><p>실제 캡처에서 정답 매칭과 모델 평가까지, 데이터로 확인하는 탐지 성능.</p></div><span className="evidence-tag"><FileCheck2 size={15}/>실제 데이터 분석</span></div>
    {error ? <div className="error-banner" role="alert">{error}<button onClick={() => setRetry(v => v + 1)}>다시 시도</button></div> : !report ? <p className="panel-message" role="status">분석 결과를 불러오는 중입니다.</p> : <>
      <section className="panel capture-panel">
        <div className="panel-heading"><div><h2>PCAP 오프라인 분석</h2><p>전체 파일 분석 · 패킷을 네트워크로 재전송하지 않습니다.</p></div><button className="outline-button" onClick={download}><ArrowDownToLine size={14}/>분석 JSON</button></div>
        <div className="capture-content">
          <div className="capture-select"><label>캡처 파일 <select aria-label="캡처 파일" value={report.source} onChange={e => setSelected(e.target.value)}>{reports.map(item => <option key={item.source}>{item.source}</option>)}</select></label><span>{(report.source_bytes / 1024 ** 3).toFixed(2)} GiB <i/> {new Date(report.started_at * 1000).toLocaleDateString('en-CA', { timeZone: 'America/Halifax' })}</span></div>
          <div className="capture-stats">{[
            ['원본 패킷', number(report.counts.packets), 'TCP · UDP 외 패킷 포함'],
            ['생성 피처 행', number(report.counts.feature_rows), '실시간 Collector와 같은 피처 계산'],
            ['정답 매칭률', labels ? percent(labels.coverage) : '—', labels ? `${number(labels.counts.matched ?? 0)}개 피처 행의 정답 확인` : '레이블 결합 대기'],
          ].map(([title, value, note]) => <div key={title}><span>{title}</span><strong>{value}</strong><small>{note}</small></div>)}</div>
          <div className="analysis-chart-heading"><h3>캡처 타임라인</h3><span>분당 TCP / UDP 패킷 · 현지 시각 (UTC−03:00)</span></div>
          <div className="capture-chart" role="img" aria-label="캡처 시간대별 분당 패킷 수">
            <ResponsiveContainer width="100%" height="100%"><AreaChart data={report.traffic_minutes} margin={{ top: 12, right: 10, left: 0, bottom: 0 }}>
              <defs><linearGradient id="captureFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#5476e8" stopOpacity={0.3}/><stop offset="100%" stopColor="#5476e8" stopOpacity={0.02}/></linearGradient></defs>
              <CartesianGrid stroke="#edf1f6" vertical={false}/><XAxis dataKey="timestamp" tickFormatter={captureTime} minTickGap={55} axisLine={false} tickLine={false} fontSize={10}/><YAxis tickFormatter={compact} width={48} axisLine={false} tickLine={false} fontSize={10}/>
              <Tooltip labelFormatter={v => `${captureTime(Number(v))} (UTC−03:00)`} formatter={v => [number(Number(v)), '패킷 / 분']}/><Area dataKey="packets" type="monotone" stroke="#5476e8" strokeWidth={1.8} fill="url(#captureFill)" isAnimationActive={false}/>
            </AreaChart></ResponsiveContainer>
          </div>
          <div className="protocol-strip"><span><i className="blue-dot"/>TCP <b>{number(report.protocols.TCP ?? 0)}</b></span><span><i className="teal-dot"/>UDP <b>{number(report.protocols.UDP ?? 0)}</b></span><span>전체 분석 패킷 <b>{number(report.counts.eligible_packets)}</b></span></div>
        </div>
      </section>
      <div className="analysis-grid">
        <section className="panel label-panel"><div className="panel-heading"><div><h2><Database size={16}/>정답 레이블 분포</h2><p>보수적으로 매칭된 피처 행 기준</p></div><span className="count-pill">{labels ? Object.keys(labels.distribution).length : 0} LABELS</span></div>
          {labels ? <div className="label-content"><div className="coverage-track" aria-label={`정답 매칭률 ${percent(labels.coverage)}`}><span style={{ width: percent(labels.coverage) }}/></div><div className="coverage-caption"><strong>{percent(labels.coverage)} 매칭</strong><span>미매칭·충돌 행은 학습에서 제외</span></div>
            <div className="label-bars">{Object.entries(labels.distribution).sort((a, b) => b[1] - a[1]).map(([label, count]) => <div className="label-row" key={label}><div><span>{label.replace('Web Attack – ', '')}</span><b>{number(count)}</b></div><div className="label-track"><span className={label === 'BENIGN' ? 'benign' : 'attack'} style={{ width: percent(count / Math.max(1, labels.counts.matched)) }}/></div></div>)}</div>
            <div className="excluded-counts"><span>미매칭 <b>{number(labels.counts.unlabeled ?? 0)}</b></span><span>정답 충돌 <b>{number(labels.counts.ambiguous ?? 0)}</b></span><span>원본 빈 행·오류 <b>{number((labels.counts.empty_label_rows ?? 0) + (labels.counts.invalid_label_rows ?? 0))}</b></span></div>
          </div> : <p className="panel-message">정답 레이블이 없어 매칭률을 계산할 수 없습니다.</p>}
        </section>
        <section className="panel evidence-panel"><div className="panel-heading"><div><h2><CheckCheck size={17}/>분석 근거와 범위</h2><p>결과를 해석하기 전에 확인하세요.</p></div></div><div className="evidence-content">
          <div><span className="step-index">01</span><section><h3>동일한 피처 계산</h3><p>PCAP을 Collector와 동일한 피처 계산으로 변환했습니다. 추가 실험은 출발지 PPS·SYN PPS·목적지 포트 수도 사용합니다.</p></section></div>
          <div><span className="step-index">02</span><section><h3>패킷 근거로 정답 시각 복원</h3><p>{labels ? labels.alignment ? `원본 ${labels.sources.length}개 CSV · 패킷 수·방향·지속시간(±${labels.alignment.duration_tolerance_us}μs)이 유일하게 일치하는 구간을 사용합니다. 미복원 구간은 60초 불확실성을 유지합니다.` : `원본 ${labels.sources.length}개 CSV · 분 단위 시각의 불확실성을 보수적으로 처리합니다.` : '정답 CSV 결합 결과를 기다리고 있습니다.'}</p></section></div>
          <div><span className="step-index">03</span><section><h3>평가 표본의 한계</h3><p>미매칭·정답 충돌은 평가에서 제외합니다. 현재 시간순 평가에는 DDoS·PortScan이 포함되며 다른 공격 유형의 성능까지 보장하지 않습니다.</p></section></div>
          <details><summary>원본 파일과 SHA-256 확인</summary><code>{report.sha256}</code>{labels?.sources.map(source => <p key={source}>{source}</p>)}</details>
        </div></section>
      </div>
      <section className="panel model-panel"><div className="panel-heading"><div><h2><FlaskConical size={17}/>Isolation Forest 평가</h2><p>Thursday + Friday · 시간순 분리 · 경계 10초 및 장기 플로우 제외</p></div><span className={`evaluation-status ${evaluation?.deployment_approved ? 'approved' : ''}`}>{evaluation ? evaluation.deployment_approved ? '운영 승인' : '실험 평가 · 운영 미승인' : '평가 대기'}</span></div>
        {modelError ? <div className="error-banner" role="alert">{modelError}<button onClick={() => setRetry(v => v + 1)}>다시 시도</button></div> : !evaluation ? <p className="panel-message">실측 평가 보고서가 아직 없습니다. 성능 지표는 평가 후 표시됩니다.</p> : <div className="model-content">
          <div className="evaluation-metrics">{[
            ['Precision', evaluation.performance.precision, '탐지한 행 중 실제 공격 비율'],
            ['Recall', evaluation.performance.recall, '실제 공격 행 중 탐지한 비율'],
            ['F1 score', evaluation.performance.f1, `목표 ≥ ${percent(evaluation.targets.f1_min)}`],
            ['False positive rate', evaluation.performance.fpr, `목표 ≤ ${percent(evaluation.targets.fpr_max)}`],
          ].map(([title, value, note]) => <div key={String(title)}><span>{title}</span><strong>{percent(Number(value))}</strong><small>{note}</small></div>)}</div>
          <div className="evaluation-bottom"><div className="split-summary"><h3>검증 데이터</h3><p>정상 학습 <b>{number(evaluation.split.training_rows)}</b>행</p><p>시간순 평가 <b>{number(evaluation.split.held_out_rows)}</b>행</p><p>경계·장기 플로우 제외 <b>{number(evaluation.split.purged_rows)}</b>행</p><span>점수 임계값 {evaluation.threshold} · {evaluation.performance.passed ? '수치 목표 충족' : '수치 목표 미달'}</span></div>
          <div className="confusion"><h3>혼동 행렬 <span>피처 행 기준</span></h3><div className="confusion-grid">{[['TN · 정상 통과', evaluation.performance.tn], ['FP · 정상 오탐', evaluation.performance.fp], ['FN · 공격 미탐', evaluation.performance.fn], ['TP · 공격 탐지', evaluation.performance.tp]].map(([label, count]) => <div key={String(label)}><span>{label}</span><b>{number(Number(count))}</b></div>)}</div></div></div>
          {evaluation.six_feature_comparison && <div className="feature-comparison"><div><span>동일한 데이터 · 동일한 시간순 분리</span><h3>출발지 문맥을 추가한 비교 실험</h3><p>각 연결의 패킷 수에 출발지 전체의 PPS, SYN PPS, 포트 다양성을 더했습니다. 아래 값은 동일한 평가 표본에서 비교합니다.</p></div><div><span>기존 6개 피처 F1</span><strong>{percent(evaluation.six_feature_comparison.performance.f1)}</strong></div><div><span>{evaluation.features.length}개 피처 F1</span><strong>{percent(evaluation.performance.f1)}</strong></div></div>}
          {evaluation.performance.per_label && <div className="per-label-metrics"><h3>평가 레이블별 관측 결과</h3><div className="table-wrap"><table><thead><tr><th>정답 레이블</th><th>평가 행</th><th>탐지된 행</th><th>탐지 비율</th></tr></thead><tbody>{Object.entries(evaluation.performance.per_label).map(([label, result]) => <tr key={label}><td>{label}{label === 'BENIGN' ? ' · 오탐' : ''}</td><td>{number(result.rows)}</td><td>{number(result.detected)}</td><td>{percent(result.detection_rate)}</td></tr>)}</tbody></table></div></div>}
          <div className="model-runtime"><ShieldCheck size={18}/><div><strong>현재 운영 엔진: {model?.runtime.mode === 'hybrid' ? '하이브리드' : '규칙 기반'}</strong><p>이 화면의 실험 결과와 운영 모델 적용 상태는 별도로 관리됩니다.</p></div></div>
        </div>}
      </section>
      <div className="analysis-footnote"><Info size={15}/><span>정답 매칭과 모델 평가는 오프라인 결과입니다. 실시간 탐지 이벤트에는 이 데이터가 주입되지 않습니다.</span></div>
    </>}
  </div>;
}
