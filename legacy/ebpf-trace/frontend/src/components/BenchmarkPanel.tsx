import { useState } from 'react';
import { ArrowDownToLine, CheckCircle2, FlaskConical, Layers3 } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { ContextBenchmark, DatasetPreparation } from '../types';

const number = (v: number) => v.toLocaleString('ko-KR');
const percent = (v: number | null) => v == null ? '—' : `${(v * 100).toFixed(2)}%`;
const names: Record<string, string> = { if_6: 'IF · 기본 6개', if_9: 'IF · 출발지 9개', if_25: 'IF · 양방향 25개', if_25_large: 'IF · 25개 / 표본 확대', hgb_25: '지도학습 · 25개' };
const days: Record<string, string> = { Monday: '월', Tuesday: '화', Wednesday: '수', Thursday: '목', Friday: '금' };
const total = (values: Record<string, number> | undefined) => Object.values(values ?? {}).reduce((a, b) => a + b, 0);

export function BenchmarkPanel({ benchmark, preparation }: { benchmark?: ContextBenchmark | null; preparation?: DatasetPreparation | null }) {
  const [selected, setSelected] = useState('');
  const candidate = benchmark?.candidates.find(item => item.id === selected) ?? benchmark?.candidates.find(item => item.id === benchmark.preferred_id);
  if (!preparation && !benchmark) return null;
  const exportReport = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify({ benchmark, preparation }, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'context-feature-benchmark.json'; anchor.click(); URL.revokeObjectURL(url);
  };
  const labelRows = Object.entries(candidate?.performance.per_label ?? {}).filter(([label]) => label !== 'BENIGN').map(([label, row]) => ({ label, recall: row.detection_rate * 100, rows: row.rows }));
  const coverage = benchmark?.attack_coverage;
  return <section className="panel benchmark-panel" aria-label="전체 요일 모델 비교">
    <div className="benchmark-heading"><div><span className="eyebrow"><FlaskConical size={14}/> DETECTION LAB / CONTEXT V2</span><h2>탐지 성능 실험실</h2><p>목적지에 모이는 트래픽과 양방향 흐름을 함께 비교합니다.</p></div><button className="outline-button" onClick={exportReport}><ArrowDownToLine size={14}/>실험 보고서</button></div>
    {preparation && <div className="dataset-rail">{preparation.days.map(day => {
      const item = preparation.completed.find(entry => entry.day === day);
      const failed = preparation.failures.some(entry => entry.day === day);
      return <div className={`dataset-day ${item?.matched_rows ? 'ready' : ''}`} key={day}><span>{days[day] ?? day}요일 {item?.matched_rows ? <CheckCircle2 size={14}/> : <Layers3 size={14}/>}</span><strong>{item ? number(item.matched_rows) : failed ? '처리 실패' : '처리 중'}</strong><small>{item ? `정답 매칭 ${percent(item.matched_rows / Math.max(item.feature_rows, 1))}` : '완료 후 결과가 표시됩니다'}</small></div>;
    })}</div>}
    {!benchmark || !candidate ? <p className="panel-message" role="status">피처·정답 매칭 결과를 준비하고 있습니다. 모델 성능은 평가가 완료된 뒤 표시됩니다.</p> : <div className="benchmark-content">
      <div className="benchmark-selection"><label>비교 모델<select aria-label="비교 모델" value={candidate.id} onChange={event => setSelected(event.target.value)}>{benchmark.candidates.map(item => <option value={item.id} key={item.id}>{names[item.id] ?? item.model}</option>)}</select></label><span className="experiment-pill">운영 미승인 · 보정 데이터로 모델 선택</span></div>
      <div className="benchmark-metrics">{[
        ['시험 F1', percent(candidate.performance.f1), `목표 ≥ ${percent(benchmark.targets.f1_min)}`],
        ['공격 재현율', percent(candidate.performance.recall), `${number(candidate.performance.fn)}개 공격 창 미탐`],
        ['정상 오탐률', percent(candidate.performance.fpr), `목표 ≤ ${percent(benchmark.targets.fpr_max)}`],
        ['시험 표본', number(total(benchmark.split.distribution.test)), '매칭·분리 기준을 통과한 피처 창'],
      ].map(([title, value, note]) => <div key={title}><span>{title}</span><strong>{value}</strong><small>{note}</small></div>)}</div>
      <div className={`benchmark-verdict ${candidate.performance.passed ? 'passed' : ''}`}><strong>{candidate.performance.passed ? '이 시험 표본에서 수치 목표 충족' : '이 시험 표본에서 수치 목표 미달'}</strong><span>별도 환경·공격 실행 검증이 필요합니다. 운영 탐지 엔진의 성능을 뜻하지 않습니다.</span></div>
      {coverage && <div className="benchmark-coverage"><strong>시험에 포함된 공격 유형 {coverage.tested_attack_types.length} / {coverage.matched_attack_types.length}종</strong><p>연결·시간 분리 후 시험 표본이 남은 유형: {coverage.tested_attack_types.join(', ')}</p>{coverage.missing_test_attack_types.length > 0 && <p>시험에 없는 유형 — {coverage.missing_test_attack_types.join(', ')}. 위 점수로 이 유형의 탐지 성능을 판단할 수 없습니다.</p>}</div>}
      <div className="benchmark-comparison table-wrap"><table><thead><tr><th>모델 / 피처</th><th>보정 F1</th><th>시험 F1</th><th>시험 재현율</th><th>시험 오탐률</th></tr></thead><tbody>{benchmark.candidates.map(item => <tr key={item.id} className={item.id === candidate.id ? 'selected' : ''}><td><button className="model-choice" onClick={() => setSelected(item.id)}>{names[item.id] ?? item.model}</button>{item.id === benchmark.preferred_id && <small>보정 기준 선택</small>}</td><td>{percent(item.calibration.f1)}</td><td>{percent(item.performance.f1)}</td><td>{percent(item.performance.recall)}</td><td>{percent(item.performance.fpr)}</td></tr>)}</tbody></table></div>
      <div className="benchmark-evidence-grid"><div><h3>공격 유형별 시험 재현율</h3><p>선택 모델의 결과 · 유형별 표본 수는 아래 표에서 확인하세요.</p><div className="benchmark-chart" role="img" aria-label="공격 유형별 재현율 그래프"><ResponsiveContainer width="100%" height="100%"><BarChart data={labelRows} layout="vertical" margin={{ top: 8, bottom: 8, right: 20, left: 0 }}><CartesianGrid stroke="#edf1f6" horizontal={false}/><XAxis type="number" domain={[0, 100]} tickFormatter={v => `${v}%`} axisLine={false} tickLine={false} fontSize={10}/><YAxis dataKey="label" type="category" width={115} tick={{ fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip formatter={v => [`${Number(v).toFixed(2)}%`, '재현율']}/><Bar dataKey="recall" fill="#5476e8" radius={[0, 4, 4, 0]} maxBarSize={18} isAnimationActive={false}/></BarChart></ResponsiveContainer></div></div>
      <div className="partition-evidence"><h3>학습·보정·시험 분리</h3><dl><div><dt>학습에 사용한 표본</dt><dd>{number(total(benchmark.split.sampled_training))}</dd></div><div><dt>임계값 보정 표본</dt><dd>{number(total(benchmark.split.distribution.calibration))}</dd></div><div><dt>최종 점수 산출 표본</dt><dd>{number(total(benchmark.split.distribution.test))}</dd></div><div><dt>시간 경계·장기 연결 제외</dt><dd>{number(benchmark.split.counts.context_or_lifetime_purged ?? 0)}</dd></div><div><dt>연결·시간 분할 불일치 제외</dt><dd>{number(benchmark.split.counts.tuple_partition_excluded ?? 0)}</dd></div></dl><p>{benchmark.protocol.block_seconds / 60}분 시간 블록과 양방향 연결을 함께 분리하고, 경계 {benchmark.protocol.purge_seconds}초를 제외합니다. 시험 점수로 임계값이나 모델을 선택하지 않습니다.</p><p>같은 공격 실행이 여러 블록에 걸칠 수 있으므로 새로운 공격 실행에 대한 독립 검증은 별도로 필요합니다.</p></div></div>
      <details className="benchmark-label-details"><summary>유형별 표본·미탐·오탐 확인</summary><div className="table-wrap"><table><thead><tr><th>정답 유형</th><th>시험 표본</th><th>탐지</th><th>미탐 / 정상 통과</th><th>탐지 비율</th></tr></thead><tbody>{Object.entries(candidate.performance.per_label ?? {}).map(([label, row]) => <tr key={label}><td>{label === 'BENIGN' ? 'BENIGN · 탐지는 오탐' : label}</td><td>{number(row.rows)}</td><td>{number(row.detected)}</td><td>{number(row.rows - row.detected)}</td><td>{percent(row.detection_rate)}</td></tr>)}</tbody></table></div></details>
      <p className="benchmark-note">6·9·25개 기본 IF는 같은 트리·표본 설정으로 비교합니다. 기존 목·금요일 평가와는 분리 기준과 표본이 달라 직접적인 성능 상승률로 해석할 수 없습니다.</p>
    </div>}
  </section>;
}
