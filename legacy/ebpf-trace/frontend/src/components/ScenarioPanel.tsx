import { useEffect, useRef, useState } from 'react';
import { ArrowUpRight, CheckCircle2, Database, FlaskConical, Play, Square } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { errorMessage, getRun, getRuns, getScenarios, startRun, stopRun } from '../api/client';
import type { Scenario, ScenarioRun } from '../types';
import { EventDetail } from './EventDetail';
import { Term } from './Term';
import { ATTACK_TYPE, UNIT, attackTypeLabel, attackTypeTerm, engineLabel, humanizeCodes, termTitle } from '../labels';
import { useNotifyStore } from '../store/notifyStore';

const stages: Record<string, string> = { baseline: '정상 접속', recon: '포트 스캔', flood: '연결 폭주', transfer: '대용량 전송', recovery: '회복', mixed_recon: '공유 주소 포트 스캔' };
// 각 단계에서 "무슨 일이 일어나는지"를 초보자 문장으로. 용어 설명은 labels.ts와 같은 문장을 재사용한다.
const stageStory: Record<string, string> = {
  baseline: '평범한 접속만 오가요. 아무것도 탐지되지 않아야 정상이에요.',
  recon: `${ATTACK_TYPE.PORT_SCAN.description} → 포트 스캔(Port Scan) 탐지를 기대해요.`,
  flood: `${ATTACK_TYPE.SYN_FLOOD.description} → 연결 폭주(SYN Flood) 탐지를 기대해요.`,
  transfer: `${ATTACK_TYPE.LARGE_FLOW.description} → 대용량 전송(Large Flow) 탐지를 기대해요.`,
  recovery: '정상 트래픽으로 돌아와요. 탐지가 멈춰야 정상이에요.',
  mixed_recon: '여러 사용자가 같은 주소를 쓰는 중에 한 명만 포트를 두드려요 → 포트 스캔(Port Scan) 탐지를 기대해요.',
};
const SAMPLES_PER_STAGE = 3;
const statuses: Record<string, string> = { running: '실행 중', completed: '완료', cancelled: '중지됨', interrupted: '서버 재시작으로 중단', failed: '실행 실패' };
export function ScenarioPanel() {
  const [catalog, setCatalog] = useState<Scenario[]>([]), [runs, setRuns] = useState<ScenarioRun[]>([]);
  const [selected, setSelected] = useState(new URLSearchParams(location.hash.split('?')[1]).get('run') || '');
  const [run, setRun] = useState<ScenarioRun | null>(null), [token, setToken] = useState('');
  const [loadError, setLoadError] = useState('');
  const [error, setError] = useState(''), [busy, setBusy] = useState(false), [eventId, setEventId] = useState<number | null>(null);
  const pending = useRef<{ scenario: string; id: string } | null>(null);
  const secure = window.isSecureContext;
  useEffect(() => { getScenarios().then(setCatalog).catch(e => setLoadError(errorMessage(e))); }, []);
  useEffect(() => {
    let active = true;
    const load = () => getRuns().then(items => { if (active) { setRuns(items); if (!selected && items.length) setSelected(items[0].id); } }).catch(e => { if (active) setLoadError(errorMessage(e)); });
    load(); const timer = setInterval(load, 3000); return () => { active = false; clearInterval(timer); };
  }, [selected]);
  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController(); setRun(null);
    const load = () => getRun(selected, controller.signal).then(value => { setRun(value); setLoadError(''); }).catch(e => { if (!controller.signal.aborted) setLoadError(errorMessage(e)); });
    load(); const timer = setInterval(load, 1000); return () => { controller.abort(); clearInterval(timer); };
  }, [selected]);
  const start = async (scenario: string) => {
    if (!secure || busy) return;
    setBusy(true); setError('');
    if (pending.current?.scenario !== scenario) pending.current = { scenario, id: crypto.randomUUID() };
    try {
      const result = await startRun(scenario, pending.current.id, token);
      pending.current = null; setSelected(result.id); setRun(result); setRuns(await getRuns());
    } catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); setToken(''); }
  };
  const stop = async () => {
    if (!run) return;
    setBusy(true);
    try { setRun(await stopRun(run.id, token)); } catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); setToken(''); }
  };
  const samples = run?.samples ?? [], active = runs.some(item => item.status === 'running') || run?.status === 'running';
  const scenario = catalog.find(item => item.id === run?.scenario_id);
  // 실행이 끝나면(완료·중지·실패) 토스트로 알려 준다. 다른 실행 기록으로 바꿔 볼 때는 울리지 않는다.
  const toast = useNotifyStore(s => s.toast);
  const lastRunState = useRef<{ id: string; status: string } | null>(null);
  useEffect(() => {
    if (!run) return;
    const before = lastRunState.current; lastRunState.current = { id: run.id, status: run.status };
    if (!before || before.id !== run.id || before.status !== 'running' || run.status === 'running') return;
    const name = humanizeCodes(scenario?.name ?? run.scenario_id);
    toast(run.status === 'completed'
      ? { level: 'ok', duration: 7000, text: `${name} 실행이 끝났어요 · ${run.event_count ?? 0}건 탐지`, action: { label: '기록 보기', href: `#events?run=${run.id}` } }
      : { level: 'warn', duration: 7000, text: `${name} 실행이 "${statuses[run.status] ?? run.status}" 상태로 끝났어요.` });
  }, [run, scenario?.name, toast]);
  const chart = samples.map(item => ({ step: item.step + 1, pps: item.features.pkt_rate, mbps: item.features.byte_rate * 8 / 1e6, stage: stages[item.stage] }));
  // 실행 결과 요약은 저장된 샘플의 실제 값으로만 만든다(하드코딩 금지).
  const stageList = scenario?.stages ?? [];
  const countOf = (stage: string) => samples.filter(s => s.stage === stage).length;
  const stagesDone = stageList.filter(stage => countOf(stage) >= SAMPLES_PER_STAGE).length;
  const currentStage = run?.status === 'running' ? stageList.find(stage => countOf(stage) < SAMPLES_PER_STAGE) : undefined;
  const attackSamples = samples.filter(s => s.expected_label !== 'BENIGN');
  const caught = attackSamples.filter(s => s.detected_label === s.expected_label).length;
  const falseAlarms = samples.filter(s => s.expected_label === 'BENIGN' && s.detected_label !== 'BENIGN').length;
  const mismatched = samples.filter(s => s.detected_label !== s.expected_label).length;
  const expectedTotal = scenario?.duration_seconds ?? 0;
  const summary = !run ? '' : run.status === 'running'
    ? `실행 중 · ${stageList.length}단계 중 ${stagesDone}단계를 마쳤고, 지금까지 ${run.event_count ?? 0}건을 탐지했어요.`
    : run.status === 'completed'
      ? `${stageList.length}단계를 모두 실행했고, 위협을 넣은 ${attackSamples.length}개 샘플 중 ${caught}개를 기대한 유형으로 탐지했어요${falseAlarms ? ` (정상 구간 오탐 ${falseAlarms}건)` : ''}. ${mismatched ? `기대와 다른 샘플 ${mismatched}개는 아래 표에서 확인하세요.` : '기대와 다르게 판단한 샘플은 없어요.'}`
      : `${statuses[run.status] ?? run.status} · ${samples.length}개 샘플까지 기록됐고 ${run.event_count ?? 0}건을 탐지했어요.`;
  return <div className="scenario-workspace">
    <div className="analysis-intro"><div><span className="eyebrow">탐지 체험 공간</span><h1>탐지 시나리오</h1><p>공격 징후가 이벤트와 데이터베이스에 기록되는 과정을 직접 확인하세요.</p></div><span className="simulation-tag"><FlaskConical size={16}/>모의 트래픽</span></div>
    <div className="scenario-notice"><ShieldIcon/><div><strong>외부로 패킷을 보내지 않는 탐지 리허설</strong><p>합성 피처 → 실제 탐지 엔진 → DB 저장 → 그래프와 이벤트. 모의 기록에는 SIMULATION 표시가 남으며 Slack 알림은 전송하지 않습니다.</p></div></div>
    <div className="scenario-cards">{catalog.map((item, index) => <section className="scenario-card" key={item.id}><span className="scenario-number">0{index + 1} / {item.duration_seconds} SEC</span><h2>{humanizeCodes(item.name)}</h2><p>{humanizeCodes(item.description)}</p><div className="stage-dots">{item.stages.map(stage => <span key={stage} title={stageStory[stage]}>{stages[stage] ?? stage}</span>)}</div><button className="primary-button" disabled={!secure || !token.trim() || busy || active} onClick={() => start(item.id)}><Play size={14}/>{humanizeCodes(item.name)} 실행</button></section>)}</div>
    <div className="scenario-auth"><label htmlFor="scenario-token">관리자 토큰<input id="scenario-token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} placeholder="실행 또는 중지할 때 입력" disabled={!secure}/></label><p>{secure ? '토큰은 저장하지 않으며 요청 후 입력을 지웁니다. 한 번에 하나의 시나리오만 실행됩니다.' : '실행은 HTTPS 또는 localhost 접속에서 사용할 수 있습니다. 현재 화면에서는 실행 기록을 조회할 수 있습니다.'}</p></div>
    {(error || loadError) && <div className="error-banner" role="alert">{error || loadError}</div>}
    <section className="panel run-panel"><div className="panel-heading"><div><h2><Database size={17}/>실행 기록과 관측 결과</h2><p>DB에 저장된 데이터를 조회합니다. 새로고침 후에도 유지됩니다.</p></div><label>실행 기록<select aria-label="실행 기록" value={selected} onChange={e => setSelected(e.target.value)}><option value="">기록 선택</option>{runs.map(item => <option key={item.id} value={item.id}>{new Date(item.started_at).toLocaleString('ko-KR')} · {humanizeCodes(catalog.find(s => s.id === item.scenario_id)?.name ?? item.scenario_id)} · {statuses[item.status]}</option>)}</select></label></div>
      {!run ? <div className="panel-message">{selected ? '실행 기록을 불러오는 중입니다.' : '시나리오를 실행하면 타임라인과 탐지 근거가 이곳에 기록됩니다.'}</div> : <div className="run-content"><div className="run-title"><div><span className={`run-status ${run.status}`}>{statuses[run.status]}</span><h3>{humanizeCodes(scenario?.name ?? run.scenario_id)}</h3><code>{run.id}</code></div><div className="run-actions"><a className="outline-button" href={`#events?run=${run.id}`}><ArrowUpRight size={15}/>탐지 이벤트에서 보기</a>{run.status === 'running' && <button className="outline-button" disabled={!secure || !token || busy} onClick={stop}><Square size={13}/>실행 중지</button>}</div></div>
        <p className="run-summary" role="status">{summary}</p>
        <div className="run-progress" role="progressbar" aria-label="시나리오 진행률" aria-valuemin={0} aria-valuemax={expectedTotal || samples.length || 1} aria-valuenow={samples.length} aria-valuetext={`${samples.length} / ${expectedTotal || samples.length} 샘플`}><i style={{ width: `${expectedTotal ? Math.min(100, 100 * samples.length / expectedTotal) : 100}%` }}/></div>
        <div className="run-stats"><div><span>저장된 샘플</span><strong>{samples.length}<small> / {(scenario?.duration_seconds ?? 0)}</small></strong></div><div><span>탐지 이벤트</span><strong>{run.event_count ?? 0}<small>건</small></strong></div><div><span>기대 유형 일치</span><strong>{run.matched_steps ?? 0}<small> / {samples.length}</small></strong></div><div><span>실행 엔진</span><strong>{engineLabel(run.detection_mode) || run.detection_mode}</strong></div></div>
        <div className="run-chart-legend"><span>● <Term term={UNIT.pps}/> · 왼쪽 축</span><span>● <Term term={UNIT.mbps}/> · 오른쪽 축</span><small>가로축: 저장된 샘플 순서</small></div><div className="run-chart" role="img" aria-label="데이터베이스에 저장된 시나리오 패킷과 대역폭 그래프"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chart}><CartesianGrid stroke="#edf1f6" vertical={false}/><XAxis dataKey="step" fontSize={11} tickLine={false}/><YAxis yAxisId="pps" fontSize={11} width={48}/><YAxis yAxisId="mbps" orientation="right" fontSize={11} width={40}/><Tooltip labelFormatter={v => `샘플 ${v}`} /><Area yAxisId="pps" dataKey="pps" name="초당 패킷(pps)" stroke="#526ce3" fill="#e8edff" isAnimationActive={false}/><Area yAxisId="mbps" dataKey="mbps" name="초당 전송량(Mbps)" stroke="#19a69b" fill="transparent" isAnimationActive={false}/></AreaChart></ResponsiveContainer></div>
        <div className="scenario-timeline">{stageList.map((stage, index) => { const points = samples.filter(s => s.stage === stage); const done = points.length >= SAMPLES_PER_STAGE; const mismatch = points.some(s => s.expected_label !== s.detected_label); return <div className={[points.length ? 'recorded' : '', done ? 'done' : '', stage === currentStage ? 'active' : '', mismatch ? 'mismatch' : ''].filter(Boolean).join(' ')} key={stage} aria-current={stage === currentStage ? 'step' : undefined}><span>{done ? <CheckCircle2 size={14} aria-label="완료"/> : <i className="step-index">{index + 1}</i>}{stages[stage] ?? stage}</span><p>{stageStory[stage] ?? ''}</p><strong>{points.length} / {SAMPLES_PER_STAGE} 저장</strong><small>{mismatch ? '기대와 다르게 판단됨' : done ? '기대대로 관측됨' : points.length ? '진행 중' : stage === currentStage ? '지금 실행 중' : '아직 실행 전'}</small></div>; })}</div>
        <div className="table-wrap"><table><thead><tr><th>단계</th><th>기대 유형</th><th>실제 탐지</th><th>DB 이벤트</th></tr></thead><tbody>{samples.map(s => <tr key={s.step}><td>{s.step + 1}. {stages[s.stage]}</td><td title={termTitle(attackTypeTerm(s.expected_label))}>{attackTypeLabel(s.expected_label)}</td><td className={s.detected_label === s.expected_label ? 'matched-label' : 'simulation-label'} title={termTitle(attackTypeTerm(s.detected_label))}>{attackTypeLabel(s.detected_label)}</td><td>{s.event_id ? <button className="event-link" onClick={() => setEventId(s.event_id)}>#{s.event_id} 상세 보기</button> : '정상 통과'}</td></tr>)}</tbody></table></div>
        <details className="run-evidence"><summary>실행 당시 임계값과 평가 범위</summary><p>유형 일치는 설계된 모의 단계의 기대값 비교이며 PCAP F1이나 공격 성공률이 아닙니다. 운영 임계값은 변경하지 않습니다.</p><pre>{JSON.stringify(run.thresholds, null, 2)}</pre></details>
      </div>}
    </section>{eventId !== null && <EventDetail id={eventId} onClose={() => setEventId(null)}/>}
  </div>;
}
function ShieldIcon() { return <FlaskConical size={24}/>; }
