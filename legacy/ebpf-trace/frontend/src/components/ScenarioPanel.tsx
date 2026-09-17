import { useEffect, useRef, useState } from 'react';
import { ArrowUpRight, Database, FlaskConical, Play, Square } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { errorMessage, getRun, getRuns, getScenarios, startRun, stopRun } from '../api/client';
import type { Scenario, ScenarioRun } from '../types';
import { EventDetail } from './EventDetail';

const stages: Record<string, string> = { baseline: '정상 접속', recon: '포트 탐색', flood: 'SYN 폭주', transfer: '대량 전송', recovery: '회복' };
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
  const chart = samples.map(item => ({ step: item.step + 1, pps: item.features.pkt_rate, mbps: item.features.byte_rate * 8 / 1e6, stage: stages[item.stage] }));
  return <div className="scenario-workspace">
    <div className="analysis-intro"><div><span className="eyebrow">DETECTION PLAYGROUND</span><h1>탐지 시나리오</h1><p>공격 징후가 이벤트와 데이터베이스에 기록되는 과정을 직접 확인하세요.</p></div><span className="simulation-tag"><FlaskConical size={16}/>모의 트래픽</span></div>
    <div className="scenario-notice"><ShieldIcon/><div><strong>외부로 패킷을 보내지 않는 탐지 리허설</strong><p>합성 피처 → 실제 탐지 엔진 → DB 저장 → 그래프와 이벤트. 모의 기록에는 SIMULATION 표시가 남으며 Slack 알림은 전송하지 않습니다.</p></div></div>
    <div className="scenario-cards">{catalog.map((item, index) => <section className="scenario-card" key={item.id}><span className="scenario-number">0{index + 1} / {item.duration_seconds} SEC</span><h2>{item.name}</h2><p>{item.description}</p><div className="stage-dots">{item.stages.map(stage => <span key={stage}>{stages[stage]}</span>)}</div><button className="primary-button" disabled={!secure || !token.trim() || busy || active} onClick={() => start(item.id)}><Play size={14}/>{item.name} 실행</button></section>)}</div>
    <div className="scenario-auth"><label htmlFor="scenario-token">관리자 토큰<input id="scenario-token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} placeholder="실행 또는 중지할 때 입력" disabled={!secure}/></label><p>{secure ? '토큰은 저장하지 않으며 요청 후 입력을 지웁니다. 한 번에 하나의 시나리오만 실행됩니다.' : '실행은 HTTPS 또는 localhost 접속에서 사용할 수 있습니다. 현재 화면에서는 실행 기록을 조회할 수 있습니다.'}</p></div>
    {(error || loadError) && <div className="error-banner" role="alert">{error || loadError}</div>}
    <section className="panel run-panel"><div className="panel-heading"><div><h2><Database size={17}/>실행 기록과 관측 결과</h2><p>DB에 저장된 데이터를 조회합니다. 새로고침 후에도 유지됩니다.</p></div><label>실행 기록<select aria-label="실행 기록" value={selected} onChange={e => setSelected(e.target.value)}><option value="">기록 선택</option>{runs.map(item => <option key={item.id} value={item.id}>{new Date(item.started_at).toLocaleString('ko-KR')} · {catalog.find(s => s.id === item.scenario_id)?.name ?? item.scenario_id} · {statuses[item.status]}</option>)}</select></label></div>
      {!run ? <div className="panel-message">{selected ? '실행 기록을 불러오는 중입니다.' : '시나리오를 실행하면 타임라인과 탐지 근거가 이곳에 기록됩니다.'}</div> : <div className="run-content"><div className="run-title"><div><span className={`run-status ${run.status}`}>{statuses[run.status]}</span><h3>{scenario?.name ?? run.scenario_id}</h3><code>{run.id}</code></div><div className="run-actions"><a className="outline-button" href={`#events?run=${run.id}`}><ArrowUpRight size={15}/>탐지 이벤트에서 보기</a>{run.status === 'running' && <button className="outline-button" disabled={!secure || !token || busy} onClick={stop}><Square size={13}/>실행 중지</button>}</div></div>
        <div className="run-stats"><div><span>저장된 샘플</span><strong>{samples.length}<small> / {(scenario?.duration_seconds ?? 0)}</small></strong></div><div><span>탐지 이벤트</span><strong>{run.event_count ?? 0}<small>건</small></strong></div><div><span>기대 유형 일치</span><strong>{run.matched_steps ?? 0}<small> / {samples.length}</small></strong></div><div><span>실행 엔진</span><strong>{run.detection_mode === 'hybrid' ? 'Hybrid' : 'Rules'}</strong></div></div>
        <div className="run-chart-legend"><span>● 패킷 / s · 왼쪽 축</span><span>● Mbps · 오른쪽 축</span><small>가로축: 저장된 샘플 순서</small></div><div className="run-chart" role="img" aria-label="데이터베이스에 저장된 시나리오 패킷과 대역폭 그래프"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chart}><CartesianGrid stroke="#edf1f6" vertical={false}/><XAxis dataKey="step" fontSize={11} tickLine={false}/><YAxis yAxisId="pps" fontSize={11} width={48}/><YAxis yAxisId="mbps" orientation="right" fontSize={11} width={40}/><Tooltip labelFormatter={v => `샘플 ${v}`} /><Area yAxisId="pps" dataKey="pps" name="패킷 / s" stroke="#526ce3" fill="#e8edff" isAnimationActive={false}/><Area yAxisId="mbps" dataKey="mbps" name="Mbps" stroke="#19a69b" fill="transparent" isAnimationActive={false}/></AreaChart></ResponsiveContainer></div>
        <div className="scenario-timeline">{scenario?.stages.map(stage => { const points = samples.filter(s => s.stage === stage); return <div className={points.length ? 'recorded' : ''} key={stage}><span>{stages[stage]}</span><strong>{points.length} / 3 저장</strong><small>{points.some(s => s.expected_label !== s.detected_label) ? '기대 유형과 차이 있음' : points.length ? '관측 완료' : '대기'}</small></div>; })}</div>
        <div className="table-wrap"><table><thead><tr><th>단계</th><th>기대 유형</th><th>실제 탐지</th><th>DB 이벤트</th></tr></thead><tbody>{samples.map(s => <tr key={s.step}><td>{s.step + 1}. {stages[s.stage]}</td><td>{s.expected_label}</td><td className={s.detected_label === s.expected_label ? 'matched-label' : 'simulation-label'}>{s.detected_label}</td><td>{s.event_id ? <button className="event-link" onClick={() => setEventId(s.event_id)}>#{s.event_id} 상세 보기</button> : '정상 통과'}</td></tr>)}</tbody></table></div>
        <details className="run-evidence"><summary>실행 당시 임계값과 평가 범위</summary><p>유형 일치는 설계된 모의 단계의 기대값 비교이며 PCAP F1이나 공격 성공률이 아닙니다. 운영 임계값은 변경하지 않습니다.</p><pre>{JSON.stringify(run.thresholds, null, 2)}</pre></details>
      </div>}
    </section>{eventId !== null && <EventDetail id={eventId} onClose={() => setEventId(null)}/>}
  </div>;
}
function ShieldIcon() { return <FlaskConical size={24}/>; }
