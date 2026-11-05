import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Cable, CheckCircle2, CircleDashed, Cpu, Network, Play, RadioTower, Shield, ShieldCheck, Square, TriangleAlert, Wifi, XCircle } from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { errorMessage, getInspection, getInspections, getInterfaces, runDefenseCheck, startInspection, stopInspection } from '../api/client';
import type { CheckItem, DefenseCheck, InspectionRun, InspectionStages, InterfaceInfo, LiveInterfaces } from '../types';
import { EventDetail } from './EventDetail';
import { Term } from './Term';
import { SEVERITY, UNIT, attackTypeLabel, engineLabel } from '../labels';
import { useNotifyStore } from '../store/notifyStore';
import '../live.css';

// 내 컴퓨터(서버가 돌아가는 호스트)의 와이파이·랜선 트래픽을 실제 탐지 경로에 통과시킨다.
// 1 수집 → 2 1차 방어선(규칙) → 3 2차 방어선(AI) → 4 대응. 각 단계는 서버가 계산한 상태를 그대로 보여 준다.
const KIND_ICON = { wifi: Wifi, ethernet: Cable, loopback: RadioTower, virtual: Network, other: Network } as const;
const KIND_LABEL: Record<InterfaceInfo['kind'], string> = { wifi: '와이파이', ethernet: '유선 랜', loopback: '루프백', virtual: '가상', other: '기타' };
const MODE_LABEL: Record<string, string> = { packet: '패킷 검사', counters: '카운터 검사' };
const RUN_STATUS: Record<string, string> = { running: '검사 중', completed: '완료', cancelled: '중지됨', failed: '실패', interrupted: '서버 재시작으로 중단' };
const STAGE_STATUS: Record<string, string> = { running: '진행 중', ok: '정상', empty: '관측 없음', idle: '해당 없음', skipped: '건너뜀', fail: '실패', failed: '실패', cancelled: '중지', warn: '주의' };
const CHECK_STATUS: Record<string, string> = { ok: '정상', warn: '주의', skipped: '건너뜀', fail: '실패' };
const DURATIONS = [5, 15, 30, 60, 120];
const formatBytes = (value: number) => value >= 1e9 ? `${(value / 1e9).toFixed(2)} GB` : value >= 1e6 ? `${(value / 1e6).toFixed(1)} MB` : value >= 1e3 ? `${(value / 1e3).toFixed(0)} KB` : `${Math.round(value)} B`;
const time = (value: number) => new Date(value).toLocaleTimeString('ko-KR', { hour12: false, minute: '2-digit', second: '2-digit' });

function StatusIcon({ status }: { status: string }) {
  if (status === 'ok') return <CheckCircle2 size={13} aria-hidden="true"/>;
  if (status === 'fail' || status === 'failed' || status === 'cancelled') return <XCircle size={13} aria-hidden="true"/>;
  if (status === 'warn') return <TriangleAlert size={13} aria-hidden="true"/>;
  if (status === 'running') return null;
  return <CircleDashed size={13} aria-hidden="true"/>;
}

function Stage({ id, icon: Icon, title, caption, status, value, unit, children }: { id: string; icon: typeof Wifi; title: string; caption: string; status: string; value: string; unit?: string; children: React.ReactNode }) {
  return <section className={`stage ${id} ${status}`} aria-label={title}>
    <div className="stage-head"><Icon size={14}/>{title}<small>{caption}</small><span className="stage-status"><StatusIcon status={status}/>{STAGE_STATUS[status] ?? status}</span></div>
    <div className="stage-value">{value}{unit && <small>{unit}</small>}</div>
    <p className="stage-sub">{children}</p>
  </section>;
}

function stageSummary(run: InspectionRun) {
  const s = run.stages;
  const hits = Object.values(s.rules.hits).reduce((a, b) => a + b, 0);
  if (run.status === 'running') return `${run.interface}에서 ${run.elapsed_seconds}초째 관측 중 · 지금까지 ${s.capture.packets.toLocaleString()}패킷을 규칙${s.model.status === 'skipped' ? '' : '과 AI'}에 통과시켰고 ${s.response.events}건을 탐지했어요.`;
  if (run.status === 'failed') return `검사가 중단됐어요: ${run.error || '알 수 없는 오류'}`;
  const model = s.model.status === 'skipped' ? `2차 AI는 ${s.model.reason}` : `2차 AI는 ${s.model.scored}건에 점수를 매겨 ${s.model.anomalies}건을 이상으로 봤어요`;
  return `${run.duration_seconds}초 중 ${run.elapsed_seconds}초를 관측했어요. 1차 규칙이 ${s.rules.checked}건을 판정해 ${hits}건에 걸렸고, ${model}. 대응 단계로 넘어간 탐지는 ${s.response.events}건(사건 ${s.response.incidents}건)이에요.`;
}

export function LiveInspectionPanel() {
  const [token, setToken] = useState(''), [live, setLive] = useState<LiveInterfaces | null>(null);
  const [selected, setSelected] = useState(''), [mode, setMode] = useState('auto'), [duration, setDuration] = useState(30);
  const [run, setRun] = useState<InspectionRun | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [check, setCheck] = useState<DefenseCheck | null>(null), [checking, setChecking] = useState(false);
  // 검사 기록은 서버 DB(live_inspections)에서 읽는다. 새로고침·서버 재시작 뒤에도 남는다.
  const [history, setHistory] = useState<InspectionRun[]>([]);
  const loadHistory = (value: string) => getInspections(value).then(setHistory).catch(() => {});
  const [eventId, setEventId] = useState<number | null>(null);
  const secure = window.isSecureContext;
  const toast = useNotifyStore(s => s.toast);
  const unlocked = live !== null;
  const packetOk = live?.capabilities.packet.available ?? false;
  const iface = live?.items.find(item => item.name === selected);

  const unlock = async () => {
    if (!token.trim() || busy) return;
    setBusy(true); setError('');
    try {
      const value = await getInterfaces(token);
      setLive(value);
      loadHistory(token);
      setSelected(current => current || value.items.find(item => item.active)?.name || value.items.find(item => item.is_up)?.name || '');
    } catch (e) { setError(errorMessage(e)); setLive(null); }
    finally { setBusy(false); }
  };
  const start = async () => {
    if (!iface || busy) return;
    setBusy(true); setError('');
    try { const started = await startInspection({ interface: iface.name, mode, duration_seconds: duration }, token); setRun(started); setHistory(items => [started, ...items.filter(item => item.id !== started.id)]); }
    catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); }
  };
  const stop = async () => {
    if (!run) return;
    setBusy(true);
    try { setRun(await stopInspection(run.id, token)); } catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); }
  };
  const runCheck = async () => {
    if (checking) return;
    setChecking(true); setError('');
    try { setCheck(await runDefenseCheck(token)); } catch (e) { setError(errorMessage(e)); }
    finally { setChecking(false); }
  };
  // 검사 중에는 1초마다 서버 상태를 가져온다(창·단계 카운터는 서버 계산값).
  useEffect(() => {
    if (!run || run.status !== 'running') return;
    const controller = new AbortController();
    const timer = setInterval(() => getInspection(run.id, token, controller.signal).then(setRun).catch(e => { if (!controller.signal.aborted) setError(errorMessage(e)); }), 1000);
    return () => { controller.abort(); clearInterval(timer); };
  }, [run?.id, run?.status, token]);
  // 끝나면 토스트로 알린다(다른 상태로 바뀔 때만).
  const lastStatus = useRef<string | null>(null);
  useEffect(() => {
    if (!run) return;
    const before = lastStatus.current; lastStatus.current = `${run.id}:${run.status}`;
    if (!before || !before.startsWith(run.id) || run.status === 'running') return;
    loadHistory(token);
    toast(run.status === 'completed'
      ? { level: 'ok', duration: 7000, text: `${run.interface} 검사가 끝났어요 · ${run.stages.response.events}건 탐지`, action: run.stages.response.events ? { label: '기록 보기', href: '#events' } : undefined }
      : { level: 'warn', duration: 7000, text: `${run.interface} 검사가 "${RUN_STATUS[run.status] ?? run.status}" 상태로 끝났어요.` });
  }, [run, toast, token]);

  const windows = run?.windows ?? [];
  const chart = useMemo(() => windows.map(w => ({ t: w.t, pps: Math.round(w.pkt_rate), mbps: Number((w.byte_rate * 8 / 1e6).toFixed(3)) })), [windows]);
  const detections = useMemo(() => windows.flatMap(w => w.events.map(e => ({ ...e, t: w.t }))), [windows]);
  const stages: InspectionStages | undefined = run?.stages;
  const hitsText = stages ? Object.entries(stages.rules.hits).map(([type, n]) => `${attackTypeLabel(type)} ${n}건`).join(' · ') : '';
  const progress = run ? Math.min(100, 100 * run.elapsed_seconds / run.duration_seconds) : 0;
  const capNote = mode === 'counters' || (mode === 'auto' && !packetOk) ? `카운터 검사: 초당 패킷·전송량만 읽어요 → 트래픽 급증·대용량 전송 규칙만 판정돼요${live?.capabilities.packet.reason ? ` (패킷 검사 불가: ${live.capabilities.packet.reason})` : ''}` : '패킷 검사: 패킷 하나하나를 읽어 25개 관측 항목을 계산해요 → 4개 규칙과 AI 점수를 모두 확인할 수 있어요';

  return <div className="live-workspace">
    <div className="analysis-intro"><div><span className="eyebrow">실시간 검사</span><h1>내 네트워크 검사</h1><p>이 서버가 연결된 와이파이·랜선의 실제 트래픽을 1차 규칙 → 2차 AI → 대응 경로에 그대로 통과시켜요.</p></div><span className="live-tagline"><Wifi size={15}/>실제 트래픽 · 저장됨</span></div>
    {!unlocked && <div className="live-steps">
      <div><i>1</i><strong>관리자 토큰 입력</strong><p>서버 호스트의 네트워크 장치를 다루므로 관리자만 실행할 수 있어요.</p></div>
      <div><i>2</i><strong>인터페이스 선택</strong><p>와이파이(Wi-Fi)·유선 랜 중 지금 쓰는 연결을 고르세요.</p></div>
      <div><i>3</i><strong>검사 시작</strong><p>정한 시간 동안 매초 관측을 규칙과 AI에 넣고, 탐지되면 사건으로 묶어요.</p></div>
      <div><i>4</i><strong>방어선 점검</strong><p>규칙·AI·차단 안전 점검이 지금 설정으로 제대로 판정하는지 한 번에 확인해요.</p></div>
    </div>}
    <section className="panel">
      <div className="panel-heading"><div><h2><ShieldCheck size={17}/>검사 준비</h2><p>토큰은 브라우저에 저장하지 않으며 이 화면을 떠나면 지워집니다.</p></div>{live && <span className="live-tag">{live.host}</span>}</div>
      <form className="live-unlock" onSubmit={e => { e.preventDefault(); unlock(); }}>
        <label htmlFor="live-token">관리자 토큰<input id="live-token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} placeholder="관리자 토큰을 입력하세요" disabled={!secure}/></label>
        <button className="primary-button" type="submit" disabled={!secure || !token.trim() || busy}>{unlocked ? '인터페이스 다시 불러오기' : '인터페이스 불러오기'}</button>
        <p>{secure ? '토큰이 맞으면 이 서버의 네트워크 인터페이스 목록을 가져와요. 검사 결과는 실제(LIVE) 탐지 기록으로 저장돼요.' : '실시간 검사는 HTTPS 또는 localhost 접속에서만 사용할 수 있어요.'}</p>
      </form>
      {live && <>
        <div className="live-host"><span>호스트 <b>{live.host}</b></span><span>인터페이스 <b>{live.items.filter(i => i.is_up && i.addresses.length > 0).length}개 (주소 있는 활성 장치만 표시)</b></span><span>패킷 검사 <b>{packetOk ? '가능' : '불가'}</b></span></div>
        <div className="iface-grid" role="radiogroup" aria-label="네트워크 인터페이스">{live.items.filter(item => item.is_up && item.addresses.length > 0).map(item => { const Icon = KIND_ICON[item.kind]; return <button type="button" role="radio" aria-checked={selected === item.name} className={`iface kind-${item.kind}`} key={item.name} onClick={() => setSelected(item.name)} disabled={run?.status === 'running'}>
          <span className="iface-icon"><Icon size={17}/></span>
          <span className="iface-text"><strong>{item.name} · {KIND_LABEL[item.kind]}</strong><span>{item.label}{item.addresses[0] ? ` · ${item.addresses[0]}` : ' · 주소 없음'}{item.speed_mbps ? ` · ${item.speed_mbps >= 1000 ? `${item.speed_mbps / 1000}G` : `${item.speed_mbps}M`}` : ''}</span></span>
          <span className={`iface-state${item.active ? '' : ' down'}`}>{item.active ? '사용 중' : '보조'}</span>
        </button>; })}</div>
        <div className="live-options">
          <label>검사 방식<select aria-label="검사 방식" value={mode} onChange={e => setMode(e.target.value)} disabled={run?.status === 'running'}><option value="auto">자동 (가능하면 패킷)</option><option value="packet" disabled={!packetOk}>패킷 검사 · 25개 항목{packetOk ? '' : ' (권한 필요)'}</option><option value="counters">카운터 검사 · 권한 불필요</option></select></label>
          <label>검사 시간<select aria-label="검사 시간" value={duration} onChange={e => setDuration(Number(e.target.value))} disabled={run?.status === 'running'}>{DURATIONS.map(d => <option key={d} value={d}>{d}초</option>)}</select></label>
          {run?.status === 'running'
            ? <button className="outline-button" type="button" onClick={stop} disabled={busy}><Square size={13}/>검사 중지</button>
            : <button className="primary-button" type="button" onClick={start} disabled={!iface || busy}><Play size={14}/>검사 시작</button>}
          <p className={`live-cap${mode !== 'counters' && packetOk ? ' ok' : ''}`}>{capNote}</p>
        </div>
      </>}
    </section>
    {error && <div className="error-banner" role="alert">{error}</div>}
    <section className="panel">
      <div className="panel-heading"><div><h2><Activity size={17}/>검사 흐름</h2><p>수집 → 1차 방어선(규칙) → 2차 방어선(AI) → 대응. 각 칸은 서버가 매초 계산해 DB에 저장한 값이에요.</p></div>{unlocked && <label className="live-history">검사 기록<select aria-label="검사 기록" value={run?.id ?? ''} disabled={run?.status === 'running'} onChange={e => { const id = e.target.value; if (!id) { setRun(null); return; } getInspection(id, token).then(setRun).catch(err => setError(errorMessage(err))); }}><option value="">기록 선택 ({history.length}건)</option>{history.map(item => <option key={item.id} value={item.id}>{new Date(item.started_at).toLocaleString('ko-KR')} · {item.interface} · {RUN_STATUS[item.status] ?? item.status}</option>)}</select></label>}</div>
      {!run || !stages ? <div className="panel-message">인터페이스를 고르고 검사를 시작하면 네 단계가 여기서 채워져요. 대시보드의 실시간 그래프에도 같은 관측이 흐릅니다.</div> : <>
        <div className="live-run-head"><div><span className={`run-status ${run.status}`}>{RUN_STATUS[run.status] ?? run.status}</span><h3>{run.interface} · {run.address}</h3><code>{run.id}</code></div><div><span className="rule-only">엔진 {engineLabel(run.detection_mode) || run.detection_mode}</span></div></div>
        <div className="live-progress" role="progressbar" aria-label="검사 진행률" aria-valuemin={0} aria-valuemax={run.duration_seconds} aria-valuenow={run.elapsed_seconds} aria-valuetext={`${run.elapsed_seconds} / ${run.duration_seconds}초`}><i style={{ width: `${progress}%` }}/></div>
        <p className="live-summary" role="status">{stageSummary(run)}</p>
        <div className="live-stages">
          <Stage id="capture" icon={Wifi} title="수집" caption={MODE_LABEL[stages.capture.mode]} status={stages.capture.status} value={stages.capture.peak_pps.toLocaleString()} unit="최고 pps">
            <b>{stages.capture.packets.toLocaleString()}</b> 패킷 · {formatBytes(stages.capture.bytes)} · {stages.capture.seconds}초{stages.capture.mode === 'packet' ? ` · 흐름 최대 ${stages.capture.flows}개` : ''}<br/>{stages.capture.note}
          </Stage>
          <Stage id="rules" icon={Shield} title="1차 방어선" caption="규칙" status={stages.rules.status} value={Object.values(stages.rules.hits).reduce((a, b) => a + b, 0).toLocaleString()} unit="건 규칙에 걸림">
            관측 <b>{stages.rules.checked}건</b> 판정 · {hitsText || '위협 규칙에 걸린 관측 없음'}<br/>{stages.rules.note}
          </Stage>
          <Stage id="model" icon={Cpu} title="2차 방어선" caption="AI" status={stages.model.status} value={stages.model.min_score != null ? stages.model.min_score.toFixed(3) : '—'} unit={stages.model.min_score != null ? '최저 이상 점수' : undefined}>
            {stages.model.status === 'skipped' ? <>{stages.model.reason}<br/>엔진 {engineLabel(stages.model.mode) || stages.model.mode} · 규칙만 사용 중</> : <>점수 <b>{stages.model.scored}건</b> · 이상 <b>{stages.model.anomalies}건</b> · 기준 {stages.model.threshold}<br/>{stages.model.feature_count}개 항목 모델 · <Term term={UNIT.anomalyScore} short/></>}
          </Stage>
          <Stage id="response" icon={ShieldCheck} title="대응" caption="사건 · 자동 경로" status={stages.response.status} value={stages.response.events.toLocaleString()} unit="건 탐지">
            사건 <b>{stages.response.incidents}건</b> · 자동 적용 {stages.response.automatic.applied} · 승인 경로 {stages.response.automatic.declined}<br/>{stages.response.note}
          </Stage>
        </div>
        <div className="run-chart-legend"><span>● <Term term={UNIT.pps}/> · 왼쪽 축</span><span>● <Term term={UNIT.mbps}/> · 오른쪽 축</span><small>가로축: 검사 시각</small></div>
        <div className="live-chart" role="img" aria-label="검사 중 관측한 초당 패킷과 전송량"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chart}><CartesianGrid stroke="#edf1f6" vertical={false}/><XAxis dataKey="t" tickFormatter={time} minTickGap={40} fontSize={11} tickLine={false}/><YAxis yAxisId="pps" fontSize={11} width={48}/><YAxis yAxisId="mbps" orientation="right" fontSize={11} width={40}/><Tooltip labelFormatter={v => time(Number(v))}/><Area yAxisId="pps" dataKey="pps" name="초당 패킷(pps)" stroke="#3775e8" fill="#e8edff" isAnimationActive={false}/><Area yAxisId="mbps" dataKey="mbps" name="초당 전송량(Mbps)" stroke="#17a994" fill="transparent" isAnimationActive={false}/></AreaChart></ResponsiveContainer></div>
        <div className="live-events"><h4>검사 중 탐지 {detections.length}건</h4>{detections.length ? <div className="table-wrap"><table><thead><tr><th>시각</th><th>탐지 유형</th><th>심각도</th><th>사건</th><th>자동 경로</th><th>상세</th></tr></thead><tbody>{detections.map(d => <tr key={d.event_id}><td>{time(d.t)}</td><td>{attackTypeLabel(d.attack_type)}</td><td>{SEVERITY[d.severity]?.label ?? d.severity}</td><td>{d.incident_id ? <a href={`#incidents?id=${d.incident_id}`}>사건 열기</a> : '—'}</td><td>{d.automatic === 'applied' ? '자동 적용' : d.automatic === 'declined' ? '승인 경로' : d.automatic ?? '평가 없음'}</td><td><button className="event-link" onClick={() => setEventId(d.event_id)}>#{d.event_id} 상세 보기</button></td></tr>)}</tbody></table></div> : <p className="empty-note">{run.status === 'running' ? '아직 규칙이나 AI에 걸린 관측이 없어요. 평소 트래픽이라면 정상이에요.' : '이 검사에서는 위협으로 판정된 관측이 없었어요. 탐지 시나리오로 규칙이 동작하는지 따로 확인할 수 있어요.'}</p>}</div>
      </>}
    </section>
    <section className="panel">
      <div className="panel-heading"><div><h2><ShieldCheck size={17}/>방어선 점검</h2><p>실제 트래픽을 기다리지 않고, 저장된 임계값으로 만든 표본을 규칙·AI·차단 안전 점검에 넣어 판정을 확인해요. 아무것도 저장하지 않아요.</p></div><button className="primary-button" type="button" onClick={runCheck} disabled={!unlocked || checking}><ShieldCheck size={14}/>{checking ? '점검 중…' : '방어선 점검 실행'}</button></div>
      {!check ? <div className="panel-message">{unlocked ? '점검을 실행하면 수집 · 1차 규칙 · 2차 AI · 대응 네 줄의 결과가 표시돼요.' : '관리자 토큰으로 인터페이스를 불러온 뒤 실행할 수 있어요.'}</div> : <div className="live-check">
        <div className="check-summary"><span>{new Date(check.checked_at).toLocaleString('ko-KR')} 기준</span>{Object.entries(check.summary).filter(([, n]) => n).map(([status, n]) => <span className={`check-pill ${status}`} key={status}>{CHECK_STATUS[status]} {n}</span>)}</div>
        {check.items.map(item => <CheckRow item={item} key={item.id}/>)}
      </div>}
    </section>
    {eventId !== null && <EventDetail id={eventId} onClose={() => setEventId(null)}/>}
  </div>;
}

function CheckRow({ item }: { item: CheckItem }) {
  const probes = item.probes ?? [];
  return <details className={`check-item ${item.status}`} open={item.status === 'fail'}>
    <summary><span className={`check-pill ${item.status}`}>{CHECK_STATUS[item.status]}</span>{item.title}</summary>
    <p className="check-detail">{item.detail}{item.live_reason ? ` · ${item.live_reason}` : ''}</p>
    {item.id === 'rules' && probes.length > 0 && <div className="table-wrap"><table><thead><tr><th>표본</th><th>기대 판정</th><th>실제 판정</th><th>결과</th></tr></thead><tbody>{probes.map(p => <tr key={p.name}><td>{p.name}</td><td>{attackTypeLabel(p.expected ?? '')}</td><td>{attackTypeLabel(p.detected ?? '')}</td><td className={p.passed ? 'pass' : 'miss'}>{p.passed ? '일치' : '불일치'}</td></tr>)}</tbody></table></div>}
    {item.id === 'model' && probes.length > 0 && <div className="table-wrap"><table><thead><tr><th>표본</th><th>AI 이상 점수</th><th>판정</th></tr></thead><tbody>{probes.map(p => <tr key={p.name}><td>{p.name}</td><td>{p.score != null ? p.score.toFixed(3) : '—'}</td><td className={p.flagged ? 'miss' : 'pass'}>{p.flagged ? '이상' : '정상'}</td></tr>)}</tbody></table></div>}
    {item.id === 'model' && <div className="check-facts"><span>엔진 <b>{engineLabel(item.mode) || item.mode}</b></span><span>관측 항목 <b>{item.contract === 'context-25' ? '25개(문맥)' : item.contract === 'source-9' ? '9개' : '6개'}</b></span><span>실시간 경로 적용 <b>{item.live_applied ? '예' : '아니오'}</b></span></div>}
    {item.id === 'response' && probes.length > 0 && <div className="table-wrap"><table><thead><tr><th>표본 출발지</th><th>위험 점수</th><th>기대 경로</th><th>실제 경로</th><th>근거</th></tr></thead><tbody>{probes.map(p => <tr key={p.name}><td>{p.name}</td><td>{p.score?.toFixed(2)}{p.hard_stop ? ' · 강제 정지' : ''}</td><td>{p.expected === 'automatic' ? '자동 경로' : '승인 경로'}</td><td className={p.passed ? 'pass' : 'miss'}>{p.route === 'automatic' ? '자동 경로' : '승인 경로'}</td><td style={{ whiteSpace: 'normal' }}>{p.reason}</td></tr>)}</tbody></table></div>}
    {item.id === 'response' && item.control && <div className="check-facts"><span>자동 경로 <b>{item.control.auto_response ? '켜짐' : '꺼짐'}</b></span><span>전체 중지 <b>{item.control.kill_switch ? '켜짐' : '꺼짐'}</b></span><span>자동 경로 등록 자산 <b>{item.assets_opted_in}/{item.assets}</b></span><span>활성 대응 지점 <b>{item.points_enabled}</b></span><span>자동 해제 <b>{item.auto_ttl_seconds}초</b></span></div>}
    {item.id === 'capture' && <div className="check-facts"><span>활성 인터페이스 <b>{item.interfaces?.join(', ') || '없음'}</b></span><span>패킷 검사 <b>{item.capabilities?.packet.available ? '가능' : '불가'}</b></span></div>}
  </details>;
}
