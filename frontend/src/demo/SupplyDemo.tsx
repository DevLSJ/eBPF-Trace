import { useCallback, useEffect, useRef, useState } from 'react';
import { BookOpen, Check, ChevronRight, CircleAlert, Clock3, Cloud, FlaskConical, HelpCircle, History, LayoutDashboard, LoaderCircle, Package, Play, Settings2, ShieldCheck } from 'lucide-react';
import { errorMessage } from '../api/client';
import { demoCommand, downloadReport, loadCatalog, loadSession, resetDemo, startDemo, type Catalog, type DemoSession, type Envelope } from './api';
import { DemoContext, go, instructions, move, steps, type DemoContextValue } from './context';
import { ActivityPage, AdvancedPage, ComponentsPage, DeliveryPage, Home, ResultPage } from './Pages';
import StepContent from './Steps';
import { Modal, Notice, type Panel } from './ui';
import './supply-demo.css';

const nav = [{ hash: '#supply', label: '개요', icon: LayoutDashboard }, { hash: '#supply/demo', label: '안내 시연', icon: Play }, { hash: '#supply/components', label: '사용 부품', icon: Package }, { hash: '#supply/delivery', label: '배포·운영', icon: Cloud }, { hash: '#supply/activity', label: '활동 기록', icon: History }];
const titles: Record<string, [string, string, string]> = {
  '#supply/components': ['SOFTWARE COMPONENTS', '어떤 부품을 사용하나요?', '부품의 버전과 사용 조건을 확인하고, 어느 배포에 포함됐는지 따라가 보세요.'],
  '#supply/delivery': ['DELIVERY & OPERATIONS', '검사에서 배포, 운영까지', '검증한 버전과 파일 지문을 기준으로 배포와 관측 기록을 연결합니다.'],
  '#supply/activity': ['ACTIVITY & EVIDENCE', '무엇을 확인하고 바꿨나요?', '실제로 발생한 시연 동작만 기록합니다. 결과와 근거는 다운로드할 수 있습니다.'],
  '#supply/result': ['YOUR DEMO, WITH EVIDENCE', '안전한 배포는, 확인의 연결입니다.', '무엇을 발견했고, 왜 멈췄고, 어떻게 확인했는지 되짚어 보세요.'],
  '#supply/advanced': ['ADVANCED · CLEAR BOUNDARIES', '시연과 실제 기능을 구분합니다', '처음 체험할 때는 이 설정들이 필요하지 않습니다. 기존 기능과 외부 연동의 범위를 확인하세요.'],
};

export default function SupplyDemo({ hash }: { hash: string }) {
  const [session, setSession] = useState<DemoSession | null>(null), [catalog, setCatalog] = useState<Catalog | null>(null);
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(''), [error, setError] = useState(''), [expired, setExpired] = useState(false);
  const [panel, setPanel] = useState<Panel | null>(null), [resetOpen, setResetOpen] = useState(false), [showGuide, setShowGuide] = useState(true);
  const [retry, setRetry] = useState<(() => void) | null>(null);
  const executing = useRef(false), main = useRef<HTMLElement>(null);
  const parts = hash.split('/'), base = parts.length > 1 ? `${parts[0]}/${parts[1]}` : parts[0];
  const known = new Set(['#supply', '#supply/demo', ...Object.keys(titles)]), section = known.has(base) ? base : '#supply';
  const requested = Number(parts[2]);
  const step = section === '#supply/demo' ? Math.max(1, Math.min(6, Number.isInteger(requested) ? requested : session?.stage || 1, session?.stage || 1)) : session?.stage || 1;
  const pending = session?.scans.some(s => ['queued', 'running'].includes(s.status));
  const apply = useCallback((value: Envelope) => { setSession(old => old && value.session && old.id === value.session.id && old.revision > value.session.revision ? old : value.session); setExpired(!!value.expired); }, []);
  const refresh = useCallback(async (signal?: AbortSignal) => { const [state, options] = await Promise.all([loadSession(signal), loadCatalog(signal)]); apply(state); setCatalog(options); setError(''); setLoading(false); }, [apply]);
  useEffect(() => { const controller = new AbortController(); refresh(controller.signal).catch(e => { if (!controller.signal.aborted) { setError(errorMessage(e)); setLoading(false); setRetry(() => () => { setLoading(true); void refresh().catch(e => { setError(errorMessage(e)); setLoading(false); }); }); } }); return () => controller.abort(); }, [refresh]);
  useEffect(() => { if (!pending) return; const controller = new AbortController(); const timer = setInterval(() => { loadSession(controller.signal).then(value => { if (!controller.signal.aborted) apply(value); }).catch(e => { if (!controller.signal.aborted) { setError(errorMessage(e)); setRetry(() => () => { void refresh().catch(e => setError(errorMessage(e))); }); } }); }, 700); return () => { controller.abort(); clearInterval(timer); }; }, [pending, session?.id, apply, refresh]);
  useEffect(() => { window.scrollTo(0, 0); main.current?.querySelector<HTMLHeadingElement>('h1')?.focus(); setPanel(null); }, [hash, loading]);
  async function perform(label: string, task: () => Promise<void>) {
    if (executing.current) return; executing.current = true; setBusy(label); setError(''); setRetry(null);
    try { await task(); } catch (e) { setError(errorMessage(e)); setRetry(() => () => { void perform(label, task); }); } finally { executing.current = false; setBusy(''); }
  }
  const act: DemoContextValue['act'] = async (kind, args = {}, then) => {
    const key = `supply-demo-command:${session?.id}:${kind}:${JSON.stringify(args)}`;
    const requestId = sessionStorage.getItem(key) || crypto.randomUUID(); sessionStorage.setItem(key, requestId);
    await perform(kind, async () => { const value = await demoCommand(kind, requestId, args); apply(value); sessionStorage.removeItem(key); then?.(value); });
  };
  function prepare() { const key = 'supply-demo-bootstrap', id = sessionStorage.getItem(key) || crypto.randomUUID(); sessionStorage.setItem(key, id); void perform('prepare', async () => { const value = await startDemo(id); apply(value); sessionStorage.removeItem(key); go(2); }); }
  const help: DemoContextValue['help'] = (title, content, topic = 'guide') => { setPanel({ title, content }); if (session) void demoCommand('help', crypto.randomUUID(), { step, topic }).catch(() => {}); };
  const resume = () => move(session?.completed_at ? '#supply/result' : `#supply/demo/${session?.stage || 1}`);
  const report = () => { void perform('download', downloadReport); };
  const guidePanel = <><p>여섯 단계에서 검사와 배포 정책의 역할을 직접 확인합니다. 가입·저장소 연결·API 키는 필요하지 않습니다.</p><ol className="demo-help-list">{steps.map((title, i) => <li key={title}><b>{i + 1}. {title}</b><p>{instructions[i][2]}</p></li>)}</ol><Notice kind="warning" title="실제 서비스에는 영향을 주지 않습니다">취약점은 고정 예시이며, 수정과 배포는 시연 기록에만 반영됩니다.</Notice></>;
  const title = titles[section];
  return <DemoContext.Provider value={{ session, catalog, busy, act, help, prepare, resume, report, reset: () => setResetOpen(true) }}><div className="trust-app"><a className="demo-skip" href="#demo-content" onClick={e => { e.preventDefault(); main.current?.querySelector<HTMLHeadingElement>('h1')?.focus(); }}>본문으로 바로가기</a>
    <header className="trust-header"><a className="trust-brand" href="#supply" aria-label="Trace 공급망 신뢰 개요"><span><ShieldCheck size={25}/></span><b>Trace<small>SUPPLY CHAIN LAB</small></b></a><nav aria-label="주 메뉴">{nav.map(item => <a key={item.hash} href={item.hash === '#supply/demo' ? `#supply/demo/${session?.stage || 1}` : item.hash} aria-current={section === item.hash || (section === '#supply/result' && item.hash === '#supply/demo') ? 'page' : undefined}><item.icon size={17}/>{item.label}</a>)}</nav><a className="trust-settings" href="#supply/advanced" aria-label="고급 설정과 실제 기능"><Settings2 size={19}/><span>고급 설정</span></a></header>
    <div className="demo-environment"><FlaskConical size={15}/><span>시연 환경 · 실제 서비스에 영향을 주지 않습니다</span><button onClick={() => help('안내 시연 사용 방법', guidePanel)}><HelpCircle size={15}/>사용 방법</button></div>
    {section !== '#supply' && section !== '#supply/advanced' && <div className="demo-progress" aria-label="전체 시연 단계">{steps.map((name, i) => <button key={name} aria-current={section === '#supply/demo' && step === i + 1 ? 'step' : undefined} disabled={i + 1 > (session?.stage || 1)} title={i + 1 > (session?.stage || 1) ? '앞 단계의 행동을 완료하면 열립니다' : `${name} 다시 보기`} onClick={() => go(i + 1)}><span>{i + 1 < (session?.stage || 1) ? <Check size={15}/> : i + 1}</span><b>{name}</b>{i < 5 && <ChevronRight size={16}/>}</button>)}<p>완료한 단계는 다시 볼 수 있습니다. 다음 단계는 현재 행동을 마치면 열립니다.</p></div>}
    <main className="trust-main" ref={main} id="demo-content">
      {error && <div className="demo-error" role="alert"><CircleAlert size={21}/><div><strong>요청을 완료하지 못했습니다</strong><p>{error}</p><small>이미 저장된 진행 상황은 유지됩니다.</small></div>{retry && <button disabled={!!busy} onClick={retry}>다시 시도</button>}<button disabled={!!busy} onClick={() => void refresh().catch(e => setError(errorMessage(e)))}>저장된 진행 다시 불러오기</button></div>}
      {expired && !session && <Notice kind="warning" title="이전 시연 세션이 만료되었습니다">같은 브라우저에서 7일간 이어갈 수 있습니다. 새 프로젝트로 다시 시작하세요.</Notice>}
      {loading ? <div className="demo-loading" role="status"><LoaderCircle className="demo-spin"/>시연 환경을 확인하는 중…</div> : <>
        {title && <div className="demo-page-title"><div><span className="demo-eyebrow">{title[0]}</span><h1 tabIndex={-1}>{title[1]}</h1><p>{title[2]}</p></div></div>}
        {section === '#supply' ? <Home/> : section === '#supply/demo' ? <><div className="demo-page-title"><div><span className="demo-eyebrow">GUIDED EXPERIENCE · {String(step).padStart(2, '0')} / 06</span><h1 tabIndex={-1}>{steps[step - 1]}</h1><p>{['한 번의 체험으로, 소프트웨어의 신뢰가 연결되는 과정을 확인하세요.', '우리 코드만큼 중요한 외부 부품, 함께 확인해 보세요.', '배포 전에 확인할 문제와 정책의 차단을 직접 경험해 보세요.', '무엇을 바꾸는지 확인하고, 새 버전의 검증을 요청하세요.', '검사한 파일과 배포할 파일이 일치할 때만 진행합니다.', '배포 후에도 관측은 계속됩니다. 같은 버전의 기록을 연결해 보세요.'][step - 1]}</p></div><span className="demo-time"><Clock3 size={15}/>내 속도로 진행</span></div><div className="demo-step-layout"><section className="demo-step-main"><StepContent step={step}/></section><aside className="demo-guide"><div><span><BookOpen size={19}/>이 단계의 안내</span><button aria-expanded={showGuide} onClick={() => setShowGuide(v => !v)}>{showGuide ? '접기' : '펼치기'}</button></div>{showGuide ? <ol>{['지금 무엇을 확인하나요?', '왜 필요한가요?', '다음에는 무엇을 누르나요?'].map((name, i) => <li key={name}><b>{name}</b><p>{instructions[step - 1][i]}</p></li>)}</ol> : <p>상단 “사용 방법”에서도 안내를 다시 열 수 있습니다.</p>}<div className="demo-guide-bottom"><ShieldCheck size={18}/><p>근거를 읽고, 직접 눌러보세요.<br/>결과는 다음 단계로 가도 남아 있습니다.</p></div></aside></div></> : section === '#supply/components' ? <ComponentsPage/> : section === '#supply/delivery' ? <DeliveryPage/> : section === '#supply/activity' ? <ActivityPage/> : section === '#supply/result' ? <ResultPage/> : <AdvancedPage/>}
      </>}
      <footer className="trust-footer"><span><ShieldCheck size={16}/>Trace · 소프트웨어 공급망 신뢰를 위한 안전한 SW 개발</span><a href="#supply/advanced">실제 기능과 시연 범위</a><small>검사하지 않음 ≠ 안전함</small></footer>
    </main>
    {panel && <Modal panel={panel} close={() => setPanel(null)}/>}
    {resetOpen && <Modal compact close={() => { if (!busy) setResetOpen(false); }} panel={{ title: '현재 시연만 초기화할까요?', content: <><p>이 브라우저의 시연 프로젝트, 버전, 검사·차단·배포·활동 기록을 지웁니다. <b>다른 방문자의 시연과 실제 운영 데이터는 변경하지 않습니다.</b></p><p>보관하려면 먼저 결과를 다운로드하세요.</p><div className="demo-action-row"><button className="demo-secondary" disabled={!!busy} onClick={() => setResetOpen(false)}>취소하고 시연 유지</button><button className="demo-danger-button" disabled={!!busy} onClick={() => void perform('reset', async () => { apply(await resetDemo()); sessionStorage.removeItem('supply-demo-bootstrap'); setResetOpen(false); go(1); })}>{busy === 'reset' ? '현재 시연 초기화 중…' : '현재 시연만 초기화'}</button></div></> }}/>}
  </div></DemoContext.Provider>;
}
