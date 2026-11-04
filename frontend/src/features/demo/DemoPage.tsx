import { Check, FileText, Minus, Play, RotateCw, ScrollText, TriangleAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { CodeWindow } from '../../components/CodeWindow';
import { KindBadge } from '../../components/KindBadge';
import { LoadError, Panel } from '../../components/Panel';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useAuth } from '../../hooks/auth-context';
import { useStream } from '../../hooks/stream-context';
import { fmtNum, shortId } from '../../lib/format';
import { KIND_SHORT } from '../../lib/policyEasy';
import { DEMO_SCENARIOS, type DemoRun, type Evidence, type InstallSession } from '../../lib/types';
import {
  buildModel,
  elapsedSec,
  EXPECT_LABEL,
  markParts,
  ms3,
  msBetween,
  rawOf,
  SCENARIO,
  STEPS,
  stepsOf,
  VERDICT_KO,
  type DemoModel,
  type Level3,
  type Outcome,
  type Step,
} from './model';
import { useDemo, type DemoError } from './useDemo';
import './demo.css';

// 「시연」 페이지(R3 11/04 — 목업 #/demo, shared/demo-page.js 11/04e B). 녹화 대본 장면 2~4 용, 1920×1080 한 화면(안쪽 스크롤 없이).
//   노출: 관리자 + /api/info.demo — 아니면 사이드바에 메뉴가 없고, 주소로 들어오면 안내만
//   왼쪽 = 시나리오 8개 + 예상 결과 + 실행(동시 1개 · 90초 — 실행 중이면 잠김 + 이유, 409 「이미 실행 중」)
//   가운데 = 실시간 5단계(설치 시작 → 커널 이벤트 → 규칙 판정 → 증거 수집 → 결과), 단계마다 도착 시각 · 직전 대비 +N ms
//   오른쪽 = 「왜」 카드: 무엇을 · 왜(규칙 · 판정 · 조건 · 원문 강조 — CodeWindow · 연쇄 진행) · 어떻게(증거 3종 · 증거 ms · 탐지→kill ms) + 건 보고서 · 정책 링크
//   필드가 없으면 그 칸만 「정보 없음」. 첫 위반이 와도 설치 시트로 옮기지 않는다

export function DemoPage() {
  const { isAdmin } = useAuth();
  const { info } = useStream();
  const allowed = isAdmin && info?.demo === true;
  const demo = useDemo(allowed);
  if (!info) return null; // /api/info 를 읽기 전 — 안내가 잠깐 비치지 않게
  if (!allowed)
    return (
      <div data-part="demo-denied" className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center text-text-3">
        <Play className="size-8" aria-hidden />
        <b className="text-base text-text-2">시연을 쓸 수 없습니다</b>
        <span className="text-sm">관리자 계정이고 서버에서 시연(DEMO_ENABLED)을 켰을 때만 씁니다.</span>
      </div>
    );
  const m = buildModel(demo.run, demo.session, demo.streamEvs);
  const steps = stepsOf(demo.run, m);
  return (
    <div data-part="demo-page" className="demo-page">
      <ScenarioCol {...demo} />
      <FlowCol run={demo.run} m={m} steps={steps} now={demo.now} loadError={demo.loadError} />
      <WhyCol run={demo.run} session={demo.session} evidence={demo.evidence} m={m} />
    </div>
  );
}

const None = ({ children = '정보 없음' }: { children?: ReactNode }) => <span className="why-none">{children}</span>;

const PILL: Record<Level3, string> = {
  killed: 'bg-red-600 text-white',
  held: 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-200',
  alert: 'bg-amber-100 text-amber-800',
};
function DecisionPill({ lv }: { lv: Level3 }) {
  return <span className={`badge inline-block rounded px-2 py-0.5 text-xs font-medium whitespace-nowrap ${PILL[lv]}`}>{VERDICT_KO[lv]}</span>;
}

// ── 왼쪽: 시나리오 · 실행 ──
function ScenarioCol({ scenario, setScenario, run, starting, now, start, error }: ReturnType<typeof useDemo>) {
  const isRunning = run?.status === 'running';
  const locked = isRunning || starting;
  const sec = isRunning && run ? elapsedSec(run, now) : 0;
  const note = isRunning
    ? `실행 중 — 동시 1개 · 최대 90초(${sec}초 경과). 끝나면 다시 시작할 수 있습니다.`
    : '한 번에 하나만 · 90초 안에 끝나지 않으면 멈춥니다. 컨테이너는 끝나면 지웁니다.';
  return (
    <div className="demo-col" data-col="scenarios">
      <Panel title="시나리오" sub={run?.simulated ? '모의 재생' : '설치 샌드박스'}>
        <div className="demo-col-body" data-fill="">
          <ul className="scn-list">
            {DEMO_SCENARIOS.map((k) => {
              const s = SCENARIO[k];
              const on = scenario === k;
              return (
                <li key={k}>
                  <button type="button" className={`scn-item ${on ? 'on' : ''}`} data-scenario={k} aria-pressed={on} disabled={locked} onClick={() => setScenario(k)}>
                    <span className="scn-top">
                      <b title={s.name}>{s.name}</b>
                      <span className={`scn-expect exp-${s.expect}`} data-part="expect" data-expect={s.expect}>
                        {EXPECT_LABEL[s.expect]}
                      </span>
                    </span>
                    <span className="scn-desc font-mono" title={s.line}>
                      {s.line}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
          <p className="scn-long" data-part="scenario-desc">
            {SCENARIO[scenario].long}
          </p>
          <div className="run-box">
            <button type="button" className="sg-btn sg-btn-primary run-btn" data-action="demo-run" disabled={locked} onClick={() => void start()}>
              {locked ? (
                <>
                  <RotateCw className="size-4 sg-spin" aria-hidden /> 실행 중…
                </>
              ) : (
                <>
                  <Play className="size-4" aria-hidden /> 시연 시작
                </>
              )}
            </button>
            <p className="run-note" data-part="run-note">
              {note}
            </p>
            {error && <ErrorBand error={error} />}
          </div>
        </div>
      </Panel>
    </div>
  );
}

function ErrorBand({ error }: { error: DemoError }) {
  return (
    <div className="demo-error" role="alert" data-part="demo-error" data-status={error.status ?? ''}>
      <TriangleAlert className="size-4 shrink-0" aria-hidden />
      <span className="min-w-0 flex-1">{error.text}</span>
    </div>
  );
}

// ── 가운데: 실시간 5단계 ──
const OUTCOME_STEP: Record<Outcome, (run: DemoRun) => string> = {
  running: () => '',
  isolated: (r) => `격리(kill)${r.exitCode != null ? ` — 종료 코드 ${r.exitCode}` : ''}`,
  passed: (r) => `통과${r.exitCode != null ? ` — 종료 코드 ${r.exitCode}` : ''}`,
  detected: () => '탐지(격리 안 함 — 시연용 dryRun)',
  warned: () => '경고 — 격리 정책에는 걸리지 않음',
  refused: () => '거부 — 차단 목록',
  timeout: () => '시간 초과 — 90초',
  failed: () => '실패',
};

function FlowCol({ run, m, steps, now, loadError }: { run: DemoRun | null; m: DemoModel; steps: Step[]; now: number; loadError: unknown }) {
  const sec = run ? elapsedSec(run, now) : 0;
  const oc = m.outcome;
  const seq = m.seq;
  const seqLine =
    seq && !seq.completed && oc === 'isolated'
      ? `기본 정책이 1단계에서 먼저 막음 · 연쇄 진행 ${seq.steps.filter((s) => s.matched).length}/${seq.steps.length}(dryRun 연쇄 규칙 ${seq.ruleId})`
      : null;
  const killMs = msBetween(m.tl?.detectedAt, m.tl?.killedAt);
  const ocText: Record<Outcome, string> = {
    running: `실행 중 · ${sec}초 경과`,
    isolated: `격리됨 — ${m.d?.ruleId || '규칙'}${killMs !== null && m.tl?.killedAt ? ` · 탐지→kill ${fmtNum(killMs)} ms` : ''}`,
    passed: '통과 — 위반 없음(대조군)',
    detected: '탐지(격리 안 함 — 시연용 dryRun)',
    warned: '경고 — 격리 정책에는 걸리지 않음',
    refused: '거부됨(차단 목록) — 차단 목록에 있어 설치 전 거부됨, 차단 해제 후 다시',
    timeout: '시간 초과 — 90초 안에 끝나지 않아 멈춤',
    failed: `실패${run?.exitCode != null ? ` — 종료 코드 ${run.exitCode}` : ''}`,
  };
  const body = (s: Step): ReactNode => {
    const fin = !!run && !m.running;
    switch (s.key) {
      case 'start':
        return run ? <span className="font-mono">{run.container}</span> : null;
      case 'events':
        return <EventsBox m={m} />;
      case 'match':
        if (m.d && m.lv)
          return (
            <>
              <code className="font-mono">{m.d.ruleId || '규칙 이름 없음'}</code> <DecisionPill lv={m.lv} />
            </>
          );
        if (m.d === null && fin) return <span className="tone-ok">위반 없음 — 설치 중 행동이 모든 정책을 통과</span>;
        return fin ? <None /> : <span className="text-text-3">판정 기다리는 중</span>;
      case 'evidence': {
        if (s.state === 'skip') return <span className="text-text-3">{m.d ? '건너뜀 — 격리하지 않아 모으지 않음' : '건너뜀 — 위반 없음'}</span>;
        const evMs = msBetween(m.tl?.evidenceStartedAt, m.tl?.evidenceDoneAt);
        if (m.tl?.evidenceDoneAt) return <span>로그 · 파일 변경 · 프로세스 — {evMs !== null ? `${fmtNum(evMs)} ms` : '시간 정보 없음'}</span>;
        return fin ? <None /> : null;
      }
      case 'outcome':
        return fin && oc && run ? <span className={`oc-${oc}`}>{OUTCOME_STEP[oc](run)}</span> : null;
    }
  };
  return (
    <div className="demo-col" data-col="flow">
      <Panel title="실시간 단계" sub={run ? `${SCENARIO[run.scenario]?.name ?? run.scenario} · ${sec}초` : '시나리오를 고르고 시작하세요'}>
        <div className="demo-col-body" data-fill="">
          {loadError ? <LoadError error={loadError} what="시연 상태" compact /> : null}
          <ol className="flow" data-part="demo-steps">
            {STEPS.map(([k, ko], i) => {
              const s = steps.find((x) => x.key === k)!;
              const b = body(s);
              return (
                <li key={k} data-step={k} data-state={s.state} data-at={s.at ?? ''} data-delta-ms={s.delta === null ? '' : String(s.delta)}>
                  <span className={`flow-dot ${s.state === 'active' ? 'sg-pulse-ring' : ''}`} aria-hidden>
                    {s.state === 'done' ? <Check className="size-4" /> : s.state === 'skip' ? <Minus className="size-4" /> : i + 1}
                  </span>
                  <div className="flow-main">
                    <div className="flow-head">
                      <b>{k === 'start' && run && !run.installId ? '컨테이너 시작' : ko}</b>
                      <span className="flow-time num font-mono" data-part="step-at">
                        {s.at ? ms3(s.at) : ''}
                      </span>
                      <span className="flow-delta num" data-part="step-delta">
                        {s.delta === null ? '' : `+${fmtNum(s.delta)} ms`}
                      </span>
                    </div>
                    {b ? <div className="flow-body">{b}</div> : null}
                  </div>
                </li>
              );
            })}
          </ol>
          {oc ? (
            <div className={`demo-outcome oc-${oc}`} data-part="demo-outcome" data-outcome={oc} role="status">
              <b>{ocText[oc]}</b>
              {seqLine ? (
                <span className="seq-line" data-part="seq-line">
                  {seqLine}
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
      </Panel>
    </div>
  );
}

function EventsBox({ m }: { m: DemoModel }) {
  const lines = m.evs.slice(-6);
  return (
    <div className="ev-box">
      <div className="ev-count" data-part="event-count">
        <b className="num">{fmtNum(m.count)}</b>건{m.running ? <i className="live-dot sg-blink" aria-hidden /> : null}
      </div>
      {lines.length ? (
        <ol className="ev-lines" data-part="event-lines">
          {lines.map((v, i) => (
            <li key={`${v.event.timestamp}-${i}`} className={v.matched ? 'hit' : ''}>
              <span className="num font-mono text-text-3">{ms3(v.event.timestamp)}</span>
              <KindBadge kind={v.event.kind} />
              <span className="ev-comm font-mono">{v.event.comm}</span>
              <span className="ev-raw font-mono" title={rawOf(v.event)}>
                {rawOf(v.event)}
              </span>
              {v.matched ? <VerdictBadge v={v} /> : <span />}
            </li>
          ))}
        </ol>
      ) : (
        <p className="text-[13px] text-text-3">{m.running ? '첫 이벤트를 기다리는 중…' : '이벤트 없음'}</p>
      )}
    </div>
  );
}

// ── 오른쪽: 「왜」 카드 ──
function WhyCol({ run, session, evidence, m }: { run: DemoRun | null; session: InstallSession | null; evidence: Evidence | null | undefined; m: DemoModel }) {
  const d = m.d;
  const ev = d?.event;
  const title = !run ? '왜' : m.outcome === 'passed' ? '왜 통과했나' : m.outcome === 'isolated' ? '왜 격리됐나' : '왜';
  const killed = m.outcome === 'isolated';
  const raw = rawOf(ev);
  const mark = ev ? markParts(raw, d?.reason) : null;

  let whyBody: ReactNode;
  if (!run) whyBody = <p className="why-muted">실행하면 판정을 만든 규칙과 이벤트가 여기에 나옵니다.</p>;
  else if (d === null) whyBody = <p className="why-pass">걸린 규칙 없음 — 설치하는 동안 정책에 걸린 행동이 없었습니다(정상 대조군).</p>;
  else if (d === undefined) whyBody = m.running ? <p className="why-muted">판정 기다리는 중…</p> : <None />;
  else
    whyBody = (
      <>
        <div className="why-rule-line">
          <code className="why-rule font-mono" data-part="why-rule">
            {d.ruleId}
          </code>
          {m.lv ? <DecisionPill lv={m.lv} /> : null}
        </div>
        {d.description ? <p className="why-desc">{d.description}</p> : null}
        <p className="why-cond" data-part="why-condition">
          {d.condition ? d.condition : <None>조건 — 정보 없음</None>}
        </p>
        {ev ? (
          // 11/04f 코드 창 — 원문은 줄바꿈(pre-wrap), 파일명 없음 · 종류는 실행이면 shell, 그 밖은 log · 걸린 부분 mark
          <CodeWindow body="div" wrap lang={ev.kind === 'exec' ? 'shell' : 'log'} bodyClassName="why-event" data-part="why-event">
            <KindBadge kind={ev.kind} />
            <code>
              {mark ? (
                <>
                  {mark[0]}
                  <mark>{mark[1]}</mark>
                  {mark[2]}
                </>
              ) : (
                raw
              )}
            </code>
            {ev.timestamp ? <span className="why-at num">{ms3(ev.timestamp)}</span> : null}
          </CodeWindow>
        ) : (
          <None />
        )}
        {d.reason ? <p className="why-reason font-mono">{d.reason}</p> : null}
      </>
    );

  const seq = m.seq;
  const seqEl = seq ? (
    <div className="why-seq" data-part="seq">
      <div className="why-seq-head">
        <b>연쇄 {seq.ruleId}</b>
        <span className="badge inline-block rounded bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-inset ring-red-200">
          {seq.dryRun ? 'dryRun' : seq.action}
        </span>
        <span className="text-text-3">
          {seq.windowSeconds}초 안 · 진행 {seq.steps.filter((x) => x.matched).length}/{seq.steps.length}
          {seq.completed ? ' · 완성' : ''}
          {seq.disabled ? ' · 꺼짐' : ''}
        </span>
      </div>
      <ol className="seq-steps" data-part="seq-steps">
        {seq.steps.map((st, i) => (
          <li key={i} data-kind={st.kind} data-matched={String(!!st.matched)} className={st.matched ? 'on' : ''}>
            <span className={`step-no step-${st.kind}`}>
              {i + 1} {KIND_SHORT[st.kind] ?? st.kind}
            </span>
            <span className="seq-main">
              <span title={st.condition}>{st.condition}</span>
              {st.event ? (
                <code className="font-mono" title={st.event.detail}>
                  {st.event.detail}
                </code>
              ) : (
                <span className="text-text-3">아직 — 이어지지 않음</span>
              )}
            </span>
            <span className="num text-text-3" data-part="seq-gap">
              {st.gapMs != null ? `+${(st.gapMs / 1000).toFixed(1)}초` : ''}
            </span>
          </li>
        ))}
      </ol>
    </div>
  ) : null;

  // 어떻게: 증거 · ms
  let evEl: ReactNode;
  if (!killed) evEl = <p className="why-muted">{m.running ? '격리되면 kill 직전에 모읍니다' : '격리하지 않아 증거를 모으지 않았습니다'}</p>;
  else if (evidence === undefined) evEl = <p className="why-muted">모으는 중…</p>;
  else if (!evidence) evEl = <None>증거 — 정보 없음</None>;
  else {
    const logs = String(evidence.logs || '')
      .split('\n')
      .filter(Boolean);
    const changes = evidence.changes ?? [];
    const procs = evidence.processes ?? [];
    evEl = (
      <ul className="ev-list">
        <li data-ev="logs">
          <b>로그</b>
          <span className="num">{logs.length}줄</span>
          {logs.length ? <code title={logs[logs.length - 1]}>{logs[logs.length - 1]}</code> : <span />}
        </li>
        <li data-ev="changes">
          <b>파일 변경</b>
          <span className="num">{changes.length}</span>
          {changes[0] ? <code title={changes[0].path}>{`${changes[0].kind} ${changes[0].path}`}</code> : <span />}
        </li>
        <li data-ev="processes">
          <b>프로세스</b>
          <span className="num">{procs.length}</span>
          {procs.length ? (
            <code title={procs[procs.length - 1].cmd}>{procs[procs.length - 1].cmd}</code>
          ) : (
            <span className="text-text-3">{evidence.partial ? '모으지 못함(예산 0.7초 초과)' : '없음'}</span>
          )}
        </li>
      </ul>
    );
  }
  const evMs = msBetween(m.tl?.evidenceStartedAt, m.tl?.evidenceDoneAt);
  const killMs = m.tl?.killedAt ? msBetween(m.tl.detectedAt, m.tl.killedAt) : null;
  const caseId = session?.caseId;
  const pkg = session ? `${session.manager} ${(session.packages ?? []).join(' ')}` : null;

  return (
    <div className="demo-col" data-col="why">
      <Panel title={title} sub={run ? (run.simulated ? '모의 재생 결과' : '실제 실행 결과') : undefined}>
        <div className="demo-col-body" data-fill="" data-part="why">
          <section className="why-sec" data-why="what">
            <h3>무엇을</h3>
            <dl className="why-dl">
              <dt>패키지</dt>
              <dd>{pkg ? <span className="font-mono">{pkg}</span> : <None />}</dd>
              <dt>컨테이너</dt>
              <dd>
                {run ? (
                  <span className="font-mono">
                    {run.container}
                    {session?.containerId ? <span className="text-text-3"> · {shortId(session.containerId)}</span> : null}
                  </span>
                ) : (
                  <None />
                )}
              </dd>
              <dt>프로세스</dt>
              <dd>{ev ? <span className="font-mono">{`${ev.comm || '?'} · pid ${ev.pid ?? '?'}`}</span> : d === null ? '—' : <None />}</dd>
            </dl>
          </section>
          <section className="why-sec" data-why="why">
            <h3>왜</h3>
            {whyBody}
            {seqEl}
          </section>
          <section className="why-sec" data-why="how">
            <h3>어떻게</h3>
            <div data-part="why-evidence">{evEl}</div>
            <div className="why-ms">
              <span data-part="evidence-ms">증거 수집 {evMs !== null ? <b className="num">{fmtNum(evMs)} ms</b> : killed ? <None /> : '—'}</span>
              <span data-part="kill-ms">탐지 → kill {killMs !== null ? <b className="num">{fmtNum(killMs)} ms</b> : killed ? <None /> : '—'}</span>
            </div>
          </section>
          {run && (caseId || run.installId || d?.ruleId) ? (
            <div className="why-links">
              {caseId || run.installId ? (
                <Link
                  to={caseId ? `/report?case=${encodeURIComponent(caseId)}` : `/report?install=${encodeURIComponent(run.installId)}`}
                  className="sg-btn sg-btn-secondary why-link"
                  data-action="open-report"
                >
                  <FileText className="size-4" aria-hidden /> 건 보고서 열기
                </Link>
              ) : null}
              {d?.ruleId ? (
                <Link to={`/policies?id=${encodeURIComponent(d.ruleId)}`} className="sg-btn sg-btn-secondary why-link" data-action="open-policy">
                  <ScrollText className="size-4" aria-hidden /> 정책에서 이 규칙 보기
                </Link>
              ) : null}
            </div>
          ) : null}
        </div>
      </Panel>
    </div>
  );
}
