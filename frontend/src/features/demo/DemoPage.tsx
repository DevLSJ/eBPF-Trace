import { Check, FileText, Minus, Play, RotateCw, ScrollText, TriangleAlert } from 'lucide-react';
import { useCallback, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ActionButton } from '../../components/ActionButton';
import { CodeWindow } from '../../components/CodeWindow';
import { FlowHero } from '../../components/FlowHero';
import { KindBadge } from '../../components/KindBadge';
import { NoPermission } from '../../components/list/ListStates';
import { LoadError, Panel } from '../../components/Panel';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useAuth } from '../../hooks/auth-context';
import { useStream } from '../../hooks/stream-context';
import { fmtNum, shortId } from '../../lib/format';
import { reducedMotion } from '../../lib/motion';
import { screenCopy } from '../../lib/screenCopy';
import { KIND_SHORT } from '../../lib/policyEasy';
import type { DemoRun, DemoScenario, Evidence, InstallSession } from '../../lib/types';
import { idleNodes, liveFlow, type FlowMode } from './flow';
import { GROUPS, useFolds } from './groups';
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
//   왼쪽 = 한눈에 3줄(11/09 — 무엇을 · 잡는 규칙 · 예상 결과) + 시나리오 8개를 묶음 3개로(접기 · 펼치기, 고른 시나리오 묶음은 늘 펼침) + 예상 결과 + 실행(동시 1개 · 90초 — 실행 중이면 잠김 + 이유, 409 「이미 실행 중」)
//   가운데 = 실시간 5단계(설치 시작 → 커널 이벤트 → 규칙 판정 → 증거 수집 → 결과), 단계마다 도착 시각 · 직전 대비 +N ms
//   오른쪽 = 탭 2개(11/09): 「판정 근거」(기본) = 「왜」 카드: 무엇을 · 왜(규칙 · 판정 · 조건 · 원문 강조 — CodeWindow · 연쇄 진행) · 어떻게(증거 3종 · 증거 ms · 탐지→kill ms) + 건 보고서 · 정책 링크
//          「흐름 그림」 = FlowHero 세로 — 대기 중 예상 경로 자동 재생, 실행 중 실제 단계, 끝나면 결과 톤에서 멈춤(flow.ts)
//   필드가 없으면 그 칸만 「정보 없음」. 첫 위반이 와도 설치 시트로 옮기지 않는다

type Tab = 'why' | 'flow';
// 고른 탭은 화면을 옮겨도 남는다(돌아오면 그대로 — useDemo 의 고른 시나리오와 같은 방식)
let lastTab: Tab = 'why';

export function DemoPage() {
  const { isAdmin } = useAuth();
  const { info } = useStream();
  const allowed = isAdmin && info?.demo === true;
  const demo = useDemo(allowed);
  const [tab, setTabState] = useState<Tab>(lastTab);
  const setTab = useCallback((t: Tab) => {
    lastTab = t;
    setTabState(t);
  }, []);
  // 끝난 실행을 본 뒤 시나리오를 다시 고르면 흐름 그림은 대기(자동 재생)로 돌아간다 — 그 실행 id 를 기억
  const [idleAfter, setIdleAfter] = useState<string | null>(null);
  const { setScenario } = demo;
  const runId = demo.run?.id ?? null;
  const pick = useCallback(
    (k: DemoScenario) => {
      setScenario(k);
      setIdleAfter(runId);
    },
    [setScenario, runId],
  );
  if (!info) return null; // /api/info 를 읽기 전 — 안내가 잠깐 비치지 않게
  // 11/09 G04 · G38: 권한 없음 양식(아이콘 없음) + 쉬운 말 — 서버 설정 이름은 툴팁에만. 조회자는 예전처럼 「관리자」 안내
  if (!allowed)
    return (
      <div data-part="demo-denied" data-reason={isAdmin ? 'off' : 'viewer'} className="h-full">
        <NoPermission
          text="시연을 쓸 수 없습니다."
          hint={
            isAdmin ? (
              <span title="서버 설정 DEMO_ENABLED=true 일 때 켜집니다">서버에서 시연이 꺼져 있습니다. 서버 설정에서 시연을 켠 뒤 다시 여세요.</span>
            ) : (
              '시연은 관리자 계정으로만 씁니다.'
            )
          }
        />
      </div>
    );
  const m = buildModel(demo.run, demo.session, demo.streamEvs);
  const steps = stepsOf(demo.run, m);
  const mode: FlowMode = !demo.run ? 'idle' : m.running ? 'live' : demo.run.id === idleAfter ? 'idle' : 'done';
  return (
    <div className="demo-wrap">
      <p data-part="screen-copy" data-screen="demo" className="m-0 shrink-0 truncate text-[length:var(--fs-sm)] text-text-3">
        {screenCopy('demo')}
      </p>
    <div data-part="demo-page" className="demo-page">
      <ScenarioCol {...demo} setScenario={pick} />
      <FlowCol run={demo.run} m={m} steps={steps} now={demo.now} loadError={demo.loadError} />
      <WhyCol
        run={demo.run}
        session={demo.session}
        evidence={demo.evidence}
        m={m}
        tab={tab}
        onTab={setTab}
        flow={<FlowTab mode={mode} scenario={demo.scenario} run={demo.run} m={m} steps={steps} onWhy={() => setTab('why')} />}
      />
    </div>
    </div>
  );
}

// 한눈에 3줄(11/09): 무엇을 · 잡는 규칙 · 예상 결과 — 규칙 이름(kebab-case)은 코드 글꼴, 전체 설명은 title
const RULE_ID = /([a-z0-9]+(?:-[a-z0-9]+)+)/g;
function ruleText(s: string): ReactNode[] {
  return s.split(RULE_ID).map((part, i) =>
    i % 2 ? (
      <code key={i} className="font-mono">
        {part}
      </code>
    ) : (
      part
    ),
  );
}
function BriefBox({ k }: { k: DemoScenario }) {
  const s = SCENARIO[k];
  return (
    <div className="scn-brief" data-part="scenario-desc" title={s.long}>
      <dl data-part="demo-brief">
        <div data-brief="what">
          <dt>무엇을</dt>
          <dd>{s.brief.what}</dd>
        </div>
        <div data-brief="rule">
          <dt>잡는 규칙</dt>
          <dd>{ruleText(s.brief.rule)}</dd>
        </div>
        <div data-brief="result">
          <dt>예상 결과</dt>
          <dd>
            <span className={`scn-expect exp-${s.expect}`} data-part="brief-expect" data-expect={s.expect}>
              {s.expect === 'passed' ? '통과' : '격리'}
            </span>{' '}
            {s.brief.result}
          </dd>
        </div>
      </dl>
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
    ? `실행 중입니다(동시 1개 · 최대 90초, ${sec}초 경과). 끝나면 다시 시작할 수 있습니다.`
    : '한 번에 하나만 · 90초 안에 끝나지 않으면 멈춥니다. 컨테이너는 끝나면 지웁니다.';
  const { folded, toggle } = useFolds();
  return (
    <div className="demo-col" data-col="scenarios">
      <Panel title="시나리오" sub={run?.simulated ? '모의 재생' : '설치 샌드박스'}>
        <div className="demo-col-body" data-fill="">
          <BriefBox k={scenario} />
          {/* 묶음 3개(11/09) — 접기는 보기만 바꾼다(실행 중에도 됨). 고른 시나리오가 든 묶음은 늘 펼침 · 접기 단추는 「선택 중」 */}
          <div className="scn-groups" data-part="scn-groups">
            {GROUPS.map((g) => {
              const pinned = g.keys.includes(scenario);
              const open = pinned || !folded.includes(g.id);
              const listId = `scn-group-${g.id}`;
              return (
                <div key={g.id} className="scn-group" role="group" aria-label={g.name} data-group={g.id} data-open={String(open)}>
                  <button
                    type="button"
                    className="scn-group-head"
                    data-action="fold-group"
                    aria-expanded={open}
                    aria-controls={listId}
                    aria-disabled={pinned || undefined}
                    title={pinned ? '고른 시나리오가 든 묶음은 접히지 않음' : undefined}
                    onClick={() => !pinned && toggle(g.id)}
                  >
                    <b className="scn-group-name">{g.name}</b>
                    <span className="scn-group-count num">{g.keys.length}</span>
                    <span className="scn-group-peek">{open ? '' : g.keys.map((k) => SCENARIO[k].name).join(' · ')}</span>
                    <span className="scn-group-act">{pinned ? '선택 중' : open ? '접기' : '펼치기'}</span>
                  </button>
                  <ul id={listId} className="scn-list" data-part="group-list" hidden={!open}>
                    {g.keys.map((k) => {
                      const s = SCENARIO[k];
                      const on = scenario === k;
                      return (
                        <li key={k}>
                          <ActionButton className={`scn-item ${on ? 'on' : ''}`} data-scenario={k} aria-pressed={on} reason={locked && '실행 중에는 시나리오를 바꿀 수 없습니다'} onClick={() => setScenario(k)}>
                            <span className="scn-top">
                              <b title={s.name}>{s.name}</b>
                              <span className={`scn-expect exp-${s.expect}`} data-part="expect" data-expect={s.expect}>
                                {EXPECT_LABEL[s.expect]}
                              </span>
                            </span>
                            <span className="scn-desc font-mono" title={s.line}>
                              {s.line}
                            </span>
                          </ActionButton>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              );
            })}
          </div>
          <div className="run-box">
            <ActionButton className="sg-btn sg-btn-primary run-btn" data-action="demo-run" reason={locked && '시연이 끝나면 다시 시작할 수 있습니다'} onClick={() => void start()}>
              {locked ? (
                <>
                  <RotateCw className="size-4 sg-spin" aria-hidden /> 실행 중…
                </>
              ) : (
                <>
                  <Play className="size-4" aria-hidden /> 시연 시작
                </>
              )}
            </ActionButton>
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
  isolated: (r) => `[격리] 컨테이너 kill${r.exitCode != null ? `(종료 코드 ${r.exitCode})` : ''}`,
  passed: (r) => `[통과] 설치 완료${r.exitCode != null ? `(종료 코드 ${r.exitCode})` : ''}`,
  detected: () => '[탐지] 격리 안 함(시연용 dryRun)',
  warned: () => '[경고] 격리 정책에는 걸리지 않음',
  refused: () => '[거부] 차단 목록',
  timeout: () => '[시간 초과] 90초',
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
    isolated: `[격리] ${m.d?.ruleId || '규칙'} 위반${killMs !== null && m.tl?.killedAt ? ` · 탐지→kill ${fmtNum(killMs)} ms` : ''}`,
    passed: '[통과] 위반 없음(대조군)',
    detected: '[탐지] 시연용 dryRun 이라 격리 안 함',
    warned: '[경고] 격리 정책에는 걸리지 않음',
    refused: '[거부] 차단 목록에 있어 설치 전 거부됨, 차단 해제 후 다시',
    timeout: '[시간 초과] 90초 안에 끝나지 않아 멈춤',
    failed: run?.exitCode != null ? `[실패] 종료 코드 ${run.exitCode}` : '실패',
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
        if (m.d === null && fin) return <span className="tone-ok">[통과] 설치 중 행동에 위반 사항 없음</span>;
        return fin ? <None /> : <span className="text-text-3">판정 기다리는 중</span>;
      case 'evidence': {
        if (s.state === 'skip') return <span className="text-text-3">{m.d ? '[건너뜀] 격리하지 않아 모으지 않음' : '[건너뜀] 위반 없음'}</span>;
        const evMs = msBetween(m.tl?.evidenceStartedAt, m.tl?.evidenceDoneAt);
        if (m.tl?.evidenceDoneAt) return <span>로그 · 파일 변경 · 프로세스 보존됨({evMs !== null ? `${fmtNum(evMs)} ms` : '시간 정보 없음'})</span>;
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

// ── 오른쪽: 탭(11/09) — 「판정 근거」(기본, 아래 「왜」 카드) · 「흐름 그림」 ──
const TABS: [Tab, string][] = [
  ['why', '판정 근거'],
  ['flow', '흐름 그림'],
];
function WhyTabs({ tab, onTab }: { tab: Tab; onTab: (t: Tab) => void }) {
  const refs = useRef<Partial<Record<Tab, HTMLButtonElement | null>>>({});
  // ← → · Home · End 로 옮기고 그 탭에 포커스(탭 목록 기본 키)
  const onKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    const i = TABS.findIndex(([k]) => k === tab);
    const to = e.key === 'ArrowRight' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' ? (i + TABS.length - 1) % TABS.length : e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    const k = TABS[to][0];
    onTab(k);
    refs.current[k]?.focus();
  };
  return (
    <div className="demo-tabs" role="tablist" aria-label="상세 보기" data-part="why-tabs">
      {TABS.map(([k, label]) => (
        <button
          key={k}
          ref={(el) => {
            refs.current[k] = el;
          }}
          type="button"
          role="tab"
          id={`demo-tab-${k}`}
          aria-selected={tab === k}
          aria-controls={k === 'why' || tab === k ? `demo-panel-${k}` : undefined /* 흐름 그림 패널은 그 탭일 때만 있다 */}
          tabIndex={tab === k ? 0 : -1}
          data-tab={k}
          className={`demo-tab ${tab === k ? 'on' : ''}`}
          onClick={() => onTab(k)}
          onKeyDown={onKey}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

// 「흐름 그림」 탭 — 대기 중 예상 경로 자동 재생 · 실행 중 실제 단계 · 끝나면 결과 톤에서 멈춤(flow.ts)
const MODE_CHIP: Record<FlowMode, string> = { idle: '대기', live: '실행 중', done: '결과' };
function FlowTab({ mode, scenario, run, m, steps, onWhy }: { mode: FlowMode; scenario: DemoScenario; run: DemoRun | null; m: DemoModel; steps: Step[]; onWhy: () => void }) {
  const live = mode !== 'idle' && run ? liveFlow(run, m, steps) : null;
  const k = live && run ? run.scenario : scenario;
  const name = SCENARIO[k]?.name ?? k;
  const oc = live ? m.outcome : null;
  const line =
    mode === 'idle'
      ? `${name} · 예상 흐름${reducedMotion() ? '' : ' 자동 재생'}`
      : mode === 'live'
        ? `${name} · 실제 진행 단계 표시`
        : `${name} · 결과에서 멈춤, 시나리오 선택 시 대기로 전환`;
  return (
    <div
      className="demo-col-body demo-flow-body"
      data-fill=""
      role="tabpanel"
      id="demo-panel-flow"
      aria-labelledby="demo-tab-flow"
      data-part="demo-flow-tab"
      data-mode={mode}
      data-outcome={oc ?? ''}
    >
      <p className="flow-mode" data-part="flow-mode">
        <span className={`flow-mode-chip mode-${mode} ${oc ? `oc-${oc}` : ''}`}>{MODE_CHIP[mode]}</span>
        <span className="flow-mode-text">{line}</span>
      </p>
      {live ? <FlowHero nodes={live.nodes} states={live.states} part="demo-flow" vertical /> : <FlowHero nodes={idleNodes(scenario)} part="demo-flow" vertical />}
      {mode === 'done' ? (
        <div className="flow-done">
          <button type="button" className="sg-btn sg-btn-sm sg-btn-secondary" data-action="show-why" onClick={onWhy}>
            판정 근거 보기
          </button>
        </div>
      ) : null}
    </div>
  );
}

function WhyCol({
  run,
  session,
  evidence,
  m,
  tab,
  onTab,
  flow,
}: {
  run: DemoRun | null;
  session: InstallSession | null;
  evidence: Evidence | null | undefined;
  m: DemoModel;
  tab: Tab;
  onTab: (t: Tab) => void;
  flow: ReactNode;
}) {
  const d = m.d;
  const ev = d?.event;
  const title = !run ? '왜' : m.outcome === 'passed' ? '왜 통과했나' : m.outcome === 'isolated' ? '왜 격리됐나' : '왜';
  const killed = m.outcome === 'isolated';
  const raw = rawOf(ev);
  const mark = ev ? markParts(raw, d?.reason) : null;

  let whyBody: ReactNode;
  if (!run) whyBody = <p className="why-muted">실행하면 판정을 만든 규칙과 이벤트가 여기에 나옵니다.</p>;
  else if (d === null) whyBody = <p className="why-pass">걸린 규칙 없음. 설치하는 동안 정책에 걸린 행동이 없었습니다(정상 대조군).</p>;
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
          {d.condition ? d.condition : <None>조건 정보 없음</None>}
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
                <span className="text-text-3">아직 이어지지 않음</span>
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
  else if (!evidence) evEl = <None>증거 정보 없음</None>;
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
      <Panel title={title} sub={run ? (run.simulated ? '모의 재생 결과' : '실제 실행 결과') : undefined} actions={<WhyTabs tab={tab} onTab={onTab} />}>
        <div className="demo-col-body" data-fill="" data-part="why" role="tabpanel" id="demo-panel-why" aria-labelledby="demo-tab-why" hidden={tab !== 'why'}>
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
              <dd>{ev ? <span className="font-mono">{`${ev.comm || '?'} · pid ${ev.pid ?? '?'}`}</span> : d === null ? '' : <None />}</dd>
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
              <span data-part="evidence-ms">증거 수집 {evMs !== null ? <b className="num">{fmtNum(evMs)} ms</b> : killed ? <None /> : ''}</span>
              <span data-part="kill-ms">탐지 → kill {killMs !== null ? <b className="num">{fmtNum(killMs)} ms</b> : killed ? <None /> : ''}</span>
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
        {tab === 'flow' ? flow : null}
      </Panel>
    </div>
  );
}
