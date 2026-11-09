import type { FlowNode, FlowState } from '../../components/FlowHero';
import { fmtNum } from '../../lib/format';
import type { DemoRun, DemoScenario } from '../../lib/types';
import { msBetween, SCENARIO, type DemoModel, type Level3, type Outcome, type Step, type StepState } from './model';

// 「흐름 그림」 탭(11/09 — 사용자 11/06 결정): 설치 → 커널 이벤트 → 규칙 판정 → 증거 수집 → 격리/통과
//   idle = 고른 시나리오의 예상 경로를 자동 재생(FlowHero 자동 재생)
//   live = 실행 중 — 실시간 단계(stepsOf)의 상태를 그대로 켬(자동 재생 멈춤)
//   done = 끝난 실행 — 결과 노드를 결과 톤(격리 = 위험 · 통과 = 정상)으로 켠 채 멈춤. 시나리오를 다시 고르면 idle
// 요점 문구는 개조식 명사형 종결(11/06 화면 문구 규칙)
export type FlowMode = 'idle' | 'live' | 'done';

const STATE: Record<StepState, FlowState> = { done: 'done', active: 'on', todo: 'off', skip: 'skip' };
const LV_SHORT: Record<Level3, string> = { killed: '격리', held: '격리 대상(dryRun)', alert: '경고' };

export function idleNodes(k: DemoScenario): FlowNode[] {
  const s = SCENARIO[k];
  const pass = s.expect === 'passed';
  return [
    { id: 'start', title: '설치 시작', sub: '감시 컨테이너 sg-install-demo-*', point: '감시 컨테이너에서 패키지 설치 시작됨' },
    { id: 'events', title: '커널 이벤트', sub: s.flow.event, point: `커널(eBPF)에서 ${s.flow.event} 포착됨` },
    { id: 'match', title: '규칙 판정', sub: s.flow.rule, point: pass ? '[통과] 모든 정책에서 위반 없음 확인됨' : `${s.flow.rule} 에 걸려 격리 판정됨` },
    pass
      ? { id: 'evidence', title: '증거 수집', sub: '건너뜀(격리 없음)', skip: true, point: '격리 없어 증거 수집 건너뜀' }
      : { id: 'evidence', title: '증거 수집', sub: '로그 · 파일 변경 · 프로세스', point: 'kill 직전 로그 · 파일 변경 · 프로세스 0.7초 안에 보존됨' },
    pass
      ? { id: 'outcome', title: '통과', sub: '위반 없이 설치 완료', tone: 'ok', point: '[통과] 위반 없이 설치 완료됨' }
      : { id: 'outcome', title: '격리', sub: '설치 끝나기 전 kill', tone: 'danger', point: '설치 끝나기 전 컨테이너 격리(kill)됨' },
  ];
}

type Tone = NonNullable<FlowNode['tone']>;
const OUTCOME: Record<Outcome, { title: string; tone: Tone; point: string }> = {
  running: { title: '격리 / 통과', tone: 'accent', point: '결과 기다리는 중' },
  isolated: { title: '격리', tone: 'danger', point: '설치 끝나기 전 컨테이너 격리(kill)됨' },
  passed: { title: '통과', tone: 'ok', point: '[통과] 위반 없이 설치 완료됨' },
  detected: { title: '탐지(dryRun)', tone: 'warn', point: '[탐지] 시연용 dryRun 이라 격리 안 함' },
  warned: { title: '경고', tone: 'warn', point: '[경고] 격리 정책에는 걸리지 않아 경고만 기록됨' },
  refused: { title: '거부', tone: 'warn', point: '차단 목록에 있어 설치 전 거부됨' },
  timeout: { title: '시간 초과', tone: 'warn', point: '90초 안에 끝나지 않아 멈춤' },
  failed: { title: '실패', tone: 'danger', point: '[실패] 시연 실행 실패, 종료 코드 확인 필요' },
};

// 실행 중 · 끝난 실행 — 노드 문구는 실제 값(컨테이너 · 이벤트 수 · 규칙 · 증거 ms · 탐지→kill ms), 상태는 실시간 단계 그대로
export function liveFlow(run: DemoRun, m: DemoModel, steps: Step[]): { nodes: FlowNode[]; states: FlowState[] } {
  const fin = !m.running;
  const st = (k: Step['key']) => steps.find((x) => x.key === k)?.state ?? 'todo';
  const n = fmtNum(m.count);

  const events: FlowNode = m.count
    ? { id: 'events', title: '커널 이벤트', sub: `${n}건`, point: m.running ? `커널 이벤트 ${n}건 수집 중` : `커널 이벤트 ${n}건 수집됨` }
    : { id: 'events', title: '커널 이벤트', sub: m.running ? '첫 이벤트 기다리는 중' : '이벤트 없음', point: m.running ? '첫 커널 이벤트 기다리는 중' : '커널 이벤트 없음' };

  let match: FlowNode;
  if (m.d && m.lv) match = { id: 'match', title: '규칙 판정', sub: `${m.d.ruleId || '규칙 이름 없음'} · ${LV_SHORT[m.lv]}`, point: `${m.d.ruleId || '규칙'} 에 걸려 ${LV_SHORT[m.lv]} 판정됨` };
  else if (m.d === null && fin) match = { id: 'match', title: '규칙 판정', sub: '위반 없음', point: '[통과] 모든 정책에서 위반 없음 확인됨' };
  else match = { id: 'match', title: '규칙 판정', sub: fin ? '정보 없음' : '판정 기다리는 중', point: fin ? '판정 정보 없음' : '규칙 판정 기다리는 중' };

  const evMs = msBetween(m.tl?.evidenceStartedAt, m.tl?.evidenceDoneAt);
  let evidence: FlowNode;
  if (m.tl?.evidenceDoneAt)
    evidence = {
      id: 'evidence',
      title: '증거 수집',
      sub: evMs !== null ? `${fmtNum(evMs)} ms` : '시간 정보 없음',
      point: `kill 직전 로그 · 파일 변경 · 프로세스 보존됨${evMs !== null ? `(${fmtNum(evMs)} ms)` : ''}`,
    };
  else if (st('evidence') === 'skip')
    evidence = { id: 'evidence', title: '증거 수집', sub: '건너뜀', point: m.d ? '격리하지 않아 증거 수집 건너뜀' : '위반 없어 증거 수집 건너뜀' };
  else if (fin) evidence = { id: 'evidence', title: '증거 수집', sub: '정보 없음', point: '증거 수집 정보 없음' };
  else if (st('evidence') === 'active') evidence = { id: 'evidence', title: '증거 수집', sub: '모으는 중', point: 'kill 직전 증거 수집 중' };
  else evidence = { id: 'evidence', title: '증거 수집', sub: '격리 시 kill 직전 수집', point: '격리 판정 시 kill 직전 증거 수집' };

  // 실행 중이라도 격리 판정이 나왔으면 결과는 격리로 보인다
  const oc: Outcome = m.outcome ?? 'running';
  const o = oc === 'running' && m.lv === 'killed' ? OUTCOME.isolated : OUTCOME[oc];
  const killMs = m.tl?.killedAt ? msBetween(m.tl.detectedAt, m.tl.killedAt) : null;
  const ocSub: Record<Outcome, string> = {
    running: m.lv === 'killed' ? '컨테이너 kill 중' : '결과 기다리는 중',
    isolated: killMs !== null ? `탐지→kill ${fmtNum(killMs)} ms` : '컨테이너 kill',
    passed: '위반 없이 설치 완료',
    detected: '격리 안 함(시연용 dryRun)',
    warned: '격리 정책에 걸리지 않음',
    refused: '설치 전 거부(차단 목록)',
    timeout: '90초 초과로 멈춤',
    failed: run.exitCode != null ? `종료 코드 ${run.exitCode}` : '실패',
  };

  const nodes: FlowNode[] = [
    { id: 'start', title: '설치 시작', sub: run.container || '컨테이너 시작', point: run.container ? `감시 컨테이너 ${run.container} 에서 설치 시작됨` : '감시 컨테이너 시작됨' },
    events,
    match,
    evidence,
    { id: 'outcome', title: o.title, sub: ocSub[oc], tone: o.tone, point: o.point },
  ];
  const states = steps.map((s) => STATE[s.state]);
  // 끝나면 결과 노드를 켠(on) 채 멈춘다 — 결과 톤 테두리 · 그림자
  if (fin) states[states.length - 1] = 'on';
  return { nodes, states };
}
