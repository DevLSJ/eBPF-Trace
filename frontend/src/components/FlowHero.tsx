import { useEffect, useState } from 'react';
import { reducedMotion } from '../lib/motion';
import './flow-hero.css';

// 흐름 그림(11/06 — 「흐름 보이고 화려하게」): 노드가 차례로 켜지고 선을 따라 점이 흐르며, 아래 요점 한 줄이 단계마다 바뀐다.
// active 를 넘기면(실제 진행) 그 단계에 멈추고, 안 넘기면 stepMs 간격으로 자동 재생한다(마지막 뒤 처음으로).
// prefers-reduced-motion 이면 자동 재생 · 흐르는 점 없이 모든 노드를 켠 정지 그림.
// 11/09 시연(선택 속성 — 연동 화면 사용법은 그대로):
//   vertical = 세로 배치(좁은 열) · states = 노드별 상태를 직접 줌(실제 진행 — 자동 재생 안 함, 움직임 줄이기여도 그 상태 그대로)
//   FlowNode.skip = 건너뛴 단계(자동 재생 중 지나가면 「건너뜀」 모양)
export type FlowState = 'done' | 'on' | 'off' | 'skip';
export interface FlowNode {
  id: string;
  title: string;
  sub: string;
  tone?: 'accent' | 'ok' | 'warn' | 'danger';
  point: string; // 이 단계의 요점(개조식)
  skip?: boolean;
}

// states 가 있으면 요점 · data-step 은 켜진(on) 첫 노드, 없으면 꺼지지 않은 마지막 노드
function curOf(states: FlowState[]) {
  const on = states.indexOf('on');
  if (on >= 0) return on;
  for (let i = states.length - 1; i >= 0; i--) if (states[i] !== 'off') return i;
  return 0;
}

export function FlowHero({
  nodes,
  active,
  states,
  stepMs = 1600,
  part = 'flow',
  compact = false,
  vertical = false,
}: {
  nodes: FlowNode[];
  active?: number;
  states?: FlowState[];
  stepMs?: number;
  part?: string;
  compact?: boolean;
  vertical?: boolean;
}) {
  const still = reducedMotion();
  const fixed = active !== undefined || states !== undefined;
  const [auto, setAuto] = useState(0);
  useEffect(() => {
    if (fixed || still) return;
    const t = window.setInterval(() => setAuto((i) => (i + 1) % nodes.length), stepMs);
    return () => window.clearInterval(t);
  }, [fixed, still, stepMs, nodes.length]);
  const cur = states ? curOf(states) : still ? nodes.length - 1 : (active ?? auto);
  const playing = !fixed && !still;
  const stateOf = (i: number): FlowState => {
    if (states) return states[i] ?? 'off';
    const s: FlowState = i < cur ? 'done' : i === cur ? 'on' : 'off';
    return nodes[i]?.skip && s !== 'off' ? 'skip' : s;
  };
  return (
    <div
      className={`flow-hero ${compact ? 'compact' : ''} ${vertical ? 'vertical' : ''} ${still ? 'still' : ''}`}
      data-part={part}
      data-step={cur}
      data-playing={String(playing)}
    >
      <ol className="flow-track">
        {nodes.map((n, i) => {
          const state = stateOf(i);
          const tone = n.tone ?? 'accent';
          const lit = i < cur && stateOf(i + 1) !== 'off';
          return (
            <li key={n.id} className={`flow-node tone-${tone} ${state}`} data-node={n.id} data-state={state} data-tone={tone} style={{ ['--i' as string]: i }}>
              <span className="flow-dot" aria-hidden>
                {i + 1}
              </span>
              <b className="flow-title">{n.title}</b>
              <span className="flow-sub" title={n.sub}>
                {n.sub}
              </span>
              {i < nodes.length - 1 && (
                <span className={`flow-link ${lit ? 'lit' : ''}`} aria-hidden>
                  {!still && i === cur - 1 && <i key={`p${cur}`} className="flow-particle" />}
                  {!still && <i className="flow-dash" />}
                </span>
              )}
            </li>
          );
        })}
      </ol>
      <p className="flow-point" key={cur} data-part={`${part}-point`} aria-live="polite">
        <span className="flow-point-step">
          {cur + 1} / {nodes.length}
        </span>
        {nodes[cur]?.point}
      </p>
    </div>
  );
}
