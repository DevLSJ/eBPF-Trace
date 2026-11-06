import { useEffect, useState } from 'react';
import { reducedMotion } from '../lib/motion';
import './flow-hero.css';

// 흐름 그림(11/06 — 「흐름 보이고 화려하게」): 노드가 차례로 켜지고 선을 따라 점이 흐르며, 아래 요점 한 줄이 단계마다 바뀐다.
// active 를 넘기면(실제 진행) 그 단계에 멈추고, 안 넘기면 stepMs 간격으로 자동 재생한다(마지막 뒤 처음으로).
// prefers-reduced-motion 이면 자동 재생 · 흐르는 점 없이 모든 노드를 켠 정지 그림.
export interface FlowNode {
  id: string;
  title: string;
  sub: string;
  tone?: 'accent' | 'ok' | 'warn' | 'danger';
  point: string; // 이 단계의 요점(개조식)
}

export function FlowHero({ nodes, active, stepMs = 1600, part = 'flow', compact = false }: { nodes: FlowNode[]; active?: number; stepMs?: number; part?: string; compact?: boolean }) {
  const still = reducedMotion();
  const [auto, setAuto] = useState(0);
  useEffect(() => {
    if (active !== undefined || still) return;
    const t = window.setInterval(() => setAuto((i) => (i + 1) % nodes.length), stepMs);
    return () => window.clearInterval(t);
  }, [active, still, stepMs, nodes.length]);
  const cur = still ? nodes.length - 1 : (active ?? auto);
  const playing = active === undefined && !still;
  return (
    <div className={`flow-hero ${compact ? 'compact' : ''} ${still ? 'still' : ''}`} data-part={part} data-step={cur} data-playing={String(playing)}>
      <ol className="flow-track">
        {nodes.map((n, i) => {
          const state = i < cur ? 'done' : i === cur ? 'on' : 'off';
          return (
            <li key={n.id} className={`flow-node tone-${n.tone ?? 'accent'} ${state}`} data-node={n.id} data-state={state} style={{ ['--i' as string]: i }}>
              <span className="flow-dot" aria-hidden>
                {i + 1}
              </span>
              <b className="flow-title">{n.title}</b>
              <span className="flow-sub">{n.sub}</span>
              {i < nodes.length - 1 && (
                <span className={`flow-link ${i < cur ? 'lit' : ''}`} aria-hidden>
                  {!still && i === cur - 1 && <i key={`p${cur}`} className="flow-particle" />}
                  {!still && <i className="flow-dash" />}
                </span>
              )}
            </li>
          );
        })}
      </ol>
      <p className="flow-point" key={cur} data-part={`${part}-point`} aria-live="polite">
        <span className="flow-point-step">{cur + 1} / {nodes.length}</span>
        {nodes[cur]?.point}
      </p>
    </div>
  );
}
