// R1 11/04 — 아직 화면에 붙지 않은 공통 부품(KPI 카드 · SVG 차트)을 e2e 에서 띄워 보는 작은 무대.
// 앱을 연 뒤 page.evaluate(() => import('/e2e/r1-harness.tsx')) 로 불러온다(Vite 개발 서버가 변환해 준다 — src 에 경로 · 화면을 더하지 않는다).
// window.__r1.mount(kind, props) → { update(props), unmount() }. 무대는 화면 왼쪽 위 고정 상자(폭 · 높이는 props.box 로)
import { createElement, type ComponentType } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { KpiCard } from '../src/components/KpiCard';
import { Donut, LineChart, StackBars } from '../src/components/charts';
import { CodeWindow } from '../src/components/CodeWindow';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const KINDS: Record<string, ComponentType<any>> = { kpi: KpiCard, line: LineChart, bars: StackBars, donut: Donut, codewin: CodeWindow };

type Props = Record<string, unknown> & { box?: { w: number; h: number } };
function mount(kind: string, props: Props) {
  const host = document.createElement('div');
  const { box, ...rest } = props;
  Object.assign(host.style, { position: 'fixed', left: '8px', top: '8px', zIndex: '9999', width: `${box?.w ?? 480}px`, height: `${box?.h ?? 220}px`, background: 'var(--bg)' });
  host.dataset.r1Stage = kind;
  document.body.append(host);
  const root = createRoot(host);
  const draw = (p: Record<string, unknown>) => root.render(createElement(MemoryRouter, null, createElement(KINDS[kind], p)));
  draw(rest);
  return {
    update: (p: Props) => {
      const { box: _b, ...r } = p;
      void _b;
      draw(r);
    },
    unmount: () => {
      root.unmount();
      host.remove();
    },
  };
}

(window as unknown as { __r1: unknown }).__r1 = { mount };
