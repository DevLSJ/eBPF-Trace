// 모션 토큰(index.css --t-fast 120 · --t-base 200 · --t-slow 320 · --ease)을 JS 에서 읽는다 — 11/04f 애니메이션 원칙(R1 11/04).
// CSS 만으로 못 하는 효과(KPI 숫자 카운트업 — 천 단위 쉼표 글자를 바꾼다)만 JS 로 하고, 길이는 여기서 토큰을 읽는다.
export const reducedMotion = () => typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// '--t-slow' → 320(ms). 값이 없거나 읽을 수 없으면 fallback
export function motionMs(name: '--t-fast' | '--t-base' | '--t-slow', fallback: number): number {
  if (typeof document === 'undefined') return fallback;
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const n = parseFloat(raw);
  if (!Number.isFinite(n)) return fallback;
  return /ms$/.test(raw) ? n : /s$/.test(raw) ? n * 1000 : n;
}
// 카운트업 · KPI 링 길이 = --t-slow × 2(640ms)
export const countUpMs = () => motionMs('--t-slow', 320) * 2;
