// 평가 화면 차트 공통 — 색 · 눈금 · 숫자 모양(11/04, 목업 mock/shared/eval.js 와 같은 규칙)

// 색 이름 → [SVG 칠, 범례 칸 배경]. 빨강(danger)은 악성(위험)에만
export const COLOR = {
  mal: ['fill-danger', 'bg-danger'],
  sus: ['fill-warn', 'bg-warn'],
  vul: ['fill-info', 'bg-info'],
  clean: ['fill-ok', 'bg-ok'],
  muted: ['fill-text-3', 'bg-text-3'], // 오류 · 대조 · 정상 세트 · 판정 단계
  attack: ['fill-accent', 'bg-accent'],
  evidence: ['fill-info', 'bg-info'],
  kill: ['fill-accent', 'bg-accent'],
} as const;
export type ColorKey = keyof typeof COLOR;
export type TipLine = [ColorKey | null, string];

// 축 눈금: 1 · 2 · 5 × 10^k 간격으로 4칸 안팎
const niceStep = (x: number) => {
  if (!(x > 0)) return 1;
  const e = Math.pow(10, Math.floor(Math.log10(x)));
  const f = x / e;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * e;
};
export function niceTicks(maxV: number) {
  const m = Math.max(1, maxV);
  const st = niceStep(m / 4);
  const top = Math.max(st, Math.ceil(m / st) * st);
  const out: number[] = [];
  for (let v = 0; v <= top + 1e-9; v += st) out.push(Math.round(v * 1e6) / 1e6);
  return out;
}
export const RATE_TICKS = [0, 0.25, 0.5, 0.75, 1];

// 축 이름이 칸(px)을 넘으면 끝을 말줄임 — 글자 폭 어림(한글 11px · 그 밖 6.6px, 고정폭 6.8px)
export function fitText(t: string, px: number, mono?: boolean) {
  const w = (ch: string) => (mono ? 6.8 : /[ㄱ-힣]/.test(ch) ? 11 : 6.6);
  const chars = [...t];
  if (chars.reduce((a, ch) => a + w(ch), 0) <= px) return t;
  let n = 0;
  let out = '';
  for (const ch of chars) {
    if (n + w(ch) > px - 8) break;
    n += w(ch);
    out += ch;
  }
  return `${out}…`;
}
