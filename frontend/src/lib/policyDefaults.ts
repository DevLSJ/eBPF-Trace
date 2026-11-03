import type { PolicyDefaults, Rule } from './types';

// 새 기본 규칙(10/20 F, 목업 screens.js mergeDefault · diffText) — 업데이트로 기본 정책 파일에 생긴 규칙 · 값은
// 기존 서버에 저절로 들어가지 않는다. 바뀐 규칙은 지금 규칙을 덮어쓰지 않고 「기본에만 있는 값」만 더한 사본으로 저장 전 확인을 거친다.

const USER_KEYS = new Set(['description', 'disabled', 'dryRun']);

type Obj = Record<string, unknown>;
type Step = { kind?: unknown } & Obj;
// 연쇄 규칙 단계(11/04): 순서 · 개수가 뜻이라 단계를 붙이지 않는다 — 단계 수 · kind 가 같을 때만 단계마다 비교 · 병합
const sameShape = (a: unknown, b: unknown): a is Step[] =>
  Array.isArray(a) && Array.isArray(b) && a.length === b.length && (b as Step[]).every((x, i) => (a as Step[])[i]?.kind === x.kind);

// 목록은 합치고(지금 값 뒤에 기본에만 있는 항목), 지금 비어 있는 옵션만 기본 값으로 채운다
export function mergeDefault(cur: Rule, def: Rule): Rule {
  return mergeObj(structuredClone(cur) as unknown as Obj, def as unknown as Obj) as unknown as Rule;
}
function mergeObj(r: Obj, def: Obj): Obj {
  for (const [k, v] of Object.entries(def)) {
    if (k === 'steps') {
      // 모양이 다르면 지금 단계 그대로
      if (sameShape(r.steps, v)) r.steps = (r.steps as Step[]).map((x, i) => mergeObj(x, (v as Step[])[i]));
      continue;
    }
    if (Array.isArray(v)) {
      const have = (r[k] as unknown[] | undefined) ?? [];
      const add = v.filter((x) => !have.includes(x));
      if (add.length) r[k] = [...have, ...add];
    } else if (r[k] === undefined || r[k] === '') r[k] = v;
  }
  return r;
}

// 바뀐 규칙 한 줄 설명 — 더해질 값만(지금 값과 다른 단일 값은 「지금 값 유지」).
// 연쇄 규칙 단계(11/04)는 mergeDefault 와 같은 조건으로 단계마다(「steps[2].denyPaths +…」), 모양이 다르면 「steps: 지금 단계 유지」
export function diffText(cur: Rule, def: Rule): string {
  const out = diffParts(cur as unknown as Obj, def as unknown as Obj, '');
  return out.length ? out.join(' · ') : '지금 규칙에만 있는 값이 있습니다(그대로 둡니다)';
}
function diffParts(a: Obj, b: Obj, pre: string): string[] {
  const out: string[] = [];
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (USER_KEYS.has(k) || JSON.stringify(a[k]) === JSON.stringify(b[k])) continue;
    const bv = b[k];
    if (k === 'steps') {
      if (sameShape(a.steps, bv)) (bv as Step[]).forEach((x, i) => out.push(...diffParts((a.steps as Step[])[i], x, `${pre}steps[${i}].`)));
      else out.push(`${pre}steps: 지금 단계 유지 (기본은 ${((bv as Step[] | undefined) ?? []).map((x) => String(x.kind)).join(' → ')})`);
      continue;
    }
    if (Array.isArray(bv)) {
      const add = bv.filter((x) => !((a[k] as unknown[] | undefined) ?? []).includes(x));
      if (add.length) out.push(`${pre}${k} +${add.join(', ')}`);
    } else if (a[k] === undefined || a[k] === '') out.push(`${pre}${k}: (없음) → ${String(bv)}`);
    else if (bv !== undefined) out.push(`${pre}${k}: ${String(a[k])} (지금 값 유지, 기본은 ${String(bv)})`);
  }
  return out;
}

export interface DefaultItem {
  kind: 'missing' | 'differs';
  id: string;
  rule: Rule; // 기본 규칙
  current?: Rule;
}

export function defaultItems(d: PolicyDefaults | undefined): DefaultItem[] {
  if (!d) return [];
  return [
    ...(d.missing ?? []).map((r) => ({ kind: 'missing' as const, id: r.id, rule: r })),
    ...(d.differs ?? []).map((x) => ({ kind: 'differs' as const, id: x.id, rule: x.default, current: x.current })),
  ];
}

// 「이번엔 숨기기」 — 이 브라우저(localStorage). 기본 규칙 내용이 바뀌면 서명이 달라져 다시 보인다
const HIDE_KEY = 'supplyguard.defaults.hidden';
export const hideSig = (r: Rule) => JSON.stringify(r);
export function hiddenDefaults(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(HIDE_KEY) || '{}') as Record<string, string>;
  } catch {
    return {};
  }
}
export function hideDefault(x: DefaultItem) {
  const m = hiddenDefaults();
  m[x.id] = hideSig(x.rule);
  try {
    localStorage.setItem(HIDE_KEY, JSON.stringify(m));
  } catch {
    /* 저장 차단 — 이번 화면에서만 숨긴다 */
  }
}
