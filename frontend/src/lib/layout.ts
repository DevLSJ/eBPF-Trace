// 화면 배치 순서 저장(11/04d 목업 shared/sortable.js 와 같은 키 · 모양, R1 11/04) — 이 브라우저(localStorage)에만.
//   supplyguard.layout = {v:1, sidebar:{install|runtime|records:[installs …]}, dashboardKpi:[collected …], evaluationKpi:[static-detection …]}
//   읽을 때 모르는 id · 중복 · 문자열 아닌 값은 버리고, 저장에 없는 새 항목은 기본 순서의 바로 앞 항목 뒤에 끼운다(앞 항목이 없으면 맨 앞).
//   JSON 오류 · v 다름 · 모양 틀림 → 기본 순서(콘솔 오류 없음), 다음 이동 때 새 값으로 덮어쓴다
export const LAYOUT_KEY = 'supplyguard.layout';
export const LAYOUT_EVENT = 'sg:layout';
// scope: 'dashboardKpi' | 'evaluationKpi' | 'sidebar.<묶음 id>'
export type LayoutScope = 'dashboardKpi' | 'evaluationKpi' | `sidebar.${string}`;

type Obj = Record<string, unknown>;
const isObj = (x: unknown): x is Obj => !!x && typeof x === 'object' && !Array.isArray(x);
const strs = (a: unknown) => (Array.isArray(a) ? a.filter((x): x is string => typeof x === 'string') : null);

function readAll(): Obj | null {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(LAYOUT_KEY);
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const o = JSON.parse(raw) as unknown;
    return isObj(o) && o.v === 1 ? o : null;
  } catch {
    return null;
  }
}
export function readLayout(scope: LayoutScope): string[] | null {
  const o = readAll();
  if (!o) return null;
  const [a, b] = scope.split('.');
  return b ? (isObj(o[a]) ? strs((o[a] as Obj)[b]) : null) : strs(o[a]);
}
export function writeLayout(scope: LayoutScope, list: string[]) {
  const o = readAll() ?? {};
  const out: Obj = { ...o, v: 1 };
  const [a, b] = scope.split('.');
  if (b) out[a] = { ...(isObj(o[a]) ? o[a] : {}), [b]: list.slice() };
  else out[a] = list.slice();
  try {
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(out));
  } catch {
    /* 저장 차단 — 이번 화면에서만 */
  }
}
// 저장 순서 + 기본 순서 → 그릴 순서
export function mergeLayout(saved: string[] | null, defaults: string[]): string[] {
  if (!saved) return defaults.slice();
  const out: string[] = [];
  for (const id of saved) if (defaults.includes(id) && !out.includes(id)) out.push(id);
  defaults.forEach((id, i) => {
    if (out.includes(id)) return;
    let at = 0;
    for (let j = i - 1; j >= 0; j--) {
      const k = out.indexOf(defaults[j]);
      if (k >= 0) {
        at = k + 1;
        break;
      }
    }
    out.splice(at, 0, id);
  });
  return out;
}
// 「화면 배치 기본 순서로」(설정) — 저장값을 지우고 열린 화면(사이드바 등)이 바로 기본 순서로 다시 그리게 알린다
export function resetLayout() {
  try {
    localStorage.removeItem(LAYOUT_KEY);
  } catch {
    /* 저장 차단 */
  }
  document.dispatchEvent(new CustomEvent(LAYOUT_EVENT));
}

// 받침 따라 을/를 · 은/는 — 끝 글자가 숫자면 읽는 소리(0 영 · 1 일 · 3 삼 · 6 육 · 7 칠 · 8 팔 = 받침)
export function josa(word: string, pair: [string, string]) {
  const ch = String(word).trim().slice(-1);
  const c = ch.charCodeAt(0);
  let has: boolean | null = null;
  if (c >= 0xac00 && c <= 0xd7a3) has = (c - 0xac00) % 28 !== 0;
  else if (/[0-9]/.test(ch)) has = '013678'.includes(ch);
  return has == null ? `${pair[0]}(${pair[1]})` : has ? pair[0] : pair[1];
}
