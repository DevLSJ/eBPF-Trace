import { useCallback, useSyncExternalStore } from 'react';

// 테마(10/30 계약 §7 · 11/09 G01): <html data-theme="light|dark">.
// 처음은 PC 설정(prefers-color-scheme)을 따르고, 상단 해/달 단추(ThemeToggle)를 누르면 반대 테마를 localStorage supplyguard.theme(light | dark)에 기억한다.
// 옛 값 system · 저장 차단 = PC 설정. 첫 그리기 전 적용은 index.html 머리 스크립트가 같은 키 · 같은 규칙으로 한다.
// 전환: 누르거나 PC 설정이 바뀌면 --dur-slow(450ms) 동안 색만 바뀐다(html.sg-theme-anim — index.css). 동작 줄이기면 즉시

export const THEME_KEY = 'supplyguard.theme';
export type Theme = 'light' | 'dark';
const DARK_MQ = '(prefers-color-scheme: dark)';
const REDUCE_MQ = '(prefers-reduced-motion: reduce)';
const ANIM = 'sg-theme-anim';
const CHANGED = 'sg-theme-change';

const media = (q: string) => (typeof window !== 'undefined' && window.matchMedia ? window.matchMedia(q) : null);

export function savedTheme(): Theme | null {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === 'light' || v === 'dark' ? v : null;
  } catch {
    return null;
  }
}
export const systemTheme = (): Theme => (media(DARK_MQ)?.matches ? 'dark' : 'light');
export const currentTheme = (): Theme => (document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');

// 전환 시간 = --dur-slow(토큰 한 곳). 규칙은 전환이 끝난 뒤 뗀다
const slowMs = () => {
  const v = getComputedStyle(document.documentElement).getPropertyValue('--dur-slow').trim();
  const n = parseFloat(v);
  return Number.isFinite(n) ? (v.endsWith('ms') ? n : n * 1000) : 450;
};
let animTimer = 0;
function paint(t: Theme) {
  const root = document.documentElement;
  if (root.dataset.theme === t) return;
  if (!media(REDUCE_MQ)?.matches) {
    // 같은 그리기에서 규칙과 테마를 함께 바꾼다 — 바뀐 뒤 스타일의 전환 규칙으로 옛 색에서 새 색으로 넘어간다
    root.classList.add(ANIM);
    window.clearTimeout(animTimer);
    animTimer = window.setTimeout(() => root.classList.remove(ANIM), slowMs() + 50);
  }
  root.dataset.theme = t;
  window.dispatchEvent(new Event(CHANGED));
}

export function setTheme(t: Theme) {
  try {
    localStorage.setItem(THEME_KEY, t);
  } catch {
    /* 저장 차단 — 이번 화면에서만 */
  }
  paint(t);
}

// 단추가 여럿(셸 머리 · 로그인 화면)이어도 html 의 data-theme 하나를 본다. PC 설정 변경 · 다른 탭의 선택도 따라간다
function subscribe(onChange: () => void) {
  const sys = media(DARK_MQ);
  const follow = () => {
    if (!savedTheme()) paint(systemTheme());
  };
  const otherTab = (e: StorageEvent) => {
    if (e.key === THEME_KEY) paint(savedTheme() ?? systemTheme());
  };
  sys?.addEventListener('change', follow);
  window.addEventListener('storage', otherTab);
  window.addEventListener(CHANGED, onChange);
  return () => {
    sys?.removeEventListener('change', follow);
    window.removeEventListener('storage', otherTab);
    window.removeEventListener(CHANGED, onChange);
  };
}

export function useTheme(): [Theme, () => void] {
  const theme = useSyncExternalStore(subscribe, currentTheme, (): Theme => 'light');
  const toggle = useCallback(() => setTheme(currentTheme() === 'dark' ? 'light' : 'dark'), []);
  return [theme, toggle];
}
