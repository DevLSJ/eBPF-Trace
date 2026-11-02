import { useCallback, useEffect, useState } from 'react';

// 테마(10/30 계약 §7): <html data-theme="light|dark">, 저장 localStorage supplyguard.theme = light | dark | system(기본 → prefers-color-scheme).
// 첫 그리기 전 적용은 index.html 머리 스크립트가 같은 키 · 같은 규칙으로 한다. 전환은 계정 메뉴 「테마」

export const THEME_KEY = 'supplyguard.theme';
export type ThemePref = 'system' | 'light' | 'dark';
export type Theme = 'light' | 'dark';
export const THEME_PREFS: ThemePref[] = ['system', 'light', 'dark'];
export const THEME_LABEL: Record<ThemePref, string> = { system: '시스템', light: '라이트', dark: '다크' };
const DARK_MQ = '(prefers-color-scheme: dark)';

export function loadThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}
const systemDark = () => typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia(DARK_MQ).matches;
export const resolveTheme = (p: ThemePref): Theme => (p === 'system' ? (systemDark() ? 'dark' : 'light') : p);
export function applyTheme(p: ThemePref) {
  document.documentElement.dataset.theme = resolveTheme(p);
}
export function saveThemePref(p: ThemePref) {
  try {
    localStorage.setItem(THEME_KEY, p);
  } catch {
    /* 저장 차단 — 이번 화면에서만 */
  }
  applyTheme(p);
}

export function useTheme(): [ThemePref, (p: ThemePref) => void] {
  const [pref, setPref] = useState<ThemePref>(loadThemePref);
  useEffect(() => {
    applyTheme(pref);
    if (pref !== 'system' || !window.matchMedia) return;
    const m = window.matchMedia(DARK_MQ);
    const on = () => applyTheme('system');
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, [pref]);
  const set = useCallback((p: ThemePref) => {
    saveThemePref(p);
    setPref(p);
  }, []);
  return [pref, set];
}
