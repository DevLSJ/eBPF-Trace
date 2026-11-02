// SupplyGuard 목업 — 테마(라이트 · 다크 · 시스템) [10/30 계약 §7]. 가장 먼저 읽힌다(UI 보다 앞) — 첫 그리기 전에 <html data-theme> 를 정한다.
//   저장: localStorage supplyguard.theme = light | dark | system(기본 → prefers-color-scheme). 시뮬 확인용 ?theme=dark|light|system 은 이번 로드에만(저장하지 않음).
//   전환은 계정 메뉴 「테마」(auth.js) → window.SG_THEME.set(). 차트(SVG) 색도 토큰에서 읽으므로(UI.cssVar) 전환 뒤 다시 그린다(UI.emit).
(function () {
  'use strict';
  const KEY = 'supplyguard.theme';
  const VALID = ['light', 'dark', 'system'];
  const mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : { matches: false, addEventListener() {} };
  const param = new URLSearchParams(location.search).get('theme');
  let override = VALID.includes(param) ? param : '';
  const stored = () => { try { const v = localStorage.getItem(KEY); return VALID.includes(v) ? v : 'system'; } catch { return 'system'; } };
  const get = () => override || stored();
  const resolved = (pref) => ((pref || get()) === 'system' ? (mq.matches ? 'dark' : 'light') : pref || get());
  function apply() {
    const r = resolved();
    document.documentElement.dataset.theme = r;
    document.documentElement.dataset.themePref = get();
    if (window.UI && typeof UI.emit === 'function') { try { UI.emit(); } catch { /* 셸 전 */ } }
    document.dispatchEvent(new CustomEvent('sg:theme', { detail: { theme: r, pref: get() } }));
  }
  function set(pref) {
    if (!VALID.includes(pref)) return;
    override = '';
    try { localStorage.setItem(KEY, pref); } catch { /* 저장 차단 */ }
    apply();
  }
  mq.addEventListener('change', () => { if (get() === 'system') apply(); });
  apply();
  window.SG_THEME = { get, set, resolved: () => resolved(), KEY, LABEL: { system: '시스템', light: '라이트', dark: '다크' } };
})();
