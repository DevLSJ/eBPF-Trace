// SupplyGuard 목업 — 공통 부품 2차(10/20 W10). 참고 제품 remastered2 의 패턴을 이 목업 방식(UI.h)으로 다시 만든 것.
//   modal(포커스 트랩 · Esc · 미저장 보호) · confirmDialog(영향 표시 + 사유 + 되돌리기) · 목록 상태(스켈레톤 · 오류+다시 시도 · 아이콘 빈 상태)
//   · 적용된 필터 칩 + 모두 해제 · 행 키보드 열기 · CSV 내려받기 · 4칸 키 입력(붙여넣기 분배) · QR 자리(목업 그림) · 역할 확인(can)
// React 로 옮길 때: components/ 의 Modal · ConfirmDialog · ListState · FilterChips · KeyBoxes 로 1:1
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, state } = U;

  // ── 역할: 조회자는 쓰기 버튼을 아예 그리지 않는다(보이는데 못 누르는 버튼 금지) [10/20 A] ──
  const can = () => !state.auth || !state.auth.user || state.auth.user.role === 'admin';

  // ── 모달: <dialog> + 포커스 트랩 · Esc · 연 곳으로 포커스 복귀 · 미저장 보호(guard() 가 true 면 닫기 전에 묻는다) ──
  const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  function modal({ title, body, foot, kind, guard, onClose, wide }) {
    const opener = document.activeElement;
    const warn = h('div', { class: 'modal-warn', hidden: true, role: 'alert' });
    const d = h('dialog', { class: `dialog modal ${wide ? 'wide' : ''}`, 'data-part': kind || 'modal', 'aria-label': typeof title === 'string' ? title : '대화상자' });
    const box = h('div', { class: 'dialog-body' }, h('div', { class: 'modal-head' }, h('h3', null, title), h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-label': '닫기', onclick: () => tryClose() }, '✕')), body, warn, foot ? h('div', { class: 'dialog-foot' }, foot) : null);
    d.append(box);
    let closed = false;
    function close(result) {
      if (closed) return; closed = true;
      try { d.close(); } catch { /* 이미 닫힘 */ }
      d.remove();
      if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
      if (onClose) onClose(result);
    }
    function tryClose(result) {
      if (guard && guard() && warn.hidden) {
        warn.hidden = false;
        replace(warn, h('span', { class: 'grow' }, '저장하지 않은 내용이 있습니다. 닫으면 사라집니다.'),
          h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => { warn.hidden = true; } }, '계속 쓰기'),
          h('button', { type: 'button', class: 'btn btn-danger-ghost btn-xs', 'data-action': 'discard-close', onclick: () => close(result) }, '버리고 닫기'));
        return;
      }
      close(result);
    }
    d.addEventListener('cancel', (e) => { e.preventDefault(); tryClose(null); });
    d.addEventListener('keydown', (e) => {
      if (e.key !== 'Tab') return;
      const els = [...d.querySelectorAll(FOCUSABLE)].filter((x) => x.offsetParent !== null || x === document.activeElement);
      if (!els.length) return;
      const first = els[0], last = els[els.length - 1];
      if (e.shiftKey && (document.activeElement === first || !d.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (document.activeElement === last || !d.contains(document.activeElement))) { e.preventDefault(); first.focus(); }
    });
    document.body.append(d);
    d.showModal();
    const auto = d.querySelector('[autofocus]') || d.querySelector('textarea, input, select') || d.querySelector('[data-confirm="ok"]');
    if (auto) auto.focus();
    return { el: d, close, tryClose };
  }

  // ── 확인 대화상자 [10/20 B]: 대상 · 함께 일어나는 일 · 사유(선택, 감사 로그에 남음) · 되돌리기 안내 → Promise<{ reason } | null> ──
  // effects: 문자열 · {kind, text} 배열 또는 그 Promise(서버 미리보기 — 판정은 POST /api/cases/{id}/preview 의 effects [10/20 결정 7]). tone: danger | primary
  function confirmDialog({ title, target, effects, undo, okLabel, tone, reason }) {
    return new Promise((resolve) => {
      const list = h('ul', { class: 'confirm-effects', 'data-part': 'confirm-effects' }, h('li', { class: 'muted' }, '계산 중…'));
      const fill = (items) => replace(list, (items && items.length ? items : ['따로 바뀌는 것 없음']).map((t) => (t && typeof t === 'object' ? h('li', { 'data-kind': t.kind }, t.text) : h('li', null, t))));
      Promise.resolve(effects).then(fill, (e) => fill([`영향을 계산하지 못했습니다 — ${e.message}`]));
      const ta = reason === false ? null : h('textarea', { class: 'ctl reason', name: 'reason', rows: 2, maxlength: 500, placeholder: '예: 이름이 requests 와 한 글자 다른 타이포스쿼팅', 'aria-label': '사유 (선택)' });
      let done = false;
      const finish = (v) => { if (done) return; done = true; resolve(v); };
      const ok = h('button', { type: 'button', class: `btn ${tone === 'primary' ? 'btn-primary' : 'btn-danger'}`, 'data-confirm': 'ok', onclick: () => { finish({ reason: ta ? ta.value.trim() : '' }); m.close(true); } }, okLabel || '확인');
      const cancel = h('button', { type: 'button', class: 'btn btn-ghost', 'data-confirm': 'cancel', onclick: () => m.tryClose(null) }, '취소');
      const m = modal({ title, kind: 'confirm', guard: () => !!(ta && ta.value.trim()) && !done, onClose: () => finish(null),
        body: h('div', { class: 'confirm' },
          h('dl', { class: 'dl tight' }, h('dt', null, '대상'), h('dd', { class: 'mono', 'data-part': 'confirm-target' }, target)),
          h('div', null, h('div', { class: 'small strong' }, '함께 일어나는 일'), list),
          ta ? h('label', { class: 'field' }, h('span', null, h('b', null, '사유'), h('small', { class: 'muted' }, ' 선택 · 감사 로그에 남습니다')), ta) : null,
          undo ? h('p', { class: 'small muted confirm-undo', 'data-part': 'confirm-undo' }, '되돌리기: ', undo) : null),
        foot: [cancel, ok] });
      if (ta) ta.focus();
    });
  }

  // ── 목록 상태 [10/20 D] ──
  function skeleton(rows) {
    return h('div', { class: 'skeleton', 'data-part': 'skeleton', 'aria-busy': 'true', 'aria-label': '불러오는 중' },
      Array.from({ length: rows || 6 }, (_, i) => h('div', { class: 'sk-row' }, h('i', { style: `width:${18 + (i % 3) * 6}%` }), h('i', { style: `width:${30 + ((i * 7) % 4) * 8}%` }), h('i', { style: 'width:12%' }))));
  }
  // 오류 + 「다시 시도」 [10/20 D] · 자동 재시도 [10/20 결정 4] — React ListError(components/list/ListStates.tsx)와 같은 모양 [10/21 React 맞춤]
  //   opts.what: 무엇을 못 불렀는지(제목 「{what}을(를) 불러오지 못했습니다」). 「다시 시도」를 누르면 오류 칸은 그대로 두고 버튼만 잠그고 돌린다(스켈레톤 없음) —
  //   onRetry 는 조용한 다시 부르기여야 한다(성공하면 목록, 실패하면 화면이 새 오류 칸을 그린다). 이 칸이 화면에 남아 있으면 RETRY_MS(기본 30초)마다 onRetry 를 한 번 부른다.
  //   백엔드 미지원(라우트 없음)은 제목 「백엔드 미지원」 · 회색 아이콘 · 버튼 없음 · 자동 재시도 없음(다시 불러도 같다)
  function errorState(err, onRetry, opts) {
    const o = opts || {};
    const what = o.what || '목록';
    const unsupported = !!(err && err.unsupported);
    const retry = unsupported ? null : o.quiet || onRetry;
    const auto = !!retry && o.auto !== false;
    const sec = Math.round(U.RETRY_MS / 1000);
    const btn = retry ? h('button', { type: 'button', class: 'btn btn-outline btn-xs', 'data-action': 'retry' }, h('span', { class: 'retry-icon', 'aria-hidden': true }, '⟳'), ' 다시 시도') : null;
    if (btn) btn.addEventListener('click', () => { if (btn.disabled) return; btn.disabled = true; btn.classList.add('retrying'); btn.setAttribute('aria-busy', 'true'); retry(); });
    const el = h('div', { class: 'list-state', 'data-part': 'error', role: 'alert', 'data-unsupported': unsupported ? 'true' : null },
      h('span', { class: `empty-icon ${unsupported ? '' : 'tone-danger'}`, 'aria-hidden': true }, unsupported ? '⊘' : '⚠'),
      h('b', null, unsupported ? '백엔드 미지원' : `${what}을(를) 불러오지 못했습니다`),
      h('span', { class: 'small muted' }, unsupported ? String(err.message || '').replace(/^백엔드 미지원 — /, '') : (err && err.message) || String(err)),
      btn, auto ? h('span', { class: 'small muted', 'data-part': 'auto-retry' }, `${sec}초마다 한 번씩 저절로 다시 불러 봅니다`) : null);
    if (auto) setTimeout(() => { if (el.isConnected) retry(); }, U.RETRY_MS);
    return el;
  }
  // 데이터가 있는데 다시 부르기만 실패 — 목록은 그대로 두고 위에 작은 오류 띠(React LoadError compact). 감사 로그 · 변경 이력 [10/21 React 맞춤]
  function loadErrorNote(err, what) {
    const unsupported = !!(err && err.unsupported);
    return h('div', { class: `load-note ${unsupported ? 'off' : 'danger'}`, role: 'note', 'data-part': 'load-error', 'data-unsupported': unsupported ? 'true' : null },
      h('span', { 'aria-hidden': true }, unsupported ? '⊘' : '⚠'),
      h('span', null, unsupported ? [h('b', null, '백엔드 미지원'), ` — ${what} API가 아직 백엔드에 없습니다.`] : `${what} 불러오기 실패: ${(err && err.message) || err}`));
  }
  function emptyState({ icon, title, hint, actions }) {
    return h('div', { class: 'empty list-state', 'data-part': 'empty' },
      h('span', { class: 'empty-icon', 'aria-hidden': true }, icon || '○'), h('b', null, title), hint ? h('span', { class: 'small muted' }, hint) : null, actions ? h('div', { class: 'row-actions' }, actions) : null);
  }
  // 적용된 필터 칩: items = [{ key, label, clear }] → 칩마다 ✕, 끝에 「모두 해제」. 비면 빈 div
  function filterChips(items, clearAll) {
    const list = (items || []).filter(Boolean);
    return h('div', { class: 'filter-chips', 'data-part': 'filter-chips', hidden: !list.length },
      list.length ? [h('span', { class: 'small muted' }, '적용된 필터'),
        list.map((x) => h('span', { class: 'fchip', 'data-chip': x.key }, x.label, h('button', { type: 'button', class: 'fchip-x', 'aria-label': `${x.label} 필터 해제`, onclick: x.clear }, '✕'))),
        h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': 'clear-filters', onclick: clearAll }, '모두 해제')] : null);
  }
  // 행 키보드 열기: Tab 으로 닿고 Enter · Space 로 연다
  function rowKeys(el, open) {
    el.tabIndex = 0;
    el.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === el) { e.preventDefault(); open(); } });
    return el;
  }
  // CSV 내려받기 — 엑셀이 한글을 읽도록 BOM, 값은 따옴표로 감싼다
  function downloadCSV(filename, rows) {
    const esc = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const text = '﻿' + rows.map((r) => r.map(esc).join(',')).join('\n') + '\n';
    const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
    const a = h('a', { href: url, download: filename, hidden: true });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  // 4칸 키 입력 — 칸마다 len 자, 숫자만. 붙여넣으면 그 칸부터 나눠 채운다 · 다 차면 다음 칸 · 빈 칸에서 지우면 앞 칸
  function keyBoxes({ groups, len, label, onEnter }) {
    const n = groups || 4, w = len || 4;
    const inputs = Array.from({ length: n }, (_, i) => h('input', { class: 'ctl mono key-box', inputmode: 'numeric', maxlength: w, autocomplete: 'off', 'aria-label': `${label || '키'} ${i + 1}번째 칸`, placeholder: 'X'.repeat(w) }));
    const fillFrom = (start, digits) => { let k = 0; for (let i = start; i < n && k < digits.length; i++) { inputs[i].value = digits.slice(k, k + w); k += w; } (inputs[Math.min(n - 1, start + Math.ceil(digits.length / w) - 1)] || inputs[n - 1]).focus(); };
    inputs.forEach((el, i) => {
      el.addEventListener('paste', (e) => { const t = (e.clipboardData || window.clipboardData).getData('text') || ''; const d = t.replace(/\D/g, ''); if (d.length > w) { e.preventDefault(); fillFrom(i, d); } });
      el.addEventListener('input', () => { const d = el.value.replace(/\D/g, ''); if (d.length > w) { fillFrom(i, d); return; } el.value = d; if (d.length === w && inputs[i + 1]) inputs[i + 1].focus(); });
      el.addEventListener('keydown', (e) => { if (e.key === 'Backspace' && !el.value && inputs[i - 1]) inputs[i - 1].focus(); if (e.key === 'Enter' && onEnter) onEnter(); });
    });
    const root = h('div', { class: 'key-boxes', 'data-part': 'key-boxes' }, inputs.map((el, i) => [el, i < n - 1 ? h('span', { class: 'muted', 'aria-hidden': true }, '-') : null]));
    root.value = () => inputs.map((x) => x.value).join('-');
    root.focusFirst = () => inputs[0].focus();
    return root;
  }
  // QR 자리 — 목업은 실제 QR 을 만들지 않는다(외부 라이브러리 금지). 찾기 무늬 3개 + 문자열 해시로 칸을 채운 그림. React 는 qrcode 라이브러리로
  function fakeQR(text, size) {
    const N = 29, px = (size || 168) / N;
    let seed = 0; for (const ch of String(text)) seed = (Math.imul(seed ^ ch.charCodeAt(0), 2654435761) >>> 0);
    const rnd = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) / 4294967296; };
    const finder = (x, y) => (r, c) => { const dr = r - y, dc = c - x; if (dr < 0 || dc < 0 || dr > 6 || dc > 6) return null; return dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4); };
    const fs = [finder(0, 0), finder(N - 7, 0), finder(0, N - 7)];
    const cells = [];
    for (let r = 0; r < N; r++) for (let c = 0; c < N; c++) {
      let on = null; for (const f of fs) { const v = f(r, c); if (v !== null) on = v; }
      const nearFinder = (r < 8 && c < 8) || (r < 8 && c > N - 9) || (r > N - 9 && c < 8);
      if (on === null) on = nearFinder ? false : rnd() < 0.48;
      if (on) cells.push(U.s('rect', { x: c * px, y: r * px, width: px + 0.2, height: px + 0.2 }));
    }
    return h('div', { class: 'qr', 'data-part': 'qr' }, U.s('svg', { viewBox: `0 0 ${N * px} ${N * px}`, width: size || 168, height: size || 168, role: 'img', 'aria-label': 'OTP 등록 QR (목업 그림 — 스캔 불가, 아래 키를 직접 입력)' }, U.s('rect', { width: N * px, height: N * px, fill: '#fff' }), U.s('g', { fill: '#0f172a' }, cells)));
  }

  Object.assign(U, { can, modal, confirmDialog, skeleton, errorState, loadErrorNote, emptyState, filterChips, rowKeys, downloadCSV, keyBoxes, fakeQR });
})();
