// SupplyGuard 목업 — 길게 눌러 순서 바꾸기 [11/04d 사용자 결정 — 목업 먼저, 확정 뒤 React]. 의존성 · CDN 없음, Pointer Events.
//   적용 3곳: 사이드바 메뉴(묶음 안에서만 — 대시보드는 맨 위 고정, 묶음 구조 · 순서 그대로) · 대시보드 종합 숫자 칸 · 평가 지표 6칸(eval.js 가 attach)
//   저장: localStorage supplyguard.layout = {v:1, sidebar:{<묶음id>:[항목id…]}, dashboardKpi:[…], evaluationKpi:[…]} — 화면마다 따로.
//     읽을 때 모르는 id 는 버리고, 새로 생긴 항목은 기본 순서의 바로 앞 항목 뒤에 끼운다. JSON 오류 · v 다름 · 모양 틀림 → 기본 순서
//   조작: 주 버튼(터치 · 펜 포함)을 0.4초 누르고 있으면 「집힘」(떠오름 · 그림자 · grabbing · 놓일 자리 점선) → 끌면 같은 묶음 안에서 자리가 바뀌고 → 놓으면 저장.
//     0.4초 전에 떼면 지금처럼 클릭 · 0.4초 안에 8px 넘게 움직이면 취소(텍스트 선택 · 스크롤 그대로) · 집은 뒤에는 클릭 · 링크 이동 없음 · Esc 는 원래 자리.
//     키보드: 항목 포커스 + Alt+↑/↓(카드는 Alt+←/→ 도) 한 칸. 결과는 aria-live 로 알림(「설치 검사를 2번째로 옮김」).
//     터치: 집힌 뒤 touchmove 를 막아 스크롤하지 않는다 · 길게 누르기 메뉴(contextmenu) · 링크 끌기(dragstart)를 막는다
//   prefers-reduced-motion 이면 다른 항목이 미끄러지는 애니메이션(FLIP)을 끈다
(function () {
  'use strict';
  const KEY = 'supplyguard.layout';
  const HOLD_MS = 400, SLOP = 8;
  const reduced = () => !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
  const isObj = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
  const strs = (a) => (Array.isArray(a) ? a.filter((x) => typeof x === 'string') : null);

  // ── 저장 ──
  function readAll() {
    let raw = null;
    try { raw = localStorage.getItem(KEY); } catch { return null; }
    if (!raw) return null;
    try { const o = JSON.parse(raw); return isObj(o) && o.v === 1 ? o : null; } catch { return null; }
  }
  // scope: 'dashboardKpi' | 'evaluationKpi' | 'sidebar.<묶음id>'
  function read(scope) {
    const o = readAll(); if (!o) return null;
    const [a, b] = scope.split('.');
    return b ? (isObj(o[a]) ? strs(o[a][b]) : null) : strs(o[a]);
  }
  function write(scope, list) {
    const o = readAll() || {};
    const out = Object.assign({}, o, { v: 1 });
    const [a, b] = scope.split('.');
    if (b) out[a] = Object.assign({}, isObj(o[a]) ? o[a] : {}, { [b]: list.slice() }); else out[a] = list.slice();
    try { localStorage.setItem(KEY, JSON.stringify(out)); } catch { /* 저장 차단 — 이번 화면에서만 */ }
  }
  // 저장 순서 + 기본 순서 → 그릴 순서(모르는 id · 중복 버림, 새 항목은 기본 순서의 바로 앞 항목 뒤 — 없으면 맨 앞)
  function merge(saved, defaults) {
    if (!saved) return defaults.slice();
    const out = [];
    for (const id of saved) if (defaults.includes(id) && !out.includes(id)) out.push(id);
    defaults.forEach((id, i) => {
      if (out.includes(id)) return;
      let at = 0;
      for (let j = i - 1; j >= 0; j--) { const k = out.indexOf(defaults[j]); if (k >= 0) { at = k + 1; break; } }
      out.splice(at, 0, id);
    });
    return out;
  }
  function reset() {
    try { localStorage.removeItem(KEY); } catch { /* 저장 차단 */ }
    document.dispatchEvent(new CustomEvent('sg:layout'));
  }

  // ── 알림(스크린 리더) ──
  let liveEl = null, helpEl = null;
  function ensureA11y() {
    if (!liveEl || !liveEl.isConnected) {
      liveEl = document.createElement('div');
      Object.assign(liveEl, { id: 'sg-sort-live', className: 'sg-sr-only' });
      liveEl.setAttribute('role', 'status'); liveEl.setAttribute('aria-live', 'polite');
      helpEl = document.createElement('div');
      Object.assign(helpEl, { id: 'sg-sort-help', className: 'sg-sr-only', textContent: '길게 눌러 끌거나 Alt+화살표로 순서를 바꿉니다' });
      document.body.append(liveEl, helpEl);
    }
  }
  let liveTimer = 0;
  function announce(text) {
    ensureA11y(); liveEl.textContent = ''; clearTimeout(liveTimer);
    liveTimer = setTimeout(() => { liveEl.textContent = text; }, 30); // 같은 문장도 다시 읽히게 비웠다가 채운다
  }
  // 받침 따라 을/를 · 은/는 — 끝 글자가 숫자면 읽는 소리(0 영 · 1 일 · 3 삼 · 6 육 · 7 칠 · 8 팔 = 받침)
  function josa(word, pair) {
    const ch = String(word).trim().slice(-1), c = ch.charCodeAt(0);
    let has = null;
    if (c >= 0xac00 && c <= 0xd7a3) has = (c - 0xac00) % 28 !== 0;
    else if (/[0-9]/.test(ch)) has = '013678'.includes(ch);
    return has == null ? `${pair[0]}(${pair[1]})` : has ? pair[0] : pair[1];
  }

  // ── 진행 중인 끌기(한 번에 하나) · 클릭 삼키기 ──
  let active = null, swallowUntil = 0;
  window.addEventListener('click', (e) => { if (performance.now() < swallowUntil) { swallowUntil = 0; e.preventDefault(); e.stopImmediatePropagation(); } }, true);
  window.addEventListener('pointerdown', () => { swallowUntil = 0; }, true); // 새로 누르면 새 클릭 — 삼키지 않는다
  window.addEventListener('keydown', (e) => { if (active && e.key === 'Escape') { e.preventDefault(); e.stopImmediatePropagation(); active.escape(); } }, true); // 서랍 · 메뉴의 Esc 보다 먼저
  document.addEventListener('touchmove', (e) => { if (active && active.picked() && e.cancelable) e.preventDefault(); }, { passive: false }); // 집힌 뒤 터치 스크롤 막기
  window.addEventListener('contextmenu', (e) => { if (active) e.preventDefault(); }, true); // 길게 누르기 메뉴
  const clearSelection = () => { try { const s = getSelection(); if (s && s.rangeCount) s.removeAllRanges(); } catch { /* 없음 */ } };

  // container 의 직계 자식 중 selector 에 맞는 것들을 한 묶음으로 정렬한다(사이드바처럼 한 부모에 여러 묶음이면 묶음마다 attach)
  //   opts: scope · selector · layout('list' | 'grid') · defaults(없으면 처음 그린 DOM 순서) · idOf · labelOf · onEnd(끌기 · 누르기가 끝났을 때 — 미뤄 둔 다시 그리기)
  function attach(container, opts) {
    const o = Object.assign({ layout: 'list', idOf: (el) => el.dataset.sortId || el.dataset.kpi, labelOf: (el) => (el.firstElementChild || el).textContent.trim() }, opts);
    const grid = o.layout === 'grid';
    let defaults = o.defaults ? o.defaults.slice() : null;
    let st = null; // { el, pid, x0, y0, x, y, timer, picked, from, bx, by, marker }
    container.classList.add('sg-sortable');
    const items = () => [...container.children].filter((el) => el.matches(o.selector));
    const ids = () => items().map(o.idOf);
    function prep() {
      ensureA11y();
      for (const el of items()) {
        if (el.dataset.sortScope === o.scope) continue;
        el.dataset.sortScope = o.scope;
        if (!el.matches('a[href], button') && !el.hasAttribute('tabindex')) el.tabIndex = 0; // 평가 지표 칸(div)도 키보드로
        const d = el.getAttribute('aria-describedby'); el.setAttribute('aria-describedby', d ? `${d} sg-sort-help` : 'sg-sort-help');
      }
    }
    // 묶음 안을 order 대로 다시 꽂는다(묶음 마지막 항목 다음 형제 앞으로 — 묶음 밖 순서는 그대로)
    function place(order) {
      const set = items(); if (set.length < 2) return;
      const by = new Map(set.map((el) => [o.idOf(el), el]));
      if (same(set.map(o.idOf), order)) return;
      const anchor = set[set.length - 1].nextSibling;
      for (const id of order) { const el = by.get(id); if (el) container.insertBefore(el, anchor); }
    }
    // fresh: 방금 기본 순서로 다시 그렸다(defaults 를 DOM 에서 다시 읽는다 — opts.defaults 가 있으면 그대로)
    function apply(fresh) {
      if (st) return;
      if (!o.defaults && (fresh || !defaults)) defaults = ids();
      const here = ids(), base = (defaults || here).filter((id) => here.includes(id));
      for (const id of here) if (!base.includes(id)) base.push(id);
      place(merge(read(o.scope), base));
      prep();
    }
    const onLayout = () => { if (!container.isConnected) { document.removeEventListener('sg:layout', onLayout); return; } apply(); };
    document.addEventListener('sg:layout', onLayout);

    // 항목의 레이아웃 자리(변환 무시) — container 는 position: relative(.sg-sortable)라 offsetParent 다
    const layoutRect = (el) => { const c = container.getBoundingClientRect(); const left = c.left + container.clientLeft - container.scrollLeft + el.offsetLeft, top = c.top + container.clientTop - container.scrollTop + el.offsetTop; return { left, top, right: left + el.offsetWidth, bottom: top + el.offsetHeight, width: el.offsetWidth, height: el.offsetHeight }; };
    function follow() {
      const el = st.el;
      const dx = st.x - st.x0 - (el.offsetLeft - st.bx), dy = st.y - st.y0 - (el.offsetTop - st.by);
      el.style.transform = `translate(${dx}px, ${dy}px) scale(1.03)`;
    }
    function placeMarker() {
      const m = st.marker, el = st.el;
      Object.assign(m.style, { left: `${el.offsetLeft}px`, top: `${el.offsetTop}px`, width: `${el.offsetWidth}px`, height: `${el.offsetHeight}px` });
    }
    // 다른 항목을 옮긴 자리로 미끄러지게(FLIP). reduced-motion 이면 바로
    function moveWithFlip(el, ref) {
      const others = items().filter((x) => x !== el);
      const anim = !reduced();
      const before = anim ? new Map(others.map((x) => [x, x.getBoundingClientRect()])) : null;
      container.insertBefore(el, ref);
      if (!anim) return;
      for (const x of others) { x.style.transition = 'none'; x.style.transform = ''; }
      const moved = [];
      for (const x of others) {
        const a = before.get(x), b = x.getBoundingClientRect(), dx = a.left - b.left, dy = a.top - b.top;
        if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) { x.style.transform = `translate(${dx}px, ${dy}px)`; moved.push(x); }
      }
      if (!moved.length) { for (const x of others) x.style.transition = ''; return; }
      void container.offsetWidth;
      for (const x of moved) { x.style.transition = 'transform var(--t-base) var(--ease)'; x.style.transform = ''; }
      setTimeout(() => { for (const x of moved) if (!x.style.transform) x.style.transition = ''; }, 260);
      for (const x of others) if (!moved.includes(x)) x.style.transition = '';
    }
    // 포인터 자리 → 묶음 안 몇 번째(끄는 항목을 뺀 목록 기준). 목록은 세로 가운데, 그리드는 읽는 순서(줄 위 → 같은 줄 왼쪽 절반)
    function targetIndex() {
      const others = items().filter((x) => x !== st.el);
      for (let i = 0; i < others.length; i++) {
        const r = layoutRect(others[i]);
        if (grid ? st.y < r.top || (st.y <= r.bottom && st.x < r.left + r.width / 2) : st.y < r.top + r.height / 2) return [i, others];
      }
      return [others.length, others];
    }
    function reorder() {
      const [idx, others] = targetIndex();
      if (idx === items().indexOf(st.el)) return;
      const ref = idx < others.length ? others[idx] : others[others.length - 1].nextSibling;
      moveWithFlip(st.el, ref);
      placeMarker(); follow();
    }

    function pick() {
      if (!st || !st.el.isConnected) { end(); return; }
      const el = st.el;
      st.picked = true; st.from = items().indexOf(el); st.fromIds = ids();
      st.bx = el.offsetLeft; st.by = el.offsetTop;
      st.marker = document.createElement('div'); st.marker.className = 'sg-sort-marker'; st.marker.setAttribute('aria-hidden', 'true');
      container.append(st.marker); placeMarker();
      el.classList.add('sg-sort-picked');
      document.documentElement.classList.add('sg-sorting');
      clearSelection(); follow();
    }
    function settle(el) {
      el.classList.remove('sg-sort-picked');
      if (reduced()) { el.style.transform = ''; el.style.transition = ''; return; }
      el.style.transition = 'transform var(--t-base) var(--ease)'; el.style.transform = '';
      setTimeout(() => { if (!el.style.transform) el.style.transition = ''; }, 260);
    }
    function drop() {
      const el = st.el, label = o.labelOf(el), now = ids(), i = items().indexOf(el);
      settle(el); st.marker.remove();
      if (same(now, st.fromIds)) announce(`${label}${josa(label, '을를')} 제자리에 놓음`);
      else { write(o.scope, now); announce(`${label}${josa(label, '을를')} ${i + 1}번째로 옮김`); }
    }
    function escape() {
      if (!st || st.cancelled) return;
      if (!st.picked) { end(); return; }
      const el = st.el, set = items().filter((x) => x !== el), ref = st.from < set.length ? set[st.from] : set[set.length - 1].nextSibling;
      moveWithFlip(el, ref); settle(el); st.marker.remove();
      announce('순서 바꾸기를 취소함');
      st.cancelled = true; // 놓을 때 클릭을 삼킨다
      document.documentElement.classList.remove('sg-sorting');
    }
    function end() {
      if (!st) return;
      clearTimeout(st.timer);
      removeEventListener('pointermove', onMove, true); removeEventListener('pointerup', onUp, true); removeEventListener('pointercancel', onCancel, true);
      document.documentElement.classList.remove('sg-sorting');
      st = null; active = null;
      if (o.onEnd) o.onEnd();
    }
    function onMove(e) {
      if (!st || e.pointerId !== st.pid) return;
      st.x = e.clientX; st.y = e.clientY;
      if (st.cancelled) return;
      if (!st.picked) { if (Math.hypot(st.x - st.x0, st.y - st.y0) > SLOP) end(); return; }
      e.preventDefault(); clearSelection(); follow(); reorder();
    }
    function onUp(e) {
      if (!st || e.pointerId !== st.pid) return;
      if (st.picked && !st.cancelled) drop();
      if (st.picked || st.cancelled) swallowUntil = performance.now() + 400; // 집은 뒤 떼면 클릭 · 링크 이동 없음
      end();
    }
    function onCancel(e) { if (!st || e.pointerId !== st.pid) return; if (st.picked && !st.cancelled) escape(); end(); }
    const ctl = { picked: () => !!(st && st.picked && !st.cancelled), escape };

    container.addEventListener('pointerdown', (e) => {
      if (st || active || !e.isPrimary) return;
      if (e.pointerType === 'mouse' && (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey)) return;
      const el = e.target.closest && e.target.closest(o.selector);
      if (!el || el.parentElement !== container) return;
      const inner = e.target.closest('button, input, select, textarea, [contenteditable]');
      if (inner && inner !== el && el.contains(inner)) return; // 칸 안의 버튼 · 입력은 그대로
      st = { el, pid: e.pointerId, x0: e.clientX, y0: e.clientY, x: e.clientX, y: e.clientY, picked: false };
      st.timer = setTimeout(pick, HOLD_MS);
      active = ctl;
      addEventListener('pointermove', onMove, true); addEventListener('pointerup', onUp, true); addEventListener('pointercancel', onCancel, true);
    });
    // 링크 · 이미지의 기본 끌기(HTML5 drag)는 쓰지 않는다 — 길게 누른 뒤 움직임을 가로채지 않게
    container.addEventListener('dragstart', (e) => { const el = e.target.closest && e.target.closest(o.selector); if (el && el.parentElement === container) e.preventDefault(); });

    // 키보드: Alt+↑/↓(그리드는 ←/→ 도) 한 칸
    container.addEventListener('keydown', (e) => {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const el = e.target;
      if (!el.matches || !el.matches(o.selector) || el.parentElement !== container) return;
      const prev = e.key === 'ArrowUp' || (grid && e.key === 'ArrowLeft'), next = e.key === 'ArrowDown' || (grid && e.key === 'ArrowRight');
      if (!prev && !next) return;
      e.preventDefault(); e.stopPropagation();
      if (st) return;
      const set = items(), i = set.indexOf(el), j = i + (prev ? -1 : 1), label = o.labelOf(el);
      if (j < 0 || j >= set.length) { announce(`${label}${josa(label, '은는')} 이미 ${prev ? '맨 앞' : '맨 끝'}입니다`); return; }
      moveWithFlip(el, prev ? set[j] : set[j].nextSibling);
      el.focus({ preventScroll: true });
      write(o.scope, ids());
      announce(`${label}${josa(label, '을를')} ${j + 1}번째로 옮김`);
    });

    apply(true);
    return { apply, busy: () => !!st, scope: o.scope, ids };
  }
  const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

  window.SG_SORT = { KEY, HOLD_MS, SLOP, attach, read, write, merge, reset, announce };
})();
