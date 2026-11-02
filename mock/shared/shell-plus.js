// SupplyGuard 목업 — 셸 2차(10/20 W10): C 알림 센터(상단 종) · E 사이드바 통합 검색(/) · 사이드바 접기(56px, 1100px 이하 자동)
// 셸(app.js shell())이 만든 자리 [data-part="bell-wrap"] · [data-part="search"] · [data-action="collapse"] 에 붙는다. 로그인 뒤(UI.whenReady)
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, state, fmt, $ } = U;
  const load = (k, d) => { try { return JSON.parse(localStorage.getItem(k) || 'null') || d; } catch { return d; } };
  const store = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* 저장 차단 */ } };
  const typing = (e) => /input|textarea|select/i.test(e.target.tagName) || e.target.isContentEditable;
  const busy = () => document.body.classList.contains('locked') || !!$('dialog[open]');

  // ── C. 알림 센터 — 데이터로 계산하는 알림. 읽음은 「알림 id → 그때의 서명」(localStorage). 서명이 바뀌면(건이 늘면) 다시 안 읽음 ──
  const READ_KEY = 'supplyguard.notices.read';
  let read = load(READ_KEY, {});
  function notices() {
    const out = [], i = state.info || {};
    const open = state.cases.filter((c) => c.state === 'open');
    if (open.length) out.push({ id: 'pending', sig: open.map((c) => c.id).join(','), tone: 'danger', icon: '⚑', title: `판정 대기 ${open.length}건`, text: open.slice(0, 3).map((c) => c.label || c.container).join(' · '), go: '#/' });
    const drafts = state.proposals.filter((p) => p.state === 'draft');
    if (drafts.length) out.push({ id: 'proposals', sig: drafts.map((p) => p.id).join(','), tone: 'warn', icon: '✎', title: `적용하지 않은 제안 ${drafts.length}건`, text: '정책에서 미리보기 후 적용하거나 버리세요', go: `#/policies?proposal=${drafts[0].id}` });
    if (state.eventsReady && !state.connected) out.push({ id: 'conn', sig: 'down', tone: 'danger', icon: '⚡', title: '실시간 연결 끊김', text: '다시 연결하는 중 — 끊긴 동안의 이벤트는 다시 붙으면 채웁니다', go: '#/events' });
    if (i.dnsResolve === 'off') out.push({ id: 'dns', sig: 'off', tone: 'warn', icon: '◎', title: '도메인 판단 꺼짐', text: 'trace_dns 가 뜨지 않아 도메인 기준 규칙이 통과 처리됩니다', go: '#/settings' });
    if (i.enforceKill === false) out.push({ id: 'dryrun', sig: 'off', tone: 'warn', icon: '⏸', title: '격리 꺼짐 (dry-run)', text: '「즉시 격리」 정책도 알림만 보냅니다 — 서버 설정 ENFORCE_KILL', go: '#/settings' });
    const n = i.notify;
    if (n && n.enabled && n.failed) out.push({ id: 'webhook', sig: String(n.failed), tone: 'danger', icon: '✉', title: `알림 발송 실패 ${n.failed}건`, text: n.lastError || '서버 설정 › 알림에서 마지막 오류를 확인하세요', go: '#/settings' });
    if (state.unseen) out.push({ id: 'violations', sig: String(state.unseen), tone: 'info', icon: '≣', title: `새 위반 ${state.unseen > 99 ? '99+' : state.unseen}건`, text: '이벤트에서 실시간 위반 보기', go: '#/events', after: () => { state.unseen = 0; } });
    return out.map((x) => Object.assign(x, { unread: read[x.id] !== x.sig }));
  }
  function bellCenter(wrap) {
    const badge = h('span', { class: 'bell-badge num', 'data-part': 'bell-badge', hidden: true });
    const btn = h('button', { type: 'button', class: 'bell', 'data-part': 'bell', 'aria-haspopup': 'true', 'aria-expanded': 'false', 'aria-label': '알림' }, h('span', { 'aria-hidden': true }, '🔔'), badge);
    const list = h('ul', { class: 'notice-list' });
    const panel = h('div', { class: 'notices', 'data-part': 'notices', role: 'dialog', 'aria-label': '알림', hidden: true },
      h('div', { class: 'notices-head' }, h('b', null, '알림'), h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': 'read-all', onclick: () => { for (const x of notices()) read[x.id] = x.sig; store(READ_KEY, read); draw(); } }, '모두 읽음')), list);
    const close = () => { panel.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
    btn.addEventListener('click', (e) => { e.stopPropagation(); panel.hidden = !panel.hidden; btn.setAttribute('aria-expanded', String(!panel.hidden)); draw(); });
    document.addEventListener('click', (e) => { if (!panel.hidden && !panel.contains(e.target) && e.target !== btn) close(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !panel.hidden) { close(); btn.focus(); } });
    let sig = '';
    function draw() {
      const xs = notices(), unread = xs.filter((x) => x.unread).length;
      badge.hidden = !unread; badge.textContent = unread; btn.setAttribute('aria-label', `알림 ${unread}건 안 읽음`);
      const next = JSON.stringify([xs.map((x) => [x.id, x.sig, x.unread, x.title]), panel.hidden]);
      if (next === sig) return; sig = next;
      if (panel.hidden) return;
      replace(list, xs.length ? xs.map((x) => h('li', null, h('button', { type: 'button', class: `notice tone-${x.tone} ${x.unread ? 'unread' : ''}`, 'data-notice': x.id, 'data-unread': String(x.unread),
        onclick: () => { read[x.id] = x.sig; store(READ_KEY, read); close(); if (x.after) x.after(); U.go(x.go, x.state); U.emit(); } },
        h('span', { class: 'notice-icon', 'aria-hidden': true }, x.icon), h('span', { class: 'notice-body' }, h('b', null, x.title), x.text ? h('span', { class: 'small muted' }, x.text) : null), x.unread ? h('i', { class: 'dot-unread', 'aria-label': '안 읽음' }) : null)))
        : h('li', { class: 'empty small' }, '새 알림 없음'));
    }
    replace(wrap, btn, panel);
    U.listeners.add(draw); draw();
  }

  // ── E. 통합 검색 — 패키지 · 컨테이너 · 규칙 id · 도메인 · 검사. ↑↓ 로 고르고 Enter 로 이동, Esc 로 닫기 ──
  const TYPE_KO = { package: '패키지', container: '컨테이너', rule: '규칙', domain: '도메인', scan: '검사', setting: '설정' };
  // 설정 화면 항목 [10/20 결정 2] — 서버 설정 줄(환경 변수 이름으로도 찾는다) · 라이선스 · (관리자) 계정 · 인증 감사
  const SETTING_ITEMS = [['서버 설정 · 자동 격리', 'ENFORCE_KILL', ''], ['서버 설정 · 감시 범위', 'WATCH_CONTAINERS', ''], ['서버 설정 · 제외', 'IGNORE_CONTAINERS', ''],
    ['서버 설정 · 컨테이너 발견 방식', 'CONTAINER_DISCOVERY', ''], ['서버 설정 · 도메인 판단', 'trace_dns', ''], ['서버 설정 · 알림', 'NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL · 테스트 발송', ''],
    ['라이선스', '평가판 · 만료일 · 키', 'license'], ['계정', '계정 추가 · 역할 · 비밀번호 초기화 · OTP 초기화', 'accounts', true], ['인증 감사', '로그인 · 실패 · 잠김 · 계정 변경 기록', 'auth-audit', true]];
  function index() {
    const out = [], seen = new Set();
    const add = (type, label, sub, go, st) => { const k = `${type}|${label}|${go}|${JSON.stringify(st || null)}`; if (seen.has(k)) return; seen.add(k); out.push({ type, label, sub, go, state: st }); }; // 필터는 상태로 [10/21b]
    for (const s of state.installs) for (const p of s.packages) add('package', `${s.manager} ${p}`, `설치 검사 ${s.id} · ${U.INSTALL_STATUS[M().statusOf(s)] || ''}`, `#/installs?id=${s.id}`, { status: 'all' });
    for (const x of state.blocklist.packages) add('package', x.value, '차단 목록', '#/policies?id=__blocklist__');
    for (const sc of state.scans) for (const p of sc.packages || []) add('package', `${p.manager || p.ecosystem} ${p.name}`, `공급망 검사 ${sc.id} · ${p.source}`, `#/scans?id=${sc.id}`);
    for (const n of state.topology.containers()) add('container', n, '런타임 · 토폴로지', U.topoLink(n).href, { container: n });
    for (const c of U.sim.containers) add('container', c.name, `런타임 · ${c.image}`, U.topoLink(c.name).href, { container: c.name });
    for (const s of state.installs) if (s.container) add('container', s.container, `설치 검사 · ${s.manager} ${s.packages.join(' ')}`, `#/installs?id=${s.id}`, { status: 'all' });
    for (const r of state.rules) add('rule', r.id, r.description || '', `#/policies?id=${encodeURIComponent(r.id)}`);
    for (const x of state.blocklist.hosts) add('domain', x.value, '차단 목록', '#/policies?id=__blocklist__');
    for (const r of state.rules) for (const f of ['allowHosts', 'denyHosts']) for (const d of r[f] || []) add('domain', d, `${r.id} · ${f === 'allowHosts' ? '허용' : '금지'} 도메인`, `#/policies?id=${encodeURIComponent(r.id)}`);
    for (const a of state.audit) if (a.event.dstHost) add('domain', a.event.dstHost, `감사 로그 · ${a.install ? a.install.label : a.event.containerName}`, '#/audit', { container: a.event.containerName });
    for (const sc of state.scans) add('scan', `${sc.id} · ${sc.target.label}`, sc.status === 'done' ? '공급망 검사 결과' : '검사 중', `#/scans?id=${sc.id}`);
    for (const [label, sub, tab, adminOnly] of SETTING_ITEMS) if (!adminOnly || U.can()) add('setting', label, sub, `#/settings${tab ? `?tab=${tab}` : ''}`);
    return out;
  }
  const M = () => window.MOCK;
  function searchBox(slot) {
    const input = h('input', { class: 'ctl side-search-input', type: 'search', placeholder: '검색   /', 'aria-label': '통합 검색 (패키지 · 컨테이너 · 규칙 id · 도메인 · 검사)', autocomplete: 'off', role: 'combobox', 'aria-expanded': 'false', 'aria-controls': 'search-results' });
    const results = h('div', { class: 'search-results', id: 'search-results', 'data-part': 'search-results', role: 'listbox', hidden: true });
    const peekBtn = h('button', { type: 'button', class: 'side-search-btn', 'aria-label': '검색 (/)', title: '검색 (/)', onclick: () => focus() }, '⌕');
    let items = [], active = 0;
    function run() {
      const q = input.value.trim().toLowerCase();
      if (!q) { results.hidden = true; input.setAttribute('aria-expanded', 'false'); return; }
      const all = index().filter((x) => x.label.toLowerCase().includes(q) || (x.sub || '').toLowerCase().includes(q));
      const by = {}; for (const x of all) (by[x.type] = by[x.type] || []).push(x);
      items = Object.keys(TYPE_KO).flatMap((t) => (by[t] || []).sort((a, b) => (a.label.toLowerCase().startsWith(q) ? 0 : 1) - (b.label.toLowerCase().startsWith(q) ? 0 : 1)).slice(0, 6));
      active = 0; draw();
    }
    function draw() {
      results.hidden = false; input.setAttribute('aria-expanded', 'true');
      if (!items.length) { replace(results, h('p', { class: 'small muted pad-sm' }, '찾는 것이 없습니다')); return; }
      let last = '';
      replace(results, items.map((x, i) => [x.type !== last ? h('div', { class: 'sr-group' }, TYPE_KO[(last = x.type)]) : null,
        h('a', { ...U.to(x.go, x.state), class: `sr-item ${i === active ? 'on' : ''}`, role: 'option', 'aria-selected': String(i === active), 'data-result': '', 'data-type': x.type, onclick: () => setTimeout(reset, 0) },
          h('span', { class: 'mono trunc-cell' }, x.label), x.sub ? h('span', { class: 'small muted trunc-cell' }, x.sub) : null)]));
    }
    function reset() { input.value = ''; results.hidden = true; input.setAttribute('aria-expanded', 'false'); slot.classList.remove('open'); input.blur(); }
    input.addEventListener('input', run);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); if (!items.length) return; active = (active + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length; draw(); }
      else if (e.key === 'Enter') { e.preventDefault(); const x = items[active]; if (x && !results.hidden) { U.go(x.go, x.state); reset(); } }
      else if (e.key === 'Escape') { e.preventDefault(); reset(); }
    });
    slot.addEventListener('focusout', (e) => { if (!slot.contains(e.relatedTarget)) setTimeout(() => { if (!slot.contains(document.activeElement)) { results.hidden = true; slot.classList.remove('open'); } }, 150); });
    function focus() { slot.classList.add('open'); input.focus(); input.select(); if (input.value) run(); }
    replace(slot, peekBtn, h('div', { class: 'side-search-box' }, input, results));
    document.addEventListener('keydown', (e) => { if (e.key === '/' && !typing(e) && !busy()) { e.preventDefault(); focus(); } });
  }

  // ── E. 사이드바 접기 — 넓은 화면: 누르면 접기/펼치기(이 브라우저에 기억). 1100px 이하: 기본 접힘, 누르면 이 화면 동안만 펼침 ──
  //   10/20 결정 5: 「그 화면 동안만」 — 다른 화면으로 옮기면(해시의 경로가 바뀌면) 다시 접는다. 좁은 화면의 펼침은 저장하지 않는다
  const SIDE_KEY = 'supplyguard.sidebar';
  function collapser(shell, btn) {
    const mq = window.matchMedia('(max-width: 1100px)');
    let narrowOpen = false;
    const apply = () => {
      const pref = load(SIDE_KEY, '');
      const on = mq.matches ? !narrowOpen : pref === 'collapsed';
      shell.classList.toggle('collapsed', on);
      btn.setAttribute('aria-label', on ? '사이드바 펼치기' : '사이드바 접기'); btn.firstChild.textContent = on ? '»' : '«';
    };
    const toggle = () => { if (mq.matches) narrowOpen = !narrowOpen; else store(SIDE_KEY, shell.classList.contains('collapsed') ? 'expanded' : 'collapsed'); apply(); };
    btn.addEventListener('click', toggle);
    mq.addEventListener('change', () => { narrowOpen = false; apply(); });
    let lastPath = U.route().path;
    window.addEventListener('hashchange', () => { const p = U.route().path; if (p === lastPath) return; lastPath = p; if (narrowOpen) { narrowOpen = false; apply(); } });
    document.addEventListener('keydown', (e) => { if (e.key === '[' && !typing(e) && !busy()) { e.preventDefault(); toggle(); } });
    apply();
  }

  // ── 768 미만: 사이드바 서랍 [10/30 계약 §7] — 메뉴 버튼(☰) · 배경 dim · Esc · 화면 이동 · 링크 클릭으로 닫힘 ──
  function drawer(shell, btn) {
    const mq = window.matchMedia('(max-width: 767px)');
    const dim = h('div', { class: 'drawer-dim', 'data-part': 'drawer-dim', hidden: true });
    shell.append(dim);
    const set = (open) => { shell.classList.toggle('drawer-open', open); dim.hidden = !open; btn.setAttribute('aria-expanded', String(open)); btn.setAttribute('aria-label', open ? '메뉴 닫기' : '메뉴 열기'); };
    btn.addEventListener('click', () => set(!shell.classList.contains('drawer-open')));
    dim.addEventListener('click', () => set(false));
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && shell.classList.contains('drawer-open')) { set(false); btn.focus(); } });
    window.addEventListener('hashchange', () => set(false));
    shell.querySelector('.sidebar').addEventListener('click', (e) => { if (mq.matches && e.target.closest('a.nav-link, a.brand, .sr-item')) set(false); });
    mq.addEventListener('change', () => { if (!mq.matches) set(false); });
  }
  U.whenReady(() => {
    const sh = U.shellEl;
    bellCenter(sh.querySelector('[data-part="bell-wrap"]'));
    searchBox(sh.querySelector('[data-part="search"]'));
    collapser(sh, sh.querySelector('[data-action="collapse"]'));
    drawer(sh, sh.querySelector('[data-action="menu"]'));
  });
  U.notices = notices;
})();
