// SupplyGuard 목업 — 「설정」 화면 [10/20 결정 2] (#/settings, 사이드바 「설정 · 기록」 묶음 끝)
// 탭: 서버 설정(보기만 — GET /api/info) · 계정(관리자) · 라이선스(GET /api/license) · 인증 감사(관리자 — GET /api/auth/audit?action&failed&before&limit, 서버 이름 기준 [10/21])
// 정책 화면에 있던 서버 설정 보기 · 계정 탭을 여기로 옮겼다. 조회자는 계정 · 인증 감사 탭을 그리지 않는다(주소로 와도 서버 설정)
// URL: ?tab=server(기본, 주소에서 생략) | accounts | license | auth-audit. 인증 감사 필터는 주소에 남기지 않는다(화면 상태만, 보안상 — 10/21 결정)
// 오류: 라이선스 · 계정 · 인증 감사는 다시 시도 · 자동 재시도 없이 일반 오류 안내만(React SettingsPage LoadError) [10/21 결정]
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, state, fmt } = U;
  const TABS = [['server', '서버 설정', false], ['accounts', '계정', true], ['license', '라이선스', false], ['auth-audit', '인증 감사', true]];
  // 인증 감사 action(서버 auth/service.go 가 남기는 13개, 10/21 확정) — 이름표는 React SettingsPage ACTION_KO 와 같다. 성공 · 실패는 ok 로 따로
  const ACTION_KO = { login: '로그인', login_lock: '로그인 잠금', logout: '로그아웃', password_change: '비밀번호 변경', license_register: '라이선스 등록', license_renew: '라이선스 갱신',
    otp_enroll: 'OTP 등록', otp_verify: 'OTP 확인', otp_recovery: '복구 코드 사용', user_create: '계정 추가', user_update: '계정 변경', user_reset_password: '비밀번호 초기화', user_reset_otp: 'OTP 초기화' };

  // ── 라이선스 탭 ── (날짜는 연도까지 — 등록 · 만료가 같은 달 · 날이면 헷갈린다)
  const ymd = (iso) => new Date(iso).toLocaleDateString('ko-KR', { year: 'numeric', month: '2-digit', day: '2-digit' });
  function licenseView() {
    const box = h('section', { class: 'panel settings-card', 'data-part': 'license' }, h('header', { class: 'panel-head' }, h('h2', null, '라이선스')), h('div', { class: 'pad' }, U.skeleton(4)));
    const body = box.lastChild;
    const load = () => U.auth.api.getLicense().then((l) => {
      const A = U.auth, tone = A.licenseTone(l), days = A.daysLeft(l);
      const note = { danger: '만료됐습니다. 관리자가 다시 로그인하면 「라이선스 등록」 단계에서 새 키를 넣습니다 — 그때까지 조회자는 로그인할 수 없습니다.',
        warn: `만료 ${days}일 전입니다 — 30일 전부터 상단 칩이 노랑으로 바뀝니다. 새 키를 받아 두세요.`, ok: '만료 30일 전부터 상단 칩이 노랑, 만료되면 빨강으로 바뀝니다.' }[tone];
      replace(body, h('dl', { class: 'dl wide-dt' },
        h('dt', null, '상태'), h('dd', null, A.licenseChip(l)),
        h('dt', null, '종류'), h('dd', null, l.kind === 'trial' ? '평가판' : '정식'),
        h('dt', null, '키'), h('dd', { class: 'mono' }, l.keyMasked),
        h('dt', null, '등록'), h('dd', { class: 'num' }, `${ymd(l.issuedAt)} · ${l.registeredBy}`),
        h('dt', null, '만료'), h('dd', { class: 'num' }, ymd(l.expiresAt), h('span', { class: 'small muted' }, tone === 'danger' ? ' · 만료됨' : ` · ${days}일 남음`))),
      h('p', { class: `note-box lic-note tone-${tone}` }, note));
    }).catch((e) => replace(body, e.status === 404 ? U.emptyState({ icon: '🔑', title: '등록된 라이선스가 없습니다', hint: '관리자가 로그인하면 라이선스 등록 단계가 나옵니다.' }) : U.loadErrorNote(e, '라이선스')));
    load();
    return box;
  }

  // ── 인증 감사 탭(관리자) — 로그인 · 실패 · 잠김 · 계정 변경. 시뮬은 모의 데이터(IP 는 문서용 주소). 필터는 서버 쿼리(action · failed=1) ──
  const PAGE = Math.max(1, Number(new URLSearchParams(location.search).get('auditPage')) || 200); // 한 번에 읽는 수(React 와 같은 200) — ?auditPage=N 은 회귀용
  function authAuditView() {
    const f = { action: '', failed: false }; // 화면 상태만 — 주소를 읽지도 쓰지도 않는다 [10/21 결정]
    const count = h('span', { class: 'num muted' });
    const tbody = h('tbody');
    const table = h('table', { class: 'table', 'data-table': 'auth-audit', hidden: true }, h('thead', null, h('tr', null, ['시각', '계정', '동작', '대상', 'IP', '결과', '내용'].map((t) => h('th', null, t)))), tbody);

    const slot = h('div', { class: 'list-slot' }, U.skeleton(6));
    const applied = h('div');
    const setF = (k, v) => { f[k] = v; load(); };
    const filters = h('div', { class: 'filters' },
      U.select([['', '한 일 전체'], ...Object.entries(ACTION_KO)], f.action, (v) => setF('action', v), { 'aria-label': '한 일' }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: f.failed, onchange: (e) => setF('failed', e.target.checked) }), ' 실패만'));
    // 「더 보기」(React 와 같음): 받은 수가 PAGE 이상이면 보이고, 마지막 행 id 를 before 로 다음을 붙인다. 필터가 바뀌면 처음부터
    const moreSlot = h('div');
    const panel = U.panel({ title: ['인증 감사 ', count], class: 'grow', body: h('div', { class: 'col' }, filters, applied, h('div', { class: 'grid-scroll', 'data-fill': '' }, slot, table, moreSlot)) });
    let loaded = false, all = [], gen = 0;
    const row = (x) => h('tr', { 'data-auth-action': x.action, 'data-ok': String(x.ok), 'data-audit-id': x.id },
      h('td', { class: 'num mono nowrap' }, fmt.dateTime(x.at)), h('td', { class: 'mono' }, x.actor || '—'),
      h('td', { class: 'nowrap' }, ACTION_KO[x.action] || x.action),
      h('td', { class: 'mono small' }, x.target || '—'),
      h('td', { class: 'mono small nowrap' }, x.ip || '—'),
      h('td', null, h('span', { class: `badge ${x.ok ? 'badge-level-normal' : 'badge-alert'}` }, x.ok ? '성공' : '실패')),
      h('td', { class: 'small muted trunc', title: x.detail || '' }, x.detail || ''));
    function drawMore(hasMore, err) {
      replace(moreSlot, hasMore || err ? h('div', { class: 'more-row' },
        err ? h('span', { class: 'small tone-danger', role: 'alert' }, `더 불러오지 못했습니다 — ${err.message}`) : null,
        hasMore ? h('button', { type: 'button', class: 'btn btn-outline btn-xs', 'data-action': 'more', onclick: more }, '더 보기') : null) : null);
    }
    function more(e) {
      const btn = e.currentTarget, my = gen; btn.disabled = true; btn.textContent = '불러오는 중…';
      U.auth.api.authAudit({ limit: PAGE, action: f.action, failed: f.failed ? '1' : '', before: all[all.length - 1].id }).then((next) => {
        if (my !== gen) return;
        all = all.concat(next); count.textContent = `${fmt.num(all.length)}건`;
        tbody.append(...next.map(row)); drawMore(next.length >= PAGE);
      }).catch((err) => { if (my === gen) drawMore(true, err); });
    }
    function load(quiet) {
      if (!quiet && !loaded) replace(slot, U.skeleton(6));
      const my = ++gen; replace(moreSlot, null);
      return U.auth.api.authAudit({ limit: PAGE, action: f.action, failed: f.failed ? '1' : '' }).then((rows) => {
        if (my !== gen) return;
        loaded = true; all = rows; count.textContent = `${fmt.num(rows.length)}건`;
        table.hidden = !rows.length;
        replace(applied, U.filterChips([f.action ? { key: 'action', label: `한 일: ${ACTION_KO[f.action]}`, clear: () => { filters.querySelector('select').value = ''; setF('action', ''); } } : null,
          f.failed ? { key: 'failed', label: '실패만', clear: () => { filters.querySelector('input[type="checkbox"]').checked = false; setF('failed', false); } } : null],
        () => { filters.querySelector('select').value = ''; filters.querySelector('input[type="checkbox"]').checked = false; f.action = ''; f.failed = false; load(); }));
        replace(slot, rows.length ? null : U.emptyState({ icon: '◷', title: f.action || f.failed ? '조건에 맞는 기록 없음' : '아직 인증 기록이 없습니다' }));
        replace(tbody, rows.map(row));
        drawMore(rows.length >= PAGE);
      }).catch((e) => { table.hidden = true; replace(slot, U.loadErrorNote(e, '인증 감사')); }); // 다시 시도 · 자동 재시도 없음 [10/21 결정]
    }
    load();
    return panel;
  }

  U.screens['/settings'] = {
    title: '설정',
    mount(page, query) {
      const tabs = TABS.filter(([, , adminOnly]) => !adminOnly || U.can());
      let tab = tabs.some(([k]) => k === query.get('tab')) ? query.get('tab') : 'server';
      if (query.get('tab') && query.get('tab') !== tab) U.setQuery({ tab: '' }); // 조회자가 계정 · 인증 감사 주소로 오면 서버 설정
      const bar = h('div', { class: 'pol-tabs seg settings-tabs', role: 'tablist', 'aria-label': '설정' });
      const body = h('div', { class: 'settings-body', 'data-settings-view': '' });
      page.append(bar, body);
      // 「화면 배치 기본 순서로」 [11/04d] — 이 브라우저에 저장한 순서(사이드바 · 대시보드 숫자 칸 · 평가 지표)를 지운다. 확인 없이 즉시 + 토스트, 조회자도(개인 설정)
      if (U.sortable) U.headerActions(h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': 'layout-reset', title: '길게 눌러 바꾼 순서(사이드바 · 대시보드 숫자 칸 · 평가 지표)를 처음대로 — 이 브라우저에만 저장된 값',
        onclick: () => { U.sortable.reset(); U.toast('화면 배치를 기본 순서로 되돌렸습니다 — 사이드바 · 대시보드 숫자 칸 · 평가 지표', { tone: 'ok', key: 'layout-reset', replace: true }); } }, '화면 배치 기본 순서로'));
      const VIEWS = {
        server: () => h('div', { class: 'settings-scroll', 'data-fill': '' }, U.policyEasy.serverSettings()),
        accounts: () => h('section', { class: 'panel grow acct-panel' }, U.auth.accountsView()),
        license: () => h('div', { class: 'settings-scroll', 'data-fill': '' }, licenseView()),
        'auth-audit': () => authAuditView(),
      };
      function draw() {
        replace(bar, tabs.map(([k, ko]) => h('button', { type: 'button', role: 'tab', class: `seg-btn ${tab === k ? 'on' : ''}`, 'data-settings-tab': k, 'aria-selected': String(tab === k),
          onclick: () => { if (tab === k) return; tab = k; U.setQuery({ tab: k === 'server' ? '' : k }); draw(); } }, ko)));
        body.dataset.settingsView = tab;
        replace(body, VIEWS[tab]());
      }
      draw();
      // 서버 상태(자동 격리 · 도메인 판단 · 발견 방식)가 바뀌면 서버 설정 탭만 다시 그린다. 알림 수는 칸 안의 「테스트 발송」이 스스로 다시 그린다
      const sigOf = () => JSON.stringify([state.info.enforceKill, state.info.dnsResolve, state.info.discovery, (state.info.watchContainers || []).join(',')]);
      let sig = sigOf();
      return { update() { const next = sigOf(); if (next !== sig) { sig = next; if (tab === 'server') replace(body, VIEWS.server()); } } };
    },
  };
  U.SETTINGS_TABS = TABS;
})();
