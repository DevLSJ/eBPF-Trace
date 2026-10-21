// SupplyGuard 목업 — 「설정」 화면 [10/20 결정 2] (#/settings, 사이드바 「설정 · 기록」 묶음 끝)
// 탭: 서버 설정(보기만 — GET /api/info) · 계정(관리자) · 라이선스(GET /api/license) · 인증 감사(관리자, 모의 데이터 — GET /api/auth/audit 계약 안)
// 정책 화면에 있던 서버 설정 보기 · 계정 탭을 여기로 옮겼다. 조회자는 계정 · 인증 감사 탭을 그리지 않는다(주소로 와도 서버 설정)
// URL: ?tab=server(기본, 주소에서 생략) | accounts | license | auth-audit · 인증 감사 필터 ?event= · ?failed=1
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, state, fmt } = U;
  const TABS = [['server', '서버 설정', false], ['accounts', '계정', true], ['license', '라이선스', false], ['auth-audit', '인증 감사', true]];
  // 인증 감사 이벤트 이름(계약 안) — 백엔드 auth 미들웨어가 남길 종류
  const EVENT_KO = { login_ok: '로그인 성공', login_fail: '로그인 실패', locked: '잠김(5분)', otp_fail: 'OTP 실패', recovery_used: '복구 코드 사용', password_changed: '비밀번호 변경', logout: '로그아웃',
    user_created: '계정 추가', role_changed: '역할 변경', user_disabled: '계정 비활성', user_enabled: '계정 활성화', password_reset: '비밀번호 초기화', otp_reset: 'OTP 초기화', license_registered: '라이선스 등록' };

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
    }).catch((e) => replace(body, e.status === 404 ? U.emptyState({ icon: '🔑', title: '등록된 라이선스가 없습니다', hint: '관리자가 로그인하면 라이선스 등록 단계가 나옵니다.' }) : U.errorState(e, load)));
    load();
    return box;
  }

  // ── 인증 감사 탭(관리자) — 로그인 · 실패 · 잠김 · 계정 변경. 모의 데이터(IP 는 문서용 주소) ──
  function authAuditView(query) {
    const f = { event: EVENT_KO[query.get('event')] ? query.get('event') : '', failed: query.get('failed') === '1' };
    const count = h('span', { class: 'num muted' });
    const tbody = h('tbody');
    const table = h('table', { class: 'table', 'data-table': 'auth-audit', hidden: true }, h('thead', null, h('tr', null, ['시각', '아이디', '한 일', '결과', 'IP', '처리자', '내용'].map((t) => h('th', null, t)))), tbody);
    const slot = h('div', { class: 'list-slot' }, U.skeleton(6));
    const applied = h('div');
    const setF = (k, v) => { f[k] = v; U.setQuery({ [k]: v === true ? '1' : v || '' }); load(); };
    const filters = h('div', { class: 'filters' },
      U.select([['', '한 일 전체'], ...Object.entries(EVENT_KO)], f.event, (v) => setF('event', v), { 'aria-label': '한 일' }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: f.failed, onchange: (e) => setF('failed', e.target.checked) }), ' 실패만'),
      h('span', { class: 'small muted push-right' }, '최근 200건 · IP 는 모의 값(문서용 주소)'));
    const panel = U.panel({ title: ['인증 감사 ', count], class: 'grow', body: h('div', { class: 'col' }, filters, applied, h('div', { class: 'grid-scroll' }, slot, table)) });
    let loaded = false;
    function load(quiet) {
      if (!quiet && !loaded) replace(slot, U.skeleton(6));
      return U.auth.api.authAudit({ limit: 200, event: f.event, failed: f.failed ? '1' : '' }).then((rows) => {
        loaded = true; count.textContent = `${fmt.num(rows.length)}건`;
        table.hidden = !rows.length;
        replace(applied, U.filterChips([f.event ? { key: 'event', label: `한 일: ${EVENT_KO[f.event]}`, clear: () => { filters.querySelector('select').value = ''; setF('event', ''); } } : null,
          f.failed ? { key: 'failed', label: '실패만', clear: () => { filters.querySelector('input[type="checkbox"]').checked = false; setF('failed', false); } } : null],
        () => { filters.querySelector('select').value = ''; filters.querySelector('input[type="checkbox"]').checked = false; f.event = ''; f.failed = false; U.setQuery({ event: '', failed: '' }); load(); }));
        replace(slot, rows.length ? null : U.emptyState({ icon: '◷', title: f.event || f.failed ? '조건에 맞는 기록 없음' : '아직 인증 기록이 없습니다' }));
        replace(tbody, rows.map((x) => h('tr', { 'data-auth-event': x.event, 'data-ok': String(x.ok) },
          h('td', { class: 'num mono nowrap' }, fmt.dateTime(x.at)), h('td', { class: 'mono' }, x.username || '—'),
          h('td', { class: 'nowrap' }, EVENT_KO[x.event] || x.event),
          h('td', null, h('span', { class: `badge ${x.ok ? 'badge-level-normal' : 'badge-alert'}` }, x.ok ? '성공' : '실패')),
          h('td', { class: 'mono small nowrap' }, x.ip || '—'), h('td', { class: 'small' }, x.by || '—'), h('td', { class: 'small muted trunc', title: x.detail || '' }, x.detail || ''))));
      }).catch((e) => { table.hidden = true; replace(slot, U.errorState(e, () => { loaded = false; load(); }, { quiet: () => load(true) })); });
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
      const VIEWS = {
        server: () => h('div', { class: 'settings-scroll' }, U.policyEasy.serverSettings()),
        accounts: () => h('section', { class: 'panel grow acct-panel' }, U.auth.accountsView()),
        license: () => h('div', { class: 'settings-scroll' }, licenseView()),
        'auth-audit': () => authAuditView(query),
      };
      function draw() {
        replace(bar, tabs.map(([k, ko]) => h('button', { type: 'button', role: 'tab', class: `seg-btn ${tab === k ? 'on' : ''}`, 'data-settings-tab': k, 'aria-selected': String(tab === k),
          onclick: () => { if (tab === k) return; tab = k; U.setQuery({ tab: k === 'server' ? '' : k, event: '', failed: '' }); draw(); } }, ko)));
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
