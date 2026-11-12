/* eBPF Trace 목업 — 공용 엔진 (라우터 · 셸(사이드바·상단바) · 알림 센터 · 안내 · 로그인 · UI 컴포넌트)
   세 버전(v1 Trace / v2-A 현행형 / v2-B Jira형)이 이 파일을 공유하고, body[data-variant]와 theme.css로만 갈라진다.
   2026-09-28 리뉴얼: React 프론트엔드와 같은 구조 — 페이지 고정(본문만 스크롤·휠 관성), 상단바(경로·사용 흐름 레일·연결 상태·알림 종·안내),
   알림 센터 드로어, 토스트(오른쪽 아래) + 스낵바(위 가운데, 사건 대응 피드백), 사이드바 접기·모바일 서랍, 스켈레톤, 화면 전환 페이드.
   Loguard 목업의 클래스 어휘(.shell .page .kpi .panel table.grid .tabs .badge .btn …)와 기능 트릭만 가져오고 디자인 토큰은 Trace 것을 쓴다. */
(function () {
  const M = window.MOCK;
  const $ = (s, r = document) => r.querySelector(s);

  // ---------- DOM ----------
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style') el.style.cssText = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'readOnly' || k === 'open') el[k] = !!v;
      else if (k === 'value') el.value = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    const add = c => { if (c == null || c === false) return; if (Array.isArray(c)) c.forEach(add); else el.append(c.nodeType ? c : document.createTextNode(String(c))); };
    children.forEach(add);
    return el;
  }
  const PATHS = {
    shield: 'M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z', dashboard: 'M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z',
    inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5 5h14l3 7v7H2v-7l3-7z', activity: 'M22 12h-4l-3 9L9 3l-3 9H2', bell: 'M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0',
    bellOff: 'M13.7 21a2 2 0 0 1-3.4 0M18.6 13A17.9 17.9 0 0 1 18 8M6.3 6.3A6 6 0 0 0 6 8c0 7-3 9-3 9h14M18 8a6 6 0 0 0-9.3-5M2 2l20 20',
    cpu: 'M4 4h16v16H4zM9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3', box: 'M21 16V8l-9-5-9 5v8l9 5 9-5zM3.3 7 12 12l8.7-5M12 22V12',
    settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
    chevron: 'm9 18 6-6-6-6', chevronDown: 'm6 9 6 6 6-6', check: 'M20 6 9 17l-5-5', warning: 'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01',
    x: 'M18 6 6 18M6 6l12 12', search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3', bot: 'M12 8V4H8M4 8h16v12H4zM2 14h2M20 14h2M15 13v2M9 13v2',
    gauge: 'M12 2a10 10 0 0 0-7 17.1M12 2a10 10 0 0 1 7 17.1M12 12l4-4M12 12h.01', lock: 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4', user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
    logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9', play: 'm5 3 14 9-14 9V3z', flask: 'M9 3h6M10 3v6L4 20a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1L14 9V3',
    clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2', key: 'M21 2l-2 2M15.5 7.5 19 4M12 11a5 5 0 1 1-7 7 5 5 0 0 1 7-7zM12 11l7-7',
    info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01', collapse: 'm11 17-5-5 5-5M18 17l-5-5 5-5', expand: 'm13 17 5-5-5-5M6 17l5-5-5-5', pin: 'M12 17v5M5 9l7-7 7 7-2 1v4l2 3H5l2-3v-4L5 9z',
    globe: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z', download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
    users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8', radio: 'M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19.1 4.9a10 10 0 0 1 0 14.2M4.9 19.1a10 10 0 0 1 0-14.2',
    server: 'M2 2h20v8H2zM2 14h20v8H2zM6 6h.01M6 18h.01', layers: 'm12 2 10 5-10 5L2 7l10-5zM2 12l10 5 10-5M2 17l10 5 10-5', filter: 'M22 3H2l8 9.5V19l4 2v-8.5L22 3z', refresh: 'M23 4v6h-6M1 20v-6h6M20.5 9A9 9 0 0 0 5.6 5.6L1 10m22 4-4.6 4.4A9 9 0 0 1 3.5 15',
    menu: 'M3 6h18M3 12h18M3 18h18', help: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.1 9a3 3 0 0 1 5.8 1c0 2-3 2-3 4M12 17h.01', wifi: 'M5 12.5a11 11 0 0 1 14 0M8.5 16a6 6 0 0 1 7 0M12 20h.01M1.4 9a16 16 0 0 1 21.2 0',
    sparkles: 'm12 3 1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3zM5 19l.7 1.8L7.5 21.5 5.7 22.2 5 24l-.7-1.8L2.5 21.5l1.8-.7L5 19z', database: 'M12 8c5 0 9-1.3 9-3s-4-3-9-3-9 1.3-9 3 4 3 9 3zM3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3',
    file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zM14 2v6h6M16 13H8M16 17H8M10 9H8', arrowUpRight: 'M7 17 17 7M7 7h10v10', shieldCheck: 'M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3zM9 12l2 2 4-4',
    checkAll: 'M18 6 7 17l-4-4M22 10l-7.5 7.5L13 16', zap: 'M13 2 3 14h9l-1 8 10-12h-9l1-8z', trend: 'M22 7 13.5 15.5 8.5 10.5 2 17M16 7h6v6',
  };
  function icon(name, cls = '') { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('class', 'ic ' + cls); s.setAttribute('aria-hidden', 'true'); const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', PATHS[name] || PATHS.info); s.append(p); return s; }

  // ---------- 라우터 ----------
  const Router = {
    parse() { const raw = location.hash.replace(/^#/, '') || '/'; const [path, qs] = raw.split('?'); return { path: path || '/', q: Object.fromEntries(new URLSearchParams(qs || '')) }; },
    go(path, q = {}) { const qs = new URLSearchParams(Object.entries(q).filter(([, v]) => v !== '' && v != null)).toString(); location.hash = path + (qs ? '?' + qs : ''); },
    set(patch) { const { path, q } = Router.parse(); Router.go(path, { ...q, ...patch }); },
  };

  // ---------- 상태 ----------
  const store = (k, v) => { try { v === undefined ? localStorage.removeItem('trace-mock:' + k) : localStorage.setItem('trace-mock:' + k, JSON.stringify(v)); } catch (e) { /* 저장 불가 환경 무시 */ } };
  const load = (k, d) => { try { const v = localStorage.getItem('trace-mock:' + k); return v ? JSON.parse(v) : d; } catch (e) { return d; } };
  const App = { h, icon, Router, MENU: [], SCREENS: {}, variant: 'trace', user: null, collapsed: false, openGroups: {}, menuOpen: false, drawerOpen: false, notices: [], onboardingDismissed: false };
  App.registerMenu = items => { App.MENU = items; };
  App.registerScreen = (path, def) => { App.SCREENS[path] = def; };
  App.pendingCount = () => M.previews.filter(p => p.status === 'preview').length;
  App.unread = kind => App.notices.filter(n => !n.read && (!kind || n.kind === kind)).length;
  App.can = perm => ({ read: true, investigate: ['analyst', 'responder', 'approver', 'admin'].includes(App.user?.role), respond: ['responder', 'admin'].includes(App.user?.role), approve: ['approver', 'admin'].includes(App.user?.role), admin: App.user?.role === 'admin' }[perm]);
  function login(username) { App.user = M.operators.find(o => o.username === username) || null; store('user', App.user?.username); }
  function logout() { App.user = null; store('user', undefined); App.drawerOpen = false; Router.go('/login'); render(); }

  // ---------- 용어 사전 (React labels.ts와 동일한 "쉬운 말(원어)" 표기) ----------
  const SEVERITY = { critical: ['긴급', 'Critical', '서비스 중단 위험이 있어 즉시 확인이 필요합니다', 'danger'], high: ['높음', 'High', '공격 가능성이 높아 빠른 확인이 필요합니다', 'warning'], medium: ['보통', 'Medium', '주의해서 지켜볼 필요가 있습니다', 'medium'], low: ['낮음', 'Low', '참고용 기록입니다', 'info'] };
  const ATTACK = { SYN_FLOOD: ['연결 폭주', 'SYN Flood', '접속 요청만 쏟아부어 서비스를 마비시키는 공격'], PORT_SCAN: ['포트 스캔', 'Port Scan', '열린 문을 찾아 여러 포트를 두드리는 정찰'], TRAFFIC_SPIKE: ['트래픽 급증', 'Traffic Spike', '평소보다 갑자기 많은 양이 들어옴'], LARGE_FLOW: ['대용량 전송', 'Large Flow', '한 연결로 매우 큰 데이터가 오감'], ANOMALY: ['이상 징후', 'AI 탐지', '규칙엔 없지만 평소 패턴과 다름'], BENIGN: ['정상', 'Benign', '공격 징후가 없는 평범한 트래픽'] };
  App.SEVERITY = SEVERITY; App.ATTACK = ATTACK;
  App.attackLabel = t => ATTACK[t] ? `${ATTACK[t][0]}(${ATTACK[t][1]})` : String(t || '').replaceAll('_', ' ');
  App.attackTitle = t => ATTACK[t] ? `${ATTACK[t][1]} · ${ATTACK[t][2]}` : '';
  App.humanize = text => String(text ?? '').replace(/(?<!\()\bSYN[ _]?FLOOD\b/gi, App.attackLabel('SYN_FLOOD')).replace(/(?<!\()\bPORT[ _]?SCAN\b/gi, App.attackLabel('PORT_SCAN')).replace(/(?<!\()\bLARGE[ _]?FLOW\b/gi, App.attackLabel('LARGE_FLOW')).replace(/(?<!\()\bTRAFFIC[ _]?SPIKE\b/gi, App.attackLabel('TRAFFIC_SPIKE')).replace(/SYN 폭주/g, '연결 폭주').replace(/포트 탐색/g, '포트 스캔').replace(/대량 전송/g, '대용량 전송');
  App.engineLabel = m => ({ hybrid: '규칙+AI', rules: '규칙만 사용', rules_only: '규칙만 사용' })[m] || m;

  // ---------- 사용 흐름 (상단바 레일 · 안내 대화상자가 공유) ----------
  const FLOW = [
    { path: '/overview', label: '관찰', icon: 'dashboard', title: '지금 상태를 확인해요', body: '상단 신호등 배너(정상·주의·문제)로 서버·수집기 상태를 보고, 실시간 트래픽 그래프와 저장된 탐지 이벤트를 훑어봐요.' },
    { path: '/scenarios', label: '체험', icon: 'flask', title: '탐지 시나리오를 실행해요', body: '외부로 패킷을 보내지 않는 모의 시나리오예요. 정상 접속 → 포트 스캔 → 연결 폭주 → 대용량 전송 → 회복이 어떻게 탐지되는지 15초 안에 볼 수 있어요.' },
    { path: '/events', label: '검토', icon: 'shieldCheck', title: '탐지 기록을 검색하고 판정해요', body: '심각도·유형·IP로 검색하고, 이벤트를 열어 사람이 읽는 요약을 확인한 뒤 정탐·오탐을 기록해요.' },
    { path: '/incidents', label: '대응', icon: 'shield', title: '사건을 맡고 승인받아 대응해요', body: '담당자 인수 → 조사 → 대응 미리보기 → 다른 승인자의 승인 → 억제 확인 → 해제 → 복구 관찰 → 종결. 차단은 정해진 시간이 지나면 스스로 풀려요.' },
    { path: '/analysis', label: '분석', icon: 'activity', title: '데이터로 근거를 확인해요', body: '실제 캡처(CIC-IDS-2017)의 정답 매칭률과 모델 비교 결과를 보고, 운영에 규칙 기반을 유지하는 이유를 확인해요.' },
  ];
  App.FLOW = FLOW;
  const flowStep = path => path.startsWith('/scenarios') ? '/scenarios' : path.startsWith('/events') ? '/events' : path.startsWith('/analysis') ? '/analysis' : /^\/(incidents|operations|actions|notifications|assets|models)/.test(path) ? '/incidents' : /^\/(overview|system)/.test(path) ? '/overview' : '';

  // ---------- 사이드바 ----------
  function renderSidebar() {
    const sb = $('#sidebar'); if (!sb) return; sb.innerHTML = ''; sb.classList.toggle('collapsed', App.collapsed); sb.classList.toggle('open', App.menuOpen);
    if (!App.user) return;
    const cur = Router.parse().path;
    sb.append(h('div', { class: 'sb-brand' }, h('a', { class: 'sb-logo', href: '#/overview', title: 'eBPF Trace 대시보드' }, icon('shield')),
      h('div', { class: 'sb-brand-text' }, h('div', { class: 'sb-product' }, 'eBPF ', h('span', { class: 'sb-product-accent' }, 'Trace')), h('div', { class: 'sb-meta' }, '네트워크 위협 탐지')),
      h('button', { class: 'sb-collapse', 'aria-label': App.collapsed ? '메뉴 펼치기' : '메뉴 접기', title: App.collapsed ? '메뉴 펼치기' : '메뉴 접기', 'aria-pressed': String(App.collapsed), onClick: () => { App.collapsed = !App.collapsed; store('collapsed', App.collapsed); renderSidebar(); } }, icon(App.collapsed ? 'expand' : 'collapse'))));
    sb.append(h('div', { class: 'sb-action' }, h('button', { class: 'btn primary block', title: '외부로 패킷을 보내지 않는 모의 탐지 시나리오', onClick: () => Router.go('/scenarios') }, icon('flask'), h('span', {}, '탐지 시나리오 열기'))));
    const nav = h('nav', { class: 'sb-nav', 'aria-label': '주 메뉴' });
    App.MENU.forEach(g => {
      const open = App.openGroups[g.id] !== false;
      nav.append(h('div', { class: 'sb-group' + (open ? ' open' : '') + (g.children.some(c => cur.startsWith(c.path)) ? ' active' : ''), 'data-group': g.id },
        h('button', { class: 'sb-group-head', 'aria-expanded': String(open), title: g.sub, onClick: () => { App.openGroups[g.id] = !open; store('open', App.openGroups); renderSidebar(); } }, icon(g.icon), h('span', { class: 'lbl' }, g.label, g.sub ? h('small', { class: 'sb-cap' }, g.sub) : null), icon('chevronDown', 'chev')),
        open ? h('div', { class: 'sb-children' }, g.children.map(c => navItem(c, cur))) : null));
    });
    sb.append(nav);
    const u = App.user;
    sb.append(h('div', { class: 'sb-footer' },
      h('div', { class: 'sb-sensor' }, h('span', { class: 'sb-sensor-ic' }, icon('radio')), h('span', { class: 'sb-sensor-text' }, h('b', {}, '커널에서 시작하는 관찰'), h('span', { class: 'sb-collector ' + (M.health.collector_connected ? 'ok' : 'warn') }, h('i'), M.health.collector_connected ? '수집기 연결됨' : '수집기 연결 대기'))),
      h('button', { class: 'sb-user', title: '계정', onClick: accountModal },
        h('span', { class: 'avatar' }, u.name.slice(0, 1)), h('span', { class: 'sb-user-text' }, h('span', { class: 'nm' }, u.name), h('span', { class: 'role' }, u.roleLabel)))));
  }
  function navItem(item, cur) {
    const active = cur === item.path || (item.path !== '/overview' && cur.startsWith(item.path + '/'));
    const count = item.badge === 'pending' ? App.pendingCount() : item.badge === 'events' ? App.unread('event') : 0;
    const badge = count ? h('span', { class: 'sb-badge ' + (item.badge === 'pending' ? 'warn' : 'info'), title: item.badge === 'pending' ? '승인 대기' : '읽지 않은 새 탐지' }, count > 99 ? '99+' : count) : null;
    return h('a', { class: 'sb-item' + (active ? ' active' : ''), href: '#' + item.path, 'aria-current': active ? 'page' : null, title: item.hint || item.label }, item.icon ? icon(item.icon) : null, h('span', { class: 'lbl' }, item.label), item.tag ? h('span', { class: 'tag new' }, item.tag) : null, badge);
  }
  function accountModal() { const u = App.user; ui.modal({ title: '내 계정', body: h('div', { class: 'kv' }, kv('이름', u.name), kv('아이디', u.username), kv('역할', u.roleLabel), kv('세션', 'HttpOnly 쿠키 · 8시간')), actions: [{ label: '로그아웃', kind: 'danger', onClick: logout }, { label: '닫기', primary: true }] }); }
  function rehearse(scenario) {
    const t = ui.toast(scenario === 'shared_source' ? '공유 출발지 훈련을 시작합니다…' : '훈련 사건을 생성하는 중…', 'info', { sticky: true });
    setTimeout(() => { t.close(); const id = scenario === 'shared_source' ? 'inc-sim-0002' : 'inc-sim-0001'; Router.go('/incidents/detail', { id, source: 'simulation' }); ui.snack(scenario === 'shared_source' ? '공유 출발지 훈련 사건을 열었어요. 차단 안전 점검(Gate)이 왜 자동 차단을 거부했는지 확인해 보세요.' : '새 훈련 사건을 열었어요. 먼저 [확인하고 맡기]로 담당자가 되어 보세요.'); }, 900);
  }
  App.rehearse = rehearse;

  // ---------- 상단바: 경로 · 사용 흐름 레일 · 연결 상태 · 알림 종 · 안내 · 계정 ----------
  function renderTopbar() {
    const tb = $('#topbar'); if (!tb) return; tb.innerHTML = ''; if (!App.user) return;
    const { path } = Router.parse(); const def = App.SCREENS[path]; const group = App.MENU.find(g => g.children.some(c => path.startsWith(c.path)));
    const title = def ? (typeof def.title === 'function' ? def.title(Router.parse()) : def.title) : '화면';
    const step = flowStep(path); const unread = App.unread();
    tb.append(h('div', { class: 'tb-left' },
      h('button', { class: 'tb-icon-btn menu-btn', 'aria-label': '메뉴 열기', 'aria-expanded': String(App.menuOpen), onClick: () => { App.menuOpen = !App.menuOpen; renderSidebar(); renderBackdrop(); } }, icon('menu')),
      h('div', { class: 'tb-crumbs', 'aria-label': '경로' }, h('span', { class: 'crumb-root' }, 'eBPF Trace ', h('span', { class: 'sep' }, '/'), ' ', group?.label || '위협 대응', ' ', h('span', { class: 'sep' }, '/'), ' '), h('b', {}, title))));
    tb.append(h('nav', { class: 'flow-rail', 'aria-label': '사용 흐름' }, FLOW.flatMap((f, i) => [i ? h('span', { class: 'flow-sep', 'aria-hidden': 'true' }, '›') : null, h('a', { href: '#' + f.path, 'aria-current': step === f.path ? 'step' : null, title: f.title }, h('i', {}, i + 1), f.label)])));
    const bell = h('button', { class: 'tb-icon-btn', 'aria-label': unread ? `알림 센터 열기 · 읽지 않은 알림 ${unread}건` : '알림 센터 열기', 'aria-expanded': String(App.drawerOpen), onClick: () => { App.drawerOpen = !App.drawerOpen; if (App.drawerOpen) App.notices.forEach(n => { n.read = true; }); renderDrawer(); renderTopbar(); renderSidebar(); } }, icon('bell'), unread ? h('span', { class: 'notify-count' + (App.bump ? ' bump' : ''), 'aria-hidden': 'true' }, unread > 99 ? '99+' : unread) : null);
    App.bump = false;
    tb.append(h('div', { class: 'tb-right' },
      h('span', { class: 'conn ' + (M.system.websocket || 'connected'), role: 'status', title: '대시보드가 서버와 실시간으로 연결되어 있습니다' }, icon('wifi'), M.system.websocket === 'connected' ? '실시간 연결됨' : '다시 연결 중'),
      bell,
      h('button', { class: 'tb-icon-btn', 'aria-label': '사용 안내 열기', title: '사용 안내 (?)', onClick: () => ui.guide() }, icon('help')),
      h('button', { class: 'tb-avatar', title: `${App.user.name} · ${App.user.roleLabel}`, onClick: accountModal }, App.user.name.slice(0, 1))));
  }
  function renderBackdrop() { $('.sb-backdrop')?.remove(); if (App.menuOpen) document.body.append(h('div', { class: 'sb-backdrop', onClick: () => { App.menuOpen = false; renderSidebar(); renderBackdrop(); renderTopbar(); } })); }

  // ---------- 알림 센터 드로어 ----------
  const relTime = at => { const s = Math.max(0, Math.round((M.at(0).getTime() - new Date(at).getTime()) / 1000)); return s < 10 ? '방금' : s < 60 ? `${s}초 전` : s < 3600 ? `${Math.round(s / 60)}분 전` : s < 86400 ? `${Math.round(s / 3600)}시간 전` : M.fmt(new Date(at)).slice(5, 10); };
  App.drawerFilter = 'all';
  function renderDrawer() {
    $('.notify-backdrop')?.remove(); $('.notify-drawer')?.remove(); if (!App.drawerOpen) return;
    const close = () => { App.drawerOpen = false; renderDrawer(); renderTopbar(); };
    const filters = [['all', '전체'], ['event', '탐지'], ['system', '시스템']];
    const list = App.notices.filter(n => App.drawerFilter === 'all' || n.kind === App.drawerFilter);
    const level = n => n.kind === 'event' ? 'shield' : n.level === 'ok' ? 'check' : n.level === 'warn' ? 'warning' : n.level === 'error' ? 'x' : 'info';
    const open = n => { if (n.eventId) { const ev = M.detections.find(d => d.event_id === n.eventId); if (ev) App.eventDetail(ev); } else if (n.href) Router.go(n.href); close(); };
    const drawer = h('aside', { class: 'notify-drawer', 'aria-label': '알림 센터' },
      h('header', { class: 'notify-head' }, h('div', {}, h('h2', {}, icon('bell'), '알림'), h('p', {}, '새 탐지 이벤트와 연결 상태 변화가 여기에 쌓여요.')), h('button', { class: 'icon-btn', 'aria-label': '알림 센터 닫기', onClick: close }, icon('x'))),
      h('div', { class: 'notify-filters', role: 'group', 'aria-label': '알림 종류' }, filters.map(([v, l]) => h('button', { class: App.drawerFilter === v ? 'active' : '', 'aria-pressed': String(App.drawerFilter === v), onClick: () => { App.drawerFilter = v; renderDrawer(); } }, l, h('b', {}, App.notices.filter(n => v === 'all' || n.kind === v).length))),
        h('button', { class: 'notify-read-all', disabled: !App.notices.some(n => !n.read), onClick: () => { App.notices.forEach(n => { n.read = true; }); renderDrawer(); renderTopbar(); renderSidebar(); } }, icon('checkAll'), '모두 읽음')),
      h('div', { class: 'notify-list' }, list.length ? list.map(n => h('article', { class: `notify-item level-${n.level}${n.read ? '' : ' unread'}` }, h('span', { class: 'notify-icon' }, icon(level(n))), h('div', { class: 'notify-body' }, h('strong', {}, n.title), n.body ? h('p', {}, n.body) : null, h('small', {}, h('time', {}, relTime(n.at)), (n.eventId || n.href) ? h('button', { class: 'notify-open', onClick: () => open(n) }, n.eventId ? '기록 열기' : '화면으로 이동') : null))))
        : h('div', { class: 'notify-empty' }, icon('bellOff'), h('strong', {}, '아직 알림이 없어요'), h('p', {}, App.drawerFilter === 'event' ? '새 탐지 이벤트가 실시간으로 들어오면 여기에 표시돼요.' : App.drawerFilter === 'system' ? '연결·수집기 상태가 바뀌면 여기에 표시돼요.' : '새 탐지 이벤트와 연결·수집기 상태 변화가 여기에 표시돼요.'))),
      h('footer', { class: 'notify-foot' }, h('a', { href: '#/notifications', onClick: close }, '운영자 알림 전달 기록 보기 →'), h('button', { class: 'btn subtle sm', title: '목업 데모: 새 탐지 알림이 도착한 것처럼 보여줍니다', onClick: () => { close(); ui.demoDetection(); } }, icon('zap'), '데모: 새 탐지'), h('button', { class: 'btn subtle sm', disabled: !App.notices.length, onClick: () => { App.notices = []; renderDrawer(); renderTopbar(); renderSidebar(); } }, '기록 비우기')));
    document.body.append(h('div', { class: 'notify-backdrop', onClick: close }), drawer);
    ui.smooth(drawer.querySelector('.notify-list'));
  }

  // ---------- 화면 렌더 ----------
  function renderMain() {
    const { path, q } = Router.parse(); const main = $('#main'); if (!main) return;
    if (!App.user) { renderLogin(main); return; }
    document.body.classList.remove('login');
    if (path === '/' || path === '/login') { Router.go('/overview'); return; }
    const def = App.SCREENS[path]; main.innerHTML = '';
    if (!def) { main.append(pageShell({ title: '화면 없음', crumbs: [] }, ui.empty({ title: '해당 경로의 화면이 없습니다', desc: path, action: { label: '대시보드로', onClick: () => Router.go('/overview') } }))); return; }
    const ctx = { path, q, set: patch => Router.set(patch), go: Router.go, actions: [], user: App.user, variant: App.variant };
    const body = def.render(ctx);
    const page = pageShell({ title: typeof def.title === 'function' ? def.title(ctx) : def.title, crumbs: def.crumbs, actions: ctx.actions, subtitle: ctx.subtitle || def.subtitle, headerExtra: ctx.headerExtra, eyebrow: def.eyebrow, hideHeader: def.hideHeader }, body);
    if (App.lastView !== (def.view || path)) page.classList.add('page-enter'); page.dataset.view = def.view || ''; App.lastView = def.view || path;
    main.append(page);
    document.title = `${typeof def.title === 'function' ? def.title(ctx) : def.title} · eBPF Trace`;
    const pb = page.querySelector('.page-body'); pb.scrollTop = 0; ui.smooth(pb); pb.querySelectorAll('.grid-scroll, .dash-lists .panel-body').forEach(ui.smooth);
    if (q.focus) requestAnimationFrame(() => page.querySelector('#' + q.focus)?.scrollIntoView({ block: 'start', behavior: 'smooth' }));
  }
  function pageShell(hdr, body) {
    const crumbs = h('nav', { class: 'crumbs', 'aria-label': '경로' }, h('a', { href: '#/overview' }, 'eBPF Trace'), ...(hdr.crumbs || []).map(c => [h('span', { class: 'sep' }, '/'), h('span', {}, c)]), h('span', { class: 'sep' }, '/'), h('span', { class: 'cur' }, hdr.title));
    const actions = App.variant !== 'legacy' && hdr.actions?.length ? h('div', { class: 'ph-actions' }, hdr.actions) : null;
    const head = h('header', { class: 'page-header' }, h('div', { class: 'ph-text' }, hdr.eyebrow ? h('div', { class: 'eyebrow' }, hdr.eyebrow) : crumbs, h('h1', { class: 'page-title' }, hdr.title), hdr.subtitle ? h('p', { class: 'page-sub' }, hdr.subtitle) : null), actions, hdr.headerExtra || null);
    const legacyActions = App.variant === 'legacy' && hdr.actions?.length ? h('div', { class: 'toolbar legacy-actions' }, h('div', { class: 'spacer' }), hdr.actions) : null;
    const pb = h('div', { class: 'page-body' }, body, h('footer', { class: 'page-foot' }, h('span', {}, 'eBPF Trace'), h('span', { class: 'muted' }, '관찰 · 판단 · 대응 · 복구'), h('span', { class: 'muted foot-right' }, 'XDP 수집기는 관측 전용 · 대응은 별도 승인 정책으로 실행됩니다.')));
    // 목록 전용 화면(.grid-wrap.fill)만 남은 높이를 채우고 행만 스크롤한다. 그 밖의 표는 본문과 함께 스크롤되며 길면 표 안에서만(max-height) 스크롤된다.
    pb.querySelectorAll('.grid-wrap.fill').forEach(g => { for (let n = g.parentElement; n && n !== pb; n = n.parentElement) n.classList.add('col'); });
    return h('div', { class: 'page' }, head, legacyActions, pb);
  }
  function renderLogin(main) {
    document.body.classList.add('login'); main.innerHTML = '';
    const id = h('input', { type: 'text', value: 'minseo', autocomplete: 'username', id: 'loginId' });
    const pw = h('input', { type: 'password', value: 'demo-password', autocomplete: 'current-password', id: 'loginPw' });
    const err = h('div', { class: 'field-error', style: 'display:none' }, icon('warning'), '아이디 또는 비밀번호가 올바르지 않습니다.');
    const form = h('form', { class: 'login-card', onSubmit: e => { e.preventDefault(); const u = M.operators.find(o => o.username === id.value.trim()); if (!u || pw.value.length < 4) { err.style.display = ''; return; } login(u.username); Router.go('/overview'); render(); ui.toast(`${u.name}님, 환영합니다. (${u.roleLabel})`); } },
      h('div', { class: 'login-brand' }, h('div', { class: 'sb-logo big' }, icon('shield')), h('div', {}, h('div', { class: 'login-product' }, 'eBPF Trace'), h('div', { class: 'muted' }, '관찰 · 판단 · 대응 · 복구'))),
      h('div', { class: 'login-steps' }, FLOW.map((f, i) => [i ? icon('chevron') : null, h('span', {}, f.label)])),
      ui.field({ label: '사용자 이름', control: id, help: 'minseo(관리자) · jihoon(승인자) · yuna(대응자) · viewer(열람자) 로 역할별 차이를 볼 수 있습니다' }),
      ui.field({ label: '비밀번호', control: pw, help: '목업: 4자 이상 아무 값' }), err,
      h('button', { class: 'btn primary block lg', type: 'submit' }, '워크스페이스 열기'),
      h('p', { class: 'muted small center' }, '개인 계정으로 판단과 대응 이력을 남깁니다 · 공개 네트워크에서는 HTTPS'));
    main.append(h('div', { class: 'login-wrap' }, form));
  }
  function render() { const { q } = Router.parse(); if (q.as && !App.user) login(q.as); App.menuOpen = false; renderBackdrop(); renderSidebar(); renderTopbar(); renderMain(); }  // 딥링크 자동 로그인은 사이드바보다 먼저
  App.render = render; App.renderTopbar = renderTopbar; App.renderSidebar = renderSidebar;

  // ================= UI 컴포넌트 =================
  const ui = {}; App.ui = ui; ui.h = h; ui.icon = icon;
  const kv = (k, v) => h('div', { class: 'kv-row' }, h('div', { class: 'kv-k' }, k), h('div', { class: 'kv-v' }, v)); ui.kv = kv;
  const STATUS = { open: ['인수 대기', 'warning'], acknowledged: ['인수 완료', 'info'], investigating: ['조사 중', 'info'], action_pending: ['적용 대기', 'warning'], contained: ['억제 확인', 'success'], recovering: ['복구 관찰', 'info'], resolved: ['복구 완료', 'success'], false_positive: ['오탐 종결', 'neutral'], duplicate: ['중복 종결', 'neutral'], accepted_risk: ['위험 수용', 'neutral'], preview: ['승인 대기', 'warning'], approved: ['승인 완료', 'success'], queued: ['작업 대기', 'neutral'], applying: ['적용 중', 'info'], applied: ['적용 확인', 'success'], revoke_requested: ['해제 요청', 'warning'], released: ['해제 확인', 'neutral'], release_failed: ['해제 실패', 'danger'], expired: ['유효기간 만료', 'neutral'], failed: ['실패', 'danger'], unknown: ['결과 미확인', 'warning'], provider_accepted: ['제공자 접수', 'success'], not_configured: ['채널 설정 필요', 'neutral'], retrying: ['재시도 대기', 'warning'], sending: ['전송 중', 'info'], shadow: ['그림자 검증(Shadow)', 'info'], advisory: ['참고(Advisory)', 'warning'], production: ['실제 판정(Production)', 'success'], offline: ['대기(Offline)', 'neutral'], completed: ['완료', 'success'], running: ['실행 중', 'info'], cancelled: ['중지됨', 'neutral'] };
  ui.badge = (text, kind = 'neutral', opts = {}) => h('span', { class: `badge ${kind}`, title: opts.title }, opts.icon ? icon(opts.icon) : null, text);
  ui.status = s => { const [label, kind] = STATUS[s] || [s, 'neutral']; return ui.badge(label, kind); };
  ui.statusLabel = s => (STATUS[s] || [s])[0];
  ui.sev = s => { const v = SEVERITY[s] || [s, '', '', 'neutral']; return h('span', { class: `badge sev ${v[3]}`, title: `${v[1]} · ${v[2]}` }, h('i'), v[0]); };
  ui.prio = p => h('span', { class: `prio ${p}`, title: ({ P1: '1순위 · 가장 먼저 처리', P2: '2순위 · 빠르게 처리', P3: '3순위', P4: '4순위' })[p] }, p);
  ui.auto = (text = '자동 적용') => h('span', { class: 'auto-badge' }, icon('bot'), text);
  ui.term = (label, title) => h('span', { class: 'term', title }, label);
  ui.btn = (label, opts = {}) => h('button', { class: `btn ${opts.kind || 'default'} ${opts.size || ''}`, type: opts.type || 'button', disabled: opts.disabled, title: opts.title, 'aria-label': opts.ariaLabel, onClick: opts.onClick }, opts.icon ? icon(opts.icon) : null, label ? h('span', {}, label) : null);
  // 토스트: 오른쪽 아래 · 자동 소멸 · 행동 버튼 1개
  const toastHost = () => $('#toasts') || document.body.appendChild(h('div', { id: 'toasts', class: 'toasts', 'aria-live': 'polite' }));
  ui.toast = (msg, kind = 'success', opts = {}) => { const el = h('div', { class: `toast ${kind}`, role: 'status' }, icon(kind === 'success' ? 'check' : kind === 'error' ? 'x' : kind === 'warn' ? 'warning' : 'info'), h('span', { class: 'toast-msg' }, msg), opts.label ? h('button', { class: 'toast-action', onClick: () => { opts.onClick?.(); close(); } }, opts.label) : null, h('button', { class: 'toast-x', 'aria-label': '알림 지우기', onClick: () => close() }, icon('x'))); toastHost().append(el); let t; const close = () => { clearTimeout(t); el.classList.add('out'); setTimeout(() => el.remove(), 200); }; if (!opts.sticky) t = setTimeout(close, opts.duration || 4200); return { close, el }; };
  // 스낵바: 화면 위 가운데 · 사건 대응 행동 결과 피드백 · 8초 뒤 자동 소멸 · 하나만 유지
  ui.snack = (msg, kind = 'success') => { $('.snack')?.remove(); const el = h('div', { class: `snack ${kind}`, role: 'status' }, icon(kind === 'success' ? 'check' : kind === 'warn' ? 'warning' : 'info'), h('span', {}, msg), h('button', { 'aria-label': '알림 닫기', onClick: () => el.remove() }, icon('x'))); document.body.append(el); setTimeout(() => { if (el.isConnected) { el.classList.add('out'); setTimeout(() => el.remove(), 200); } }, 8000); return el; };
  ui.notify = n => { App.notices.unshift({ id: 'no-' + Date.now(), read: App.drawerOpen, at: M.iso(M.at(0)), ...n }); App.notices = App.notices.slice(0, 120); App.bump = !App.drawerOpen; renderTopbar(); renderSidebar(); if (App.drawerOpen) renderDrawer(); };
  ui.demoDetection = () => { const ev = { ...M.detections[Math.floor(Math.random() * 6)], event_id: 9900 + Math.floor(Math.random() * 90), detected_at: M.iso(M.at(0)), source: 'live', severity: 'critical', attack_type: 'SYN_FLOOD', is_confirmed: null }; M.detections.unshift(ev); ui.notify({ kind: 'event', level: 'warn', title: `${App.attackLabel(ev.attack_type)} · ${SEVERITY[ev.severity][0]}`, body: `${ev.flow.src_ip} → ${ev.flow.dst_ip}:${ev.flow.dst_port} · 실제 수집기 관측`, eventId: ev.event_id }); ui.toast(`새 탐지 · ${App.attackLabel(ev.attack_type)} (${SEVERITY[ev.severity][0]}) · ${ev.flow.src_ip}`, 'warn', { duration: 6000, label: '기록 보기', onClick: () => Router.go('/events') }); if (Router.parse().path === '/overview' || Router.parse().path === '/events') renderMain(); };
  ui.modal = ({ title, body, actions = [], size = '', cls = '', onClose }) => {
    const bd = h('div', { class: 'modal-backdrop', onClick: e => { if (e.target === bd) close(); } });
    const close = () => { bd.classList.add('out'); setTimeout(() => bd.remove(), 150); document.removeEventListener('keydown', esc); onClose?.(); };
    const esc = e => { if (e.key === 'Escape') close(); };
    const dlg = h('div', { class: `modal ${size} ${cls}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': typeof title === 'string' ? title : '대화상자' }, h('div', { class: 'modal-head' }, typeof title === 'string' ? h('h2', {}, title) : title, h('button', { class: 'icon-btn', 'aria-label': '닫기', onClick: close }, icon('x'))), h('div', { class: 'modal-body' }, body),
      actions.length ? h('div', { class: 'modal-foot' }, actions.map(a => ui.btn(a.label, { kind: a.kind || (a.primary ? 'primary' : 'default'), icon: a.icon, disabled: a.disabled, onClick: () => { const r = a.onClick?.({ close }); if (r !== false && !a.keepOpen) close(); } }))) : null);
    bd.append(dlg); document.body.append(bd); document.addEventListener('keydown', esc); ui.smooth(dlg.querySelector('.modal-body')); return { close, el: dlg };
  };
  ui.confirm = ({ title = '확인', message, okLabel = '확인', cancelLabel = '취소', danger = false }) => new Promise(res => ui.modal({ title, size: 'sm', body: h('p', { class: 'confirm-msg' }, message), onClose: () => res(false), actions: [{ label: cancelLabel, onClick: () => res(false) }, { label: okLabel, kind: danger ? 'danger' : 'primary', onClick: () => res(true) }] }));
  // 사용 안내 대화상자 (? 키)
  ui.guide = () => { if ($('.guide-modal')) return; ui.modal({ cls: 'guide-modal', size: 'lg', title: h('div', {}, h('span', { class: 'eyebrow' }, '처음 사용 안내'), h('h2', {}, '다섯 단계로 따라가는 eBPF Trace'), h('p', { class: 'muted' }, '왼쪽 메뉴는 이 순서대로 묶여 있어요. 단계를 누르면 해당 화면으로 이동해요.')),
    body: h('ol', { class: 'guide-steps' }, FLOW.map((f, i) => h('li', {}, h('a', { href: '#' + f.path, onClick: () => $('.modal-backdrop .icon-btn')?.click() }, h('span', { class: 'guide-index' }, i + 1), h('span', { class: 'guide-icon' }, icon(f.icon)), h('span', { class: 'guide-text' }, h('strong', {}, f.title), h('p', {}, f.body)))))),
    actions: [{ label: '알겠어요', primary: true }] });
    const foot = $('.guide-modal .modal-foot'); foot?.prepend(h('span', { class: 'guide-keys' }, h('kbd', {}, '?'), ' 이 안내 열기 · ', h('kbd', {}, 'Esc'), ' 닫기 · 종 아이콘에서 새 탐지와 연결 상태 알림을 볼 수 있어요.')); };
  ui.field = ({ label, control, required, help, error, inline }) => { const id = control.id || ('f' + Math.random().toString(36).slice(2, 8)); control.id = id; return h('div', { class: 'field' + (inline ? ' inline' : '') }, h('label', { for: id }, label, required ? h('span', { class: 'req' }, ' *') : null), h('div', { class: 'field-ctl' }, control, help ? h('div', { class: 'field-help' }, help) : null, error ? h('div', { class: 'field-error' }, icon('warning'), error) : null)); };
  ui.input = (opts = {}) => h('input', { type: opts.type || 'text', value: opts.value ?? '', placeholder: opts.placeholder, min: opts.min, max: opts.max, readOnly: opts.readOnly, 'aria-label': opts.ariaLabel });
  ui.select = (options, value) => h('select', {}, options.map(o => { const [v, l] = Array.isArray(o) ? o : [o, o]; return h('option', { value: v, selected: String(v) === String(value) }, l); }));
  ui.textarea = (opts = {}) => h('textarea', { placeholder: opts.placeholder, rows: opts.rows || 3, 'aria-label': opts.ariaLabel }, opts.value || '');
  ui.switch = ({ checked, label, sub, onChange, disabled }) => h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked, disabled, onChange: e => onChange?.(e.target.checked) }), h('span', { class: 'sw' }), h('span', { class: 'sw-text' }, h('b', {}, label), sub ? h('span', { class: 'muted small' }, sub) : null));
  ui.banner = (kind, content, extra) => h('div', { class: `banner ${kind}` }, icon(kind === 'danger' || kind === 'warn' ? 'warning' : 'info'), h('div', { class: 'banner-text' }, content), extra || null);
  // 상태 신호등 배너: 색 + 아이콘 + 정상/주의/문제 텍스트 + 원인 + 다음 행동
  ui.statusBanner = ({ level, title, cause, action }) => h('div', { class: `status-banner status-${level}`, role: level === 'error' ? 'alert' : 'status', 'data-level': level }, icon(level === 'ok' ? 'check' : level === 'warn' ? 'warning' : 'x'), h('div', { class: 'status-body' }, h('strong', {}, h('span', { class: 'status-name' }, ({ ok: '정상', warn: '주의', error: '문제' })[level]), title), cause ? h('p', {}, cause) : null), action ? h('a', { class: 'status-action', href: action.href ? '#' + action.href : null, onClick: action.onClick }, action.label) : null);
  ui.empty = ({ icon: ic = 'box', title, desc, action }) => h('div', { class: 'empty' }, icon(ic, 'empty-ic'), h('div', { class: 'empty-title' }, title), desc ? h('div', { class: 'empty-desc' }, desc) : null, action ? ui.btn(action.label, { kind: 'primary', onClick: action.onClick }) : null);
  ui.skeleton = (rows = 5) => h('div', { class: 'skeleton-rows', role: 'status', 'aria-label': '불러오는 중' }, Array.from({ length: rows }, () => h('div')));
  ui.kpi = ({ label, value, unit, delta, sub, kind = '', icon: ic, onClick, title, tone }) => h(onClick ? 'button' : 'div', { class: `kpi ${kind} ${onClick ? 'clickable' : ''}`, onClick }, h('div', { class: 'kpi-top' }, h('span', { class: 'kpi-label' + (title ? ' term' : ''), title }, label), ic ? h('span', { class: 'kpi-ic-wrap ' + (tone || '') }, icon(ic, 'kpi-ic')) : null), h('div', { class: 'kpi-value' }, value, unit ? h('span', { class: 'unit' }, unit) : null), (delta != null || sub) ? h('div', { class: 'kpi-delta ' + (delta > 0 ? 'up' : delta < 0 ? 'down' : '') }, delta != null ? `${delta > 0 ? '▲' : delta < 0 ? '▼' : '—'} ${Math.abs(delta)}% ` : '', sub || '') : null);
  ui.panel = ({ title, sub, actions, body, cls = '', id }) => h('section', { class: `panel ${cls}`, id }, title ? h('div', { class: 'panel-head' }, h('div', {}, h('h3', {}, title), sub ? h('div', { class: 'muted small' }, sub) : null), actions ? h('div', { class: 'panel-actions' }, actions) : null) : null, h('div', { class: 'panel-body' }, body));
  ui.tabs = (ctx, key, tabs) => { const cur = tabs.find(t => t.id === ctx.q[key]) || tabs[0]; return h('div', {}, h('div', { class: 'tabs', role: 'tablist' }, tabs.map(t => h('button', { class: 'tab' + (t.id === cur.id ? ' active' : ''), role: 'tab', 'aria-selected': String(t.id === cur.id), onClick: () => ctx.set({ [key]: t.id }) }, t.label, t.badge != null ? h('span', { class: 'tab-badge' }, t.badge) : null))), cur.render()); };
  ui.search = (ctx, fields) => {
    const ctl = f => { const el = f.type === 'select' ? ui.select([['', f.placeholder || '전체'], ...f.options], ctx.q[f.key] || '') : h('input', { type: 'search', placeholder: f.placeholder || f.label, value: ctx.q[f.key] || '' }); el.setAttribute('aria-label', f.label); el.addEventListener('change', () => ctx.set({ [f.key]: el.value, page: '' })); return el; };
    if (App.variant === 'legacy') return h('div', { class: 'searchbox' }, h('div', { class: 'searchbox-title' }, icon('filter'), '검색 조건'), h('div', { class: 'searchbox-grid' }, fields.map(f => h('div', { class: 'sb-field' }, h('label', {}, f.label), ctl(f)))), h('div', { class: 'searchbox-actions' }, ui.btn('초기화', { onClick: () => ctx.go(ctx.path) }), ui.btn('조회', { kind: 'primary', icon: 'search' })));
    return h('div', { class: 'filterbar' }, fields.map(f => h('div', { class: 'fb-field' }, f.type === 'select' ? null : icon('search'), ctl(f))), h('div', { class: 'fb-actions' }, ui.btn('초기화', { kind: 'subtle', size: 'sm', onClick: () => ctx.go(ctx.path) })));
  };
  ui.grid = (ctx, { rows, columns, id = 'g', pageSize = 10, onRowClick, empty = '표시할 항목이 없습니다', emptyDesc, live = '5초마다 갱신', loading = false, fill = false }) => {
    const pkey = id + 'p', page = Math.max(1, Number(ctx.q[pkey]) || 1), pages = Math.max(1, Math.ceil(rows.length / pageSize)), slice = rows.slice((page - 1) * pageSize, page * pageSize);
    const table = h('table', { class: 'grid' }, h('thead', {}, h('tr', {}, columns.map(c => h('th', { class: c.align === 'right' ? 'al-right' : c.align === 'center' ? 'al-center' : '', style: c.width ? `width:${c.width}` : '', title: c.title }, c.label)))),
      h('tbody', {}, slice.length ? slice.map(r => h('tr', { tabindex: onRowClick ? 0 : null, class: r._cls || '', onClick: onRowClick ? () => onRowClick(r) : null, onKeydown: onRowClick ? e => { if (e.key === 'Enter') onRowClick(r); } : null }, columns.map(c => h('td', { class: (c.align === 'right' ? 'al-right ' : c.align === 'center' ? 'al-center ' : '') + (c.wrap ? 'wrap' : '') }, c.render ? c.render(r) : r[c.key] ?? '—')))) : null));
    const pager = h('div', { class: 'pager' }, Array.from({ length: pages }, (_, i) => h('button', { class: 'pg' + (i + 1 === page ? ' active' : ''), onClick: () => ctx.set({ [pkey]: i + 1 }) }, i + 1)));
    return h('div', { class: 'grid-wrap' + (fill ? ' fill' : '') }, h('div', { class: 'grid-toolbar' }, h('div', { class: 'grid-count' }, h('strong', {}, rows.length.toLocaleString()), '건'), live ? h('div', { class: 'grid-tools live-dot' }, h('i'), live) : null), h('div', { class: 'grid-scroll' }, table, loading ? ui.skeleton() : !slice.length ? ui.empty({ icon: 'shieldCheck', title: empty, desc: emptyDesc }) : null), h('div', { class: 'grid-footer' }, h('div', { class: 'gf-left' }, `${rows.length.toLocaleString()}개 기록 · ${page} / ${pages} 페이지`), pager));
  };
  // 차트 — 단순 SVG
  ui.lineChart = ({ values, labels, height = 220, color = 'var(--color-primary)', label = '추이', fill = true }) => {
    const w = 640, pad = { l: 44, r: 12, t: 12, b: 26 }, max = Math.max(...values) * 1.08 || 1, x = i => pad.l + i * (w - pad.l - pad.r) / Math.max(1, values.length - 1), y = v => pad.t + (height - pad.t - pad.b) * (1 - v / max);
    const ns = 'http://www.w3.org/2000/svg', s = document.createElementNS(ns, 'svg'); s.setAttribute('viewBox', `0 0 ${w} ${height}`); s.setAttribute('class', 'chart'); s.setAttribute('role', 'img'); s.setAttribute('aria-label', label);
    const add = (tag, a, txt) => { const e = document.createElementNS(ns, tag); Object.entries(a).forEach(([k, v]) => e.setAttribute(k, v)); if (txt != null) e.textContent = txt; s.append(e); return e; };
    for (let i = 0; i <= 4; i++) { const v = max * i / 4, yy = y(v); add('line', { x1: pad.l, x2: w - pad.r, y1: yy, y2: yy, class: 'gridline' }); add('text', { x: pad.l - 6, y: yy + 4, class: 'tick', 'text-anchor': 'end' }, v >= 1000000 ? (v / 1e6).toFixed(1) + 'M' : v >= 10000 ? Math.round(v / 1000) + 'K' : Math.round(v).toLocaleString()); }
    if (fill) add('path', { d: values.map((v, i) => `${i ? 'L' : 'M'}${x(i)},${y(v)}`).join(' ') + ` L${x(values.length - 1)},${y(0)} L${x(0)},${y(0)} Z`, fill: color, opacity: .12 });
    add('path', { d: values.map((v, i) => `${i ? 'L' : 'M'}${x(i)},${y(v)}`).join(' '), fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-linejoin': 'round' });
    labels.forEach((l, i) => { if (i % Math.ceil(labels.length / 6) === 0 || i === labels.length - 1) add('text', { x: x(i), y: height - 8, class: 'tick', 'text-anchor': 'middle' }, l); });
    return s;
  };
  ui.barChart = ({ items, height = 220, color = 'var(--color-info)', label = '건수', horizontal = false }) => {
    const ns = 'http://www.w3.org/2000/svg', s = document.createElementNS(ns, 'svg'); s.setAttribute('class', 'chart'); s.setAttribute('role', 'img'); s.setAttribute('aria-label', label);
    const add = (tag, a, txt) => { const e = document.createElementNS(ns, tag); Object.entries(a).forEach(([k, v]) => e.setAttribute(k, v)); if (txt != null) e.textContent = txt; s.append(e); return e; };
    if (horizontal) { const w = 420, rowH = 26, padL = 150, hh = items.length * rowH + 16, max = Math.max(...items.map(i => i.value)) * 1.05 || 1; s.setAttribute('viewBox', `0 0 ${w} ${hh}`); items.forEach((it, i) => { const bw = (w - padL - 50) * it.value / max; add('text', { x: padL - 8, y: 8 + i * rowH + 15, class: 'tick', 'text-anchor': 'end' }, it.label); add('rect', { x: padL, y: 8 + i * rowH + 4, width: bw, height: 16, rx: 4, fill: color, class: 'bar-rect' }); add('text', { x: padL + bw + 6, y: 8 + i * rowH + 16, class: 'dlabel' }, it.text ?? it.value); }); return s; }
    const w = 380, pad = { l: 40, r: 10, t: 12, b: 40 }, max = Math.max(...items.map(i => i.value)) * 1.1 || 1, bw = (w - pad.l - pad.r) / items.length; s.setAttribute('viewBox', `0 0 ${w} ${height}`);
    for (let i = 0; i <= 4; i++) { const yy = pad.t + (height - pad.t - pad.b) * (1 - i / 4); add('line', { x1: pad.l, x2: w - pad.r, y1: yy, y2: yy, class: 'gridline' }); add('text', { x: pad.l - 6, y: yy + 4, class: 'tick', 'text-anchor': 'end' }, Math.round(max * i / 4)); }
    items.forEach((it, i) => { const bh = (height - pad.t - pad.b) * it.value / max; add('rect', { x: pad.l + i * bw + bw * .2, y: height - pad.b - bh, width: bw * .6, height: bh, rx: 4, fill: color, class: 'bar-rect' }); add('text', { x: pad.l + i * bw + bw / 2, y: height - pad.b - bh - 4, class: 'dlabel', 'text-anchor': 'middle' }, it.value); add('text', { x: pad.l + i * bw + bw / 2, y: height - 10, class: 'tick', 'text-anchor': 'middle' }, it.label); });
    return s;
  };
  ui.meter = ({ label, value, color = 'var(--color-primary)' }) => h('div', { class: 'meter-row' }, h('div', { class: 'meter-label' }, h('span', {}, label), h('b', {}, value == null ? '서버 지표 대기' : `${value.toFixed(1)}%`)), h('div', { class: 'meter', role: 'meter', 'aria-label': label, 'aria-valuenow': value ?? 0, 'aria-valuemin': 0, 'aria-valuemax': 100 }, h('div', { class: 'meter-bar', style: `width:${value ?? 0}%;background:${color}` })));
  // Trace 전용
  const HARD_STOP = { insufficient_evidence: '관측이 부족해 판단을 보류', protected_neighbourhood: '보호 대상 주소와 가까운 출발지', critical_asset_mixed_traffic: '중요 자산에 정상 트래픽이 섞여 있음' };
  const DECISION = { applied: '자동으로 차단했어요 · 차단 안전 점검(Gate)이 저위험이라 승인 없이 적용', declined: '자동 차단을 하지 않았어요 · 점검 결과 고위험이라 승인자에게 넘김', limit_reached: '자동 차단을 멈췄어요 · 한 시간 상한에 도달해 승인 경로로 전환', gate_error: '점검 중 오류가 나서 안전하게 승인 경로로 넘겼어요' };
  const SIGNAL = { normal_fraction: ['정상 연결 비율', '이 출발지의 연결 중 정상적으로 완료된 비율. 높을수록 정상 사용자일 가능성'], port_diversity: ['포트 다양성', '두드린 포트 수. 많을수록 정찰(스캔) 성격'], observation: ['관측 기간', '이 출발지를 얼마나 오래 지켜봤는지. 짧으면 판단 근거가 부족'], proximity: ['보호 주소 근접도', '보호할 주소 범위(CIDR)와 얼마나 가까운지'] };
  const gateWhy = g => { const score = g.score.toFixed(2), limit = g.threshold.toFixed(2); if (g.hard_stop) return `승인이 필요해요 · 점수와 상관없이 "${HARD_STOP[g.hard_stop] || g.hard_stop}" 조건에 걸려 자동 차단을 멈췄어요.`; return g.level === 'high' ? `승인이 필요해요 · 실수로 정상 사용자까지 막을 위험 점수가 ${score}로 기준선 ${limit} 이상이라, 자동으로 차단하지 않고 다른 승인자가 검토해요.` : `자동 차단이 가능해요 · 위험 점수가 ${score}로 기준선 ${limit}보다 낮아, 자동 경로가 켜져 있으면 승인 없이 기한부로 차단해요.`; };
  const sigValue = v => typeof v === 'number' ? v.toLocaleString() : v && typeof v === 'object' ? Object.entries(v).map(([k, x]) => `${k} ${x}`).join(' · ') : String(v ?? '없음');
  ui.gate = (g, { compact = false, signals = false } = {}) => h('div', { class: `gate ${g.level} ${compact ? 'compact' : ''}`, role: 'group', 'aria-label': '차단 안전 점검(Gate)' },
    h('div', { class: 'gate-head' }, icon('gauge'), h('b', { class: 'term', title: 'risk score · 실수로 정상 사용자까지 막을 위험 점수(0~1). 낮을수록 안전' }, `부수 피해 위험 ${g.score.toFixed(2)}`), h('span', { class: 'gate-level' }, g.level === 'high' ? '고위험 · 승인 경로' : '저위험 · 자동 경로 가능'), h('small', {}, h('span', { class: 'term', title: 'threshold · 이 값 이상이면 자동 차단 없이 승인 경로로 보내요' }, `기준선 ${g.threshold.toFixed(2)}`), g.hard_stop ? ` · 강제 정지: ${HARD_STOP[g.hard_stop] || g.hard_stop}` : '')),
    h('div', { class: 'gate-bar' }, h('i', { style: `width:${Math.min(100, Math.round(g.score * 100))}%` })),
    h('p', { class: 'gate-why' }, gateWhy(g)),
    compact ? h('p', { class: 'gate-first' }, g.reasons[0]) : h('ul', {}, g.reasons.map(r => h('li', {}, r))),
    signals && !compact ? h('details', { class: 'gate-details' }, h('summary', {}, `점수를 만든 신호 ${Object.keys(g.signals).length}개 보기`), h('div', { class: 'gate-signals' }, Object.entries(g.signals).map(([k, s]) => h('div', { title: SIGNAL[k]?.[1] }, h('b', {}, `${SIGNAL[k]?.[0] || k}(${k})`), `위험 ${s.risk.toFixed(2)} × 가중치 ${s.weight} · 관측값 ${sigValue(s.value)}`)))) : null);
  ui.decision = d => h('div', { class: `decision ${d.status}` }, icon(d.status === 'applied' ? 'bot' : 'warning'), h('div', {}, h('b', {}, DECISION[d.status] || d.status), `출발지 ${d.source_ip} · ${M.fmt(new Date(d.at))}`, d.blocked_by?.length ? h('div', { class: 'muted small' }, '막힌 이유: ' + d.blocked_by.join(' ')) : null));
  ui.autoLine = (a, assetOptIn) => h('div', { class: 'auto-line' }, h('span', { title: '점검 결과가 저위험일 때만 승인 없이 기한부로 차단하는 경로' }, icon('bot'), '자동 경로 ', h('b', {}, a.auto_response ? '켜짐' : '꺼짐')), h('span', { title: '이 자산이 자동 경로에 등록되어 있는지' }, '이 자산 ', h('b', {}, assetOptIn ? '등록됨' : '미등록')), h('span', { class: 'term', title: 'TTL · 이 시간이 지나면 커널이 스스로 차단을 풀어요' }, '자동 해제 시간(TTL) ', h('b', {}, `${a.auto_ttl_seconds}초`)), h('span', { class: 'term', title: 'threshold · 이 값 이상이면 승인 경로' }, '위험 기준선 ', h('b', {}, a.risk_threshold.toFixed(2))), h('span', {}, '최근 1시간 ', h('b', {}, `${a.auto_usage.used} / ${a.auto_usage.limit}`)));
  ui.timeline = items => h('ol', { class: 'timeline' }, items.map(e => h('li', { class: e.cls || '' }, h('time', {}, M.fmt(new Date(e.at))), h('b', {}, e.label), h('p', {}, e.actor), e.detail?.reason ? h('blockquote', {}, e.detail.reason) : null)));
  ui.when = (v, empty = '아직 없음') => v ? M.fmt(new Date(v)) : empty;
  ui.ago = v => relTime(v);
  ui.dur = (s, empty = '아직 측정되지 않음') => s == null ? empty : s < 60 ? `${s}초` : `${(s / 60).toFixed(1)}분`;
  // 사람이 읽는 탐지 이벤트 요약 (React EventDetail.summarizeEvent와 같은 문장 규칙)
  ui.summarize = ev => { const f = ev.features, { src_ip, dst_ip, dst_port } = ev.flow, pps = Math.round(f.pkt_rate).toLocaleString('ko-KR'); switch (ev.attack_type) {
    case 'SYN_FLOOD': return `${src_ip}이(가) ${dst_ip}:${dst_port}로 초당 ${pps}개 패킷을 보냈고, 그중 ${Math.round(f.syn_ratio * 100)}%가 새 연결 요청(SYN)이라 연결 폭주(SYN Flood)로 판단했어요.`;
    case 'PORT_SCAN': return `${src_ip}이(가) ${dst_ip}의 서로 다른 포트 ${f.port_cnt}개를 10초 안에 두드려 포트 스캔(Port Scan)으로 판단했어요.`;
    case 'LARGE_FLOW': return `${src_ip}과(와) ${dst_ip}:${dst_port} 사이 한 연결로 초당 ${(f.byte_rate / 1e6).toFixed(1)}MB(약 ${Math.round(f.byte_rate * 8 / 1e6)}Mbps)가 오가 대용량 전송(Large Flow)으로 판단했어요.`;
    case 'TRAFFIC_SPIKE': return `${src_ip}에서 ${dst_ip}:${dst_port}로 초당 ${pps}개 패킷이 들어와 평소 기준을 크게 넘어 트래픽 급증(Traffic Spike)으로 판단했어요.`;
    case 'ANOMALY': return `${src_ip}에서 ${dst_ip}:${dst_port}로 가는 흐름의 AI 이상 점수가 ${ev.anomaly_score.toFixed(3)}으로 기준선보다 낮아 이상 징후(AI 탐지)로 판단했어요.`;
    default: return '요약할 정보가 부족합니다. 아래 관측 항목을 확인하세요.'; } };
  // 탐지 이벤트 상세 대화상자 (대시보드·탐지 이벤트·알림 드로어가 공유)
  const FEATURE_LABEL = { pkt_rate: '초당 패킷(pps)', byte_rate: '초당 바이트(bytes/s)', syn_ratio: '접속 요청 비율(SYN ratio)', port_entropy: '포트 다양성(Port Entropy)', port_cnt: '목적지 포트 수 (10초)', flow_duration: '연결 지속 시간 (ms)', avg_pkt_size: '평균 패킷 크기 (bytes)', feature_schema_version: '관측 항목 버전(feature schema)' };
  App.eventDetail = ev => {
    const sev = SEVERITY[ev.severity]; const review = ui.select([['pending', '검토 대기'], ['confirmed', '정탐 확인'], ['false_positive', '오탐 확인']], ev.is_confirmed === true ? 'confirmed' : ev.is_confirmed === false ? 'false_positive' : 'pending'); review.setAttribute('aria-label', '판정');
    const note = ui.textarea({ placeholder: '판단 근거를 남겨 주세요.', value: ev.note, ariaLabel: '검토 메모' }), token = ui.input({ type: 'password', placeholder: '저장 시에만 사용', ariaLabel: '검토용 관리자 토큰' });
    ui.modal({ title: `탐지 이벤트 #${ev.event_id}`, cls: 'event-modal', body: h('div', {},
      h('div', { class: 'detail-intro' }, ui.sev(ev.severity), h('strong', { title: App.attackTitle(ev.attack_type) }, App.attackLabel(ev.attack_type)), h('p', {}, ui.when(ev.detected_at))),
      h('div', { class: 'case-chips' }, ui.badge(ev.source === 'simulation' ? 'SIMULATION · 모의 탐지' : 'LIVE · 네트워크 수집기(Collector) 탐지', ev.source === 'simulation' ? 'info' : 'success'), ev.scenario_run_id ? h('a', { href: `#/scenarios?run=${ev.scenario_run_id}`, onClick: () => $('.modal-backdrop .icon-btn')?.click() }, '실행 그래프 ↗') : null),
      h('div', { class: 'event-summary' }, h('p', {}, ui.summarize(ev)), h('small', {}, `심각도 ${sev[0]}(${sev[1]}) · ${sev[2]}`)),
      h('dl', { class: 'detail-grid' }, h('div', {}, h('dt', {}, '출발지'), h('dd', {}, `${ev.flow.src_ip}:${ev.flow.src_port}`)), h('div', {}, h('dt', {}, '목적지'), h('dd', {}, `${ev.flow.dst_ip}:${ev.flow.dst_port}`)), h('div', {}, h('dt', {}, '프로토콜'), h('dd', {}, ev.flow.protocol === 6 ? 'TCP' : 'UDP')), h('div', {}, h('dt', { class: 'term', title: 'Anomaly Score · 0에 가까울수록 정상, −1에 가까울수록 의심' }, 'AI 이상 점수'), h('dd', {}, ev.anomaly_score?.toFixed(4) ?? '미제공 (규칙 기반)'))),
      h('details', { class: 'feature-details' }, h('summary', {}, `관측 항목 자세히 보기 (${Object.keys(ev.features).length}개)`), h('dl', { class: 'detail-grid' }, Object.entries(ev.features).map(([k, v]) => h('div', {}, h('dt', {}, FEATURE_LABEL[k] || k), h('dd', {}, typeof v === 'number' ? v.toLocaleString('ko-KR', { maximumFractionDigits: 4 }) : String(v)))))),
      h('div', { class: 'review-form' }, h('h3', {}, '분석가 검토'), h('p', { class: 'muted small' }, '검토 결과는 DB에 저장됩니다. 모델의 정답 레이블이나 학습 데이터로 자동 사용되지 않습니다.'), h('div', { class: 'form-grid' }, ui.field({ label: '판정', control: review }), h('div', { class: 'span-2' }, ui.field({ label: '검토 메모', control: note })), ui.field({ label: '검토용 관리자 토큰', control: token, help: 'HTTPS 또는 localhost에서만 저장' })), ev.reviewed_at ? h('small', { class: 'muted' }, `마지막 검토: ${ui.when(ev.reviewed_at)}`) : null)),
      actions: [{ label: '닫기' }, { label: '검토 저장', primary: true, icon: 'check', keepOpen: true, onClick: () => { if (!token.value) { ui.toast('검토 저장에는 관리자 토큰이 필요해요.', 'warn'); return false; } ev.is_confirmed = review.value === 'pending' ? null : review.value === 'confirmed'; ev.note = note.value; ev.reviewed_at = M.iso(M.at(0)); token.value = ''; ui.toast('검토 결과를 저장했어요.'); if (['/overview', '/events'].includes(Router.parse().path)) renderMain(); } }] });
  };
  // 부드러운 스크롤 (스크롤바 없이 관성 애니메이션) — 안쪽 스크롤 영역·모달·드로어가 열려 있으면 양보한다
  ui.smooth = el => {
    if (!el || el._smooth || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return; el._smooth = true;
    let target = null, raf = 0;
    const step = () => { if (target === null) { raf = 0; return; } const diff = target - el.scrollTop; if (Math.abs(diff) < .5) { el.scrollTop = target; target = null; raf = 0; return; } el.scrollTop += diff * .22; raf = requestAnimationFrame(step); };
    el.addEventListener('scroll', () => { if (!raf) target = null; }, { passive: true });
    el.addEventListener('wheel', e => {
      if (e.ctrlKey || e.metaKey || Math.abs(e.deltaX) > Math.abs(e.deltaY)) return;
      if (!el.closest('.modal, .notify-drawer') && document.querySelector('.modal-backdrop, .notify-drawer')) return;
      for (let n = e.target; n && n !== el; n = n.parentElement) { const cs = getComputedStyle(n); if (/(auto|scroll)/.test(cs.overflowY) && n.scrollHeight > n.clientHeight + 1) { const up = e.deltaY < 0; if ((up && n.scrollTop > 0) || (!up && n.scrollTop + n.clientHeight < n.scrollHeight - 1)) return; } }
      const max = el.scrollHeight - el.clientHeight; if (max <= 0) return;
      e.preventDefault();
      const d = e.deltaMode === 1 ? e.deltaY * 40 : e.deltaMode === 2 ? e.deltaY * el.clientHeight : e.deltaY;
      if (target === null) target = el.scrollTop; target = Math.max(0, Math.min(max, target + d)); if (!raf) raf = requestAnimationFrame(step);
    }, { passive: false });
  };

  // ---------- 초기화 ----------
  App.init = ({ variant }) => {
    App.variant = variant; document.body.dataset.variant = variant;
    App.collapsed = load('collapsed', false); App.openGroups = load('open', {}); App.onboardingDismissed = load('onboarding', false);
    App.notices = M.notices.map(n => ({ ...n }));
    const saved = load('user', null); if (saved) login(saved);
    document.addEventListener('keydown', e => { if (e.target.closest('input, textarea, select, [contenteditable]')) return; if (e.key === '?') { e.preventDefault(); ui.guide(); } else if (e.key === 'Escape') { if (App.drawerOpen) { App.drawerOpen = false; renderDrawer(); renderTopbar(); } if (App.menuOpen) { App.menuOpen = false; renderSidebar(); renderBackdrop(); } } });
    window.addEventListener('hashchange', () => { if (App.drawerOpen) { App.drawerOpen = false; renderDrawer(); } render(); }); render();
  };
  App.store = store; App.load = load;
  window.App = App;
})();
