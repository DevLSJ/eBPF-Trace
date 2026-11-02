// SupplyGuard 목업 — 우측 하단 「도우미」 패널 [10/20 시안]. 플로팅 버튼 하나(🛡) → 탭 2개: 「대응 가이드」 · 「AI 도우미」(chat.js 본문을 그대로 넣는다).
// 대응 가이드: 건(격리 · 경고)마다 5단계 체크리스트 — 1 탐지 · 2 격리 확인(데이터로 자동) · 3 공격 체인(링크를 누르면) · 4 판정(decision 이 바뀌면) · 5 후속 조치(사용자가 체크).
//   체크 상태는 localStorage `supplyguard.guide.<caseId>` = { chain, follow: { 묶음: true } }. 새 건이 열리면 패널이 가이드 탭으로 자동 열린다.
//   건이 없으면 「처음이세요? 구축 순서」 3단계(데이터로 완료 판정, 「그만 보기」 가능 — localStorage `supplyguard.guide.setup`).
// 실제 앱에 옮길 때: 단계 1 · 2 · 4 는 GET /api/cases 의 level · decision 으로, 3 · 5 는 브라우저 저장(또는 건의 note)으로. notify · dnsResolve 는 /api/info 에 추가 예정
(function () {
  'use strict';
  const U = window.UI;
  const { h, state, fmt, replace } = U;
  const SRC = U.CASE_SOURCE; // 출처 표기는 app.js 한 곳 [10/20 J]
  const TOTAL = 5;
  // 규칙별 후속 조치 문구 사전 — 같은 묶음(group)이면 한 줄로 합친다
  const FOLLOW = [
    { group: 'secrets', rules: ['sensitive-files', 'sandbox-secrets'], text: '노출됐을 수 있는 키 · 토큰 교체, 같은 볼륨을 쓰는 컨테이너 확인' },
    { group: 'egress', rules: ['reverse-shell-ports', 'runtime-direct-ip', 'sandbox-egress', 'egress-allowlist', 'runtime-dns-exfil', 'sandbox-dns'], text: '목적지 IP · 도메인을 차단 목록에 올리기, 같은 이미지를 쓰는 다른 컨테이너 확인' }, // dns 규칙도 egress 묶음 [10/30]
    { group: 'download', rules: ['no-shell-download', 'pipe-to-shell'], text: '설치 스크립트 출처 확인, 패키지 버전 고정 · 차단' },
    { group: 'blocked-image', rules: ['blocked-image'], text: '차단된 이미지가 다시 기동된 경로(배포 파이프라인 · 이미지 태그) 확인' },
    { group: 'hosts', rules: ['blocklist-hosts'], text: '차단 도메인으로 나간 프로세스와 그 이미지 확인' },
  ];
  const followFor = (c) => {
    const out = FOLLOW.map((f) => ({ ...f, hit: f.rules.filter((r) => c.ruleIds.includes(r)) })).filter((f) => f.hit.length);
    return out.length ? out : [{ group: 'default', rules: [], hit: c.ruleIds.slice(), text: '같은 이미지 · 패키지를 쓰는 다른 컨테이너 확인' }];
  };
  const caseLink = (c) => U.caseLink(c, true); // { href, state } [10/21b]

  // ── 저장 (이 브라우저의 체크 상태) ──
  const load = (k, d) => { try { return JSON.parse(localStorage.getItem(k) || 'null') || d; } catch { return d; } };
  const store = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* 저장 차단 */ } };
  const gkey = (id) => `supplyguard.guide.${id}`;
  const gpref = (id) => load(gkey(id), { chain: false, follow: {} });
  const SETUP_KEY = `supplyguard.guide.setup${U.fresh ? '.fresh' : ''}`;
  let setupPref = load(SETUP_KEY, { off: false, visitedPolicies: false });
  const saveSetup = () => store(SETUP_KEY, setupPref);

  // ── 단계 판정 ──
  function stepsOf(c) {
    const p = gpref(c.id);
    const follows = followFor(c);
    const followDone = follows.length > 0 && follows.every((f) => p.follow[f.group]);
    return { p, follows, done: [true, true, !!p.chain, c.decision !== 'pending', followDone] };
  }
  const progressOf = (c) => stepsOf(c).done.filter(Boolean).length;
  // 라이브는 판정 API(GET /api/cases)가 백엔드에 아직 없어 건이 없는 것으로 본다(시드 건은 시뮬 전용)
  const allCases = () => (state.source === 'live' ? [] : state.cases);
  const recentCases = () => [...allCases()].sort((a, b) => Date.parse(b.openedAt) - Date.parse(a.openedAt)).slice(0, 5);
  // 배지 = 종결되지 않은 건 가운데 5단계가 다 끝나지 않은 수
  const pendingGuides = () => allCases().filter((c) => c.state !== 'closed' && progressOf(c) < TOTAL).length;

  // ── 구축 순서(건이 없을 때) — 데이터로 완료 판정. live 에서 모르는 것은 null(미확인) ──
  const INSTALL_CMD = 'sg-install pip requests';
  const SETUP = [
    { id: 'install', title: '설치 검사 돌려 보기', desc: '터미널에서 감시 컨테이너로 패키지를 설치해 봅니다. 결과는 「설치 검사」에 쌓입니다.', go: '#/installs', state: { status: 'all' }, label: '설치 검사 →',
      done: () => (state.source === 'live' ? null : state.installs.length > 0) },
    { id: 'policies', title: '정책 확인', desc: '기본 정책이 무엇을 막는지 한 번 봅니다(정책 화면을 열면 완료).', go: '#/policies', label: '정책 →', done: () => !!setupPref.visitedPolicies },
    { id: 'runtime', title: '런타임 감시 컨테이너 확인', desc: '토폴로지에 감시 중인 컨테이너가 보이면 런타임 감시가 돌고 있는 것입니다.', go: '#/topology', label: '토폴로지 →',
      done: () => (state.topology.containers().length > 0 ? true : state.source === 'live' ? null : false) },
  ];
  function setupView() {
    if (setupPref.off) return h('div', { class: 'guide-empty', 'data-part': 'setup-off' }, h('p', { class: 'muted' }, '아직 격리 · 경고된 건이 없습니다.'),
      h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => { setupPref.off = false; saveSetup(); draw(true); } }, '구축 순서 다시 보기'));
    const st = SETUP.map((s) => s.done());
    const n = st.filter((v) => v === true).length;
    return h('section', { class: 'guide-setup', 'data-part': 'setup-steps' },
      h('div', { class: 'guide-head' }, h('b', null, n === SETUP.length ? '구축 완료' : '처음이세요? 구축 순서 3단계'), h('span', { class: 'small muted num' }, `${n}/${SETUP.length}`),
        h('button', { type: 'button', class: 'btn btn-ghost btn-xs push-right', 'aria-label': '구축 순서 그만 보기', title: '다시 보려면 「구축 순서 다시 보기」', onclick: () => { setupPref.off = true; saveSetup(); draw(true); } }, '그만 보기')),
      bar(n, SETUP.length),
      h('ol', { class: 'guide-steps' }, SETUP.map((s, i) => h('li', { class: `guide-step ${st[i] === true ? 'done' : ''}`, 'data-setup': s.id, 'data-done': st[i] === null ? 'unknown' : String(!!st[i]) },
        h('span', { class: 'guide-n', 'aria-hidden': true }, st[i] === true ? '✓' : String(i + 1)),
        h('div', { class: 'guide-body' }, h('b', null, s.title), st[i] === null ? h('span', { class: 'badge badge-alert' }, '미확인') : null, h('p', { class: 'small muted' }, s.desc),
          h('div', { class: 'row-inline' },
            s.id === 'install' ? h('button', { type: 'button', class: 'btn btn-primary btn-xs', 'aria-label': 'sg-install 명령 복사', onclick: () => copy(INSTALL_CMD) }, '명령 복사') : null,
            s.id === 'install' ? h('code', { class: 'mono' }, INSTALL_CMD) : null,
            h('a', { ...U.to(s.go, s.state), class: 'link small' }, s.label)))))),
      n === SETUP.length ? h('p', { class: 'small muted' }, '설치 검사 · 정책 · 런타임 감시까지 모두 확인했습니다. 격리 · 경고가 생기면 여기에 대응 가이드가 뜹니다.') : null);
  }
  function copy(text) {
    try { navigator.clipboard.writeText(text).catch(() => {}); } catch { /* 복사 차단 */ }
    U.toast(`명령을 복사했습니다 — ${text}`, { tone: 'ok', key: 'copy', replace: true, action: { label: '설치 검사', go: '#/installs', state: { status: 'all' } } });
  }
  const bar = (n, total) => h('div', { class: 'guide-bar', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': total, 'aria-valuenow': n, 'aria-label': `${n}/${total}`, 'data-part': 'guide-progress', 'data-value': `${n}/${total}` }, h('span', { style: `width:${(n / total) * 100}%` }));

  // ── 건 가이드 ──
  let selectedId = null;
  function pickCase(list) {
    if (selectedId && list.some((c) => c.id === selectedId)) return list.find((c) => c.id === selectedId);
    return list.find((c) => c.state !== 'closed') || list[0];
  }
  function notifyLine() {
    const n = state.server && state.server.notify;
    const [cls, text] = n === 'webhook' ? ['tone-ok', '웹훅 알림 발송됨'] : n === 'failed' ? ['tone-danger', '웹훅 발송 실패 — 설정 › 서버 설정 › 알림에서 마지막 오류 확인'] : n === 'none' ? ['tone-warn', '웹훅 미설정 — 알림을 받으려면 NOTIFY_WEBHOOK_URL 을 설정하세요'] : ['muted', '웹훅 알림 미확인 (백엔드가 알려 주지 않음)'];
    return h('p', { class: `small ${cls}`, 'data-part': 'notify' }, text);
  }
  function caseView(list) {
    const c = pickCase(list);
    const { p, follows, done } = stepsOf(c);
    const n = done.filter(Boolean).length;
    const rows = state.audit.filter((a) => a.caseId === c.id);
    const firstAt = rows.length ? rows[rows.length - 1].event.timestamp : c.openedAt;
    const mark = (patch) => { const q = gpref(c.id); Object.assign(q, patch); store(gkey(c.id), q); draw(true); };
    const link = caseLink(c);
    const isolation = c.level === 'killed' ? ['tone-danger', '격리됨', c.source === 'install' ? '감시 컨테이너를 종료했습니다(kill). 설치는 끝나기 전에 막혔습니다.' : '컨테이너를 종료했습니다(kill). 15초 뒤 재기동되면 차단 이미지일 때만 즉시 다시 격리됩니다.']
      : c.level === 'held' ? ['tone-warn', '격리 대상', 'dry-run 이라 알림만 보냈습니다 — 컨테이너가 살아 있습니다. 필요하면 직접 멈추고, 격리 모드(ENFORCE_KILL)를 켜세요.']
      : ['tone-warn', '경고', '격리 정책이 아니라 알림만 보냈습니다. 컨테이너는 계속 동작 중입니다.'];
    const step = (i, title, body) => h('li', { class: `guide-step ${done[i] ? 'done' : ''}`, 'data-step': i + 1, 'data-done': String(done[i]) },
      h('span', { class: 'guide-n', 'aria-hidden': true }, done[i] ? '✓' : String(i + 1)), h('div', { class: 'guide-body' }, h('b', null, title), body));
    return h('section', { class: 'guide-case', 'data-part': 'guide-case-view' },
      list.length > 1 ? h('label', { class: 'guide-pick' }, h('span', { class: 'small muted' }, '건'),
        h('select', { class: 'ctl', 'data-part': 'guide-case', 'aria-label': '건 선택 (최근 5건)', onchange: (e) => { selectedId = e.target.value; draw(true); } },
          list.map((x) => h('option', { value: x.id, selected: x.id === c.id }, `${SRC[x.source]} · ${x.label || x.container} · ${U.LEVEL_LABEL[x.level]} · ${fmt.time(x.openedAt)}`)))) : null,
      h('div', { class: 'guide-head' }, h('b', null, `${SRC[c.source]} · ${c.label || c.container}`), U.verdictBadge(U.fakeVerdict(c.level)), h('span', { class: 'small muted num push-right' }, `${n}/${TOTAL}`)),
      bar(n, TOTAL),
      h('ol', { class: 'guide-steps' },
        step(0, '탐지', h('div', null, h('p', { class: 'small muted num' }, `${fmt.dateTime(firstAt)} · 위반 ${c.violations}건`),
          h('ul', { class: 'rule-chips' }, c.ruleIds.map((id) => h('li', null, h('a', { href: `#/policies?id=${encodeURIComponent(id)}`, class: 'chip mono' }, id)))))),
        step(1, '격리 확인', h('p', { class: 'small' }, h('b', { class: isolation[0] }, isolation[1]), ' — ', h('span', { class: 'muted' }, isolation[2]))),
        step(2, '공격 체인 보기', h('div', { class: 'row-inline' },
          h('a', { ...U.to(link), class: 'link small', 'data-part': 'chain-link', onclick: () => mark({ chain: true }) }, c.source === 'install' ? '설치 검사 시트에서 공격 체인 →' : c.source === 'scan' ? '검사 결과 보기 →' : '토폴로지에서 공격 체인 →'),
          c.source === 'runtime' ? h('a', { ...U.to('#/events', { container: c.container }), class: 'link small', onclick: () => mark({ chain: true }) }, '이벤트 →') : null)),
        step(3, '판정', c.decision === 'pending'
          ? h('div', { class: 'row-inline' }, U.decisionBadge('pending'), h('a', { ...U.to(link), class: 'link small' }, '악성 확정 / 오탐 판정하러 가기 →'))
          : h('div', { class: 'row-inline' }, U.decisionBadge(c.decision), h('span', { class: 'small muted num' }, `${c.decidedBy} · ${fmt.dateTime(c.decidedAt)}`),
            c.state === 'decided' ? h('a', { href: `#/policies?proposal=${c.proposalId}`, class: 'link small' }, '제안 적용 →') : h('span', { class: 'small muted' }, '종결'))),
        step(4, '후속 조치', h('div', null,
          h('ul', { class: 'guide-follow' }, follows.map((f) => h('li', null, h('label', { class: 'check small', 'data-follow': f.hit.join(' '), 'data-group': f.group },
            h('input', { type: 'checkbox', checked: !!p.follow[f.group], onchange: (e) => { const q = gpref(c.id); q.follow[f.group] = e.target.checked; store(gkey(c.id), q); draw(true); } }),
            h('span', null, f.text, ' ', h('span', { class: 'muted mono' }, `(${f.hit.join(', ')})`)))))),
          notifyLine()))));
  }

  // ── 패널 · 탭 · 버튼 ──
  let tab = 'guide', opener = null, lastSig = '';
  const guideEl = h('div', { class: 'guide', 'data-part': 'guide', role: 'tabpanel', id: 'assist-guide', 'aria-labelledby': 'assist-tab-guide' });
  const chatEl = h('div', { class: 'assist-chat', role: 'tabpanel', id: 'assist-chat', 'aria-labelledby': 'assist-tab-chat', hidden: true }, U.chat ? U.chat.el : h('p', { class: 'muted' }, 'AI 도우미를 불러오지 못했습니다.'));
  // AI 꺼짐(/api/info chat=false — 서버에 OLLAMA_URL 없음) 안내 [11/02 결정: 탭은 보이고 이유를 알린다]
  const chatOff = h('div', { class: 'assist-chat-off', 'data-part': 'chat-off', role: 'note' },
    h('b', null, 'AI 도우미가 꺼져 있습니다'),
    h('p', { class: 'small muted' }, '서버에 Ollama(OLLAMA_URL)를 연결하면 켜집니다. 대응 가이드 탭은 그대로 쓸 수 있습니다.'));
  const chatIsOff = () => !!(U.state.info && U.state.info.chat === false);
  const tabBtn = (id, label) => h('button', { type: 'button', role: 'tab', id: `assist-tab-${id}`, 'data-tab': id, 'aria-selected': String(tab === id), 'aria-controls': `assist-${id}`, class: 'assist-tab', onclick: () => show(id) }, label);
  const tabs = h('div', { class: 'assist-tabs', role: 'tablist', 'aria-label': '도우미' }, tabBtn('guide', '대응 가이드'), tabBtn('chat', 'AI 도우미'));
  const panel = h('section', { class: 'assist-panel', 'data-part': 'assistant', role: 'dialog', 'aria-label': 'SupplyGuard 도우미', hidden: true },
    h('header', { class: 'assist-head' }, h('b', null, '🛡 도우미'), h('button', { type: 'button', class: 'btn btn-ghost btn-xs push-right', 'aria-label': '닫기', onclick: () => close() }, '✕')),
    tabs, guideEl, chatEl);
  const badge = h('span', { class: 'assist-badge num', 'data-part': 'assistant-badge', hidden: true });
  const fab = h('button', { type: 'button', class: 'assist-fab', 'data-part': 'assistant-fab', 'aria-label': '도우미 열기', 'aria-expanded': 'false', 'aria-haspopup': 'dialog', onclick: () => (panel.hidden ? open() : close()) }, h('span', { 'aria-hidden': true }, '🛡'), badge);

  function show(id) {
    tab = id;
    for (const b of tabs.querySelectorAll('[role="tab"]')) b.setAttribute('aria-selected', String(b.dataset.tab === id));
    guideEl.hidden = id !== 'guide'; chatEl.hidden = id !== 'chat';
    if (id === 'chat') { const off = chatIsOff(); replace(chatEl, off ? chatOff : (U.chat ? U.chat.el : h('p', { class: 'muted' }, 'AI 도우미를 불러오지 못했습니다.'))); if (!off && U.chat) U.chat.shown(); } else draw(true);
  }
  function open(id) {
    if (panel.hidden) opener = document.activeElement;
    panel.hidden = false; fab.setAttribute('aria-expanded', 'true');
    show(id || tab);
    if (id !== 'chat') setTimeout(() => { const t = tabs.querySelector(`[data-tab="${tab}"]`); if (t) t.focus(); }, 0);
  }
  // silent: 화면 이동으로 닫힐 때 — 포커스를 건드리지 않는다
  function close(silent) {
    if (panel.hidden) return;
    panel.hidden = true; fab.setAttribute('aria-expanded', 'false');
    const back = opener && opener.isConnected && opener !== document.body ? opener : fab; opener = null;
    if (silent !== true) back.focus();
  }
  // 가이드 탭 그리기 — 상태 서명이 바뀔 때만(입력 중인 체크박스 · 드롭다운을 흔들지 않게). force 면 무조건
  function draw(force) {
    const pend = pendingGuides();
    badge.hidden = !pend; badge.textContent = pend; fab.setAttribute('aria-label', pend ? `도우미 열기 — 미완료 가이드 ${pend}건` : '도우미 열기');
    if (panel.hidden || tab !== 'guide') return;
    const list = recentCases();
    const sig = JSON.stringify([list.map((c) => [c.id, c.level, c.decision, c.state, c.violations, c.ruleIds]), selectedId, setupPref, state.source, state.server, list.length ? null : SETUP.map((s) => s.done())]);
    if (!force && sig === lastSig) return;
    lastSig = sig;
    guideEl.dataset.case = list.length ? pickCase(list).id : '';
    replace(guideEl, list.length ? caseView(list) : setupView());
  }

  // 새 건이 열리면 그 건을 고르고 가이드 탭으로 자동 연다(처음 떠 있던 시드 건은 제외).
  // 자동 열림은 대시보드에서만 — 다른 화면에서는 떠 있는 패널이 상세 시트의 판정 칸 · 정책 편집기의 「저장 후 적용」을 가린다(실측, 참고 제품 구축 카드와 같은 규칙).
  // 그 밖의 화면에서는 배지 + 왼쪽 아래 토스트 「가이드 열기」로 알린다
  let known = new Set(state.cases.map((c) => c.id));
  function watch() {
    const fresh = state.cases.filter((c) => !known.has(c.id));
    if (fresh.length) {
      for (const c of fresh) known.add(c.id);
      const c = fresh.find((x) => x.state === 'open');
      if (c) {
        selectedId = c.id;
        if (U.route().path === '/') open('guide');
        else U.toast(`대응 가이드 준비됨 — ${SRC[c.source]} ${c.label || c.container}`, { tone: 'warn', key: `guide:${c.id}`, action: { label: '가이드 열기', run: () => open('guide') } });
      }
    }
    if (U.route().path === '/policies' && !setupPref.visitedPolicies) { setupPref.visitedPolicies = true; saveSetup(); }
    draw();
  }
  function mount() {
    document.body.append(fab, panel);
    U.listeners.add(watch);
    // 화면이 바뀌면 패널을 닫는다(가리지 않게). 배지는 남는다
    window.addEventListener('hashchange', () => { close(true); watch(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !panel.hidden) { e.preventDefault(); close(); } });
    // 가이드 안의 화면 이동 링크를 누르면 패널을 닫는다 — 열린 채 두면 오른쪽 상세 시트의 판정 버튼 · 「적용」을 가린다(실측). 배지가 남아 있어 다시 열 수 있다
    guideEl.addEventListener('click', (e) => { const a = e.target.closest('a[href^="#/"]'); if (a) setTimeout(close, 0); });
    watch();
  }
  // 로그인 뒤 셸이 뜰 때 붙는다 [10/20 A — 로그인 화면 위에 도우미 버튼이 보이지 않게]
  U.whenReady(mount);
  U.assistant = { open, close, show, draw: () => draw(true), FOLLOW, SETUP, progressOf };
})();
