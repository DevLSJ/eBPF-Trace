// SupplyGuard 목업 — 시연 패널 · 상태 신호등 [10/30 계약 §4 · §5]. 대시보드(screens.js) 맨 위에 붙는다 — U.demoPanel() · U.signals().
// 시연 패널: 관리자이고 /api/info.demo 가 true 일 때만(조회자 · demo false 면 카드 없음). 시뮬은 모의 서버 srv.demoRun 이 Run 을 흉내 내고(?demo=off 로 숨김), live 는 GET /api/demo · POST /api/demo/run.
//   단계 레일 6단계 ① 컨테이너 시작(Run.status=running) ② 설치 진행(세션 있음) ③ 커널 이벤트 수집(그 컨테이너 이벤트 1건 이상) ④ 규칙 위반(첫 위반) ⑤ 격리 · 증거(timeline.killedAt 또는 isolated) ⑥ 판정 대기(건 열림)
//   첫 위반이 오면 설치 시트를 자동으로 연다(#/installs?id=<installId>). 2초 폴링(실행 중일 때만) + 기존 스트림. 409 「이미 실행 중」 · 503 · 네트워크 오류는 카드 안 오류 띠 + 「다시 시도」
// 신호등: 알약 5개(가젯 · 도메인 판단 · 자동 격리 · 알림 · 라이선스) 초록 · 노랑 · 빨강 · 회색, 누르면 #/settings(해당 탭). /api/info + GET /api/license(404 = 없음). 시뮬 값은 state.server(info) + ?license=
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, state, fmt } = U;
  const SCENARIOS = [['all', '전부 순서대로'], ['shell', '외부 스크립트 실행 + 비밀 파일 접근'], ['revshell', '리버스 셸 포트 4444'], ['direct-ip', 'DNS 없이 공인 IP 접속'], ['domain', '예약 도메인 example.com 접속'], ['dns-exfil', 'DNS 질의로 데이터 실어 보내기']];
  const STEPS = ['컨테이너 시작', '설치 진행', '커널 이벤트 수집', '규칙 위반', '격리 · 증거', '판정 대기'];
  const POLL_MS = 2000;
  // 패널 상태는 화면을 옮겨도 남는다(대시보드로 돌아오면 마지막 실행 결과)
  let scenario = 'all', run = null, session = null, err = null, openedFor = null, starting = false, busyRetry = false;

  const fail = (e) => { err = e; };
  async function refresh() {
    const d = await U.api.demo();
    run = d.running || d.last || null; err = null;
    session = run && run.installId ? await U.api.install(run.installId).catch(() => null) : null;
  }
  function progress() {
    if (!run) return { done: [false, false, false, false, false, false], active: -1 };
    const events = state.verdicts.filter((v) => v.event.containerName === run.container).length + (session ? Object.values(session.activity.kinds).reduce((n, x) => n + x, 0) : 0);
    const violations = session ? session.violations.length : 0;
    const killed = !!(session && ((session.isolation && session.isolation.timeline && session.isolation.timeline.killedAt) || session.status === 'isolated'));
    const done = [run.status !== 'refused', !!session, events > 0, violations > 0, killed, !!(session && session.caseId)];
    const active = run.status === 'running' ? done.indexOf(false) : -1;
    return { done, active, violations, killed };
  }
  const secs = (a, b) => `${((Date.parse(b) - Date.parse(a)) / 1000).toFixed(1)}초`;
  function resultLine() {
    const p = progress();
    // 문구 · 색은 React DemoPanel.tsx 와 같게(11/02 결정 — React 기준)
    if (run.status === 'refused') return ['refused', '거부됨(차단 목록) — 차단 목록에 있어 설치 전 거부됨, 차단 해제 후 다시'];
    if (run.status === 'timeout') return ['timeout', '시간 초과 — 90초 안에 끝나지 않아 컨테이너를 멈췄습니다'];
    if (run.status === 'failed') return ['failed', `실패${run.exitCode !== null && run.exitCode !== undefined ? ` — 종료 코드 ${run.exitCode}` : ''}`];
    const rules = session ? [...new Set(session.violations.map((v) => v.ruleId))].length : 0;
    if (p.killed) { const tl = session.isolation && session.isolation.timeline; const sec = tl && tl.killedAt ? ((Date.parse(tl.killedAt) - Date.parse(tl.detectedAt)) / 1000).toFixed(2) : null; return ['isolated', `격리됨 — 규칙 ${rules || p.violations}개${sec ? ` · ${sec}초` : ''}`]; }
    if (p.violations) return ['warned', `경고 — 규칙 ${rules || p.violations}개 · 격리 정책에는 걸리지 않음`];
    return ['passed', '통과 — 위반 없음'];
  }

  function demoPanel() {
    if (!U.can() || !state.info || !state.info.demo) return null;
    const root = h('section', { class: 'panel demo-card', 'data-section': 'demo' });
    // 머리 한 줄(React 맞춤 11/02): 제목 · 「시나리오」 선택 · 고른 시나리오 설명 · (오른쪽 끝) 시작 → 실행 중… → 다시 실행
    const DESC = Object.fromEntries(SCENARIOS);
    const desc = h('span', { class: 'small muted demo-desc', 'data-part': 'demo-desc' }, DESC[scenario]);
    const select = h('select', { class: 'ctl demo-scn', 'data-part': 'demo-scenario', onchange: (e) => { scenario = e.target.value; desc.textContent = DESC[scenario]; } }, SCENARIOS.map(([k, d]) => h('option', { value: k, selected: k === scenario }, `${k} — ${d}`)));
    const startBtn = h('button', { type: 'button', class: 'btn btn-primary demo-start', 'data-action': 'demo-start', onclick: () => start() }, '▶ 시연 시작');
    const body = h('div', { class: 'demo-body', hidden: true });
    root.append(h('header', { class: 'panel-head demo-head' }, h('h2', null, '시연'), h('label', { class: 'demo-label small muted', 'data-part': 'demo-label' }, '시나리오', select), desc, startBtn), body);
    let sig = '', timer = 0, pollAt = 0, lastErrKey = '';
    async function start() {
      if (starting) return;
      starting = true; err = null; draw(true);
      try {
        run = await U.api.demoRun({ scenario }); session = null; openedFor = null;
        if (run.status === 'refused') await refresh();
      } catch (e) { fail(e); }
      starting = false; draw(true);
    }
    const retry = () => { err = null; if (run && run.status === 'running') refresh().then(() => draw(true)).catch((e) => { fail(e); draw(true); }); else start(); };
    function draw(force) {
      const p = progress();
      const next = JSON.stringify([run && [run.id, run.status, run.finishedAt], session && [session.status, session.violations.length, session.caseId, session.isolation], p.done, err && err.message, starting, Date.now() - (run && run.status === 'running' ? 0 : 1e12) > 0 ? Math.floor(Date.now() / 500) : 0]);
      if (!force && next === sig) return; sig = next;
      const isRunning = !!(run && run.status === 'running');
      startBtn.disabled = starting || isRunning;
      startBtn.textContent = isRunning || starting ? '↻ 실행 중…' : run ? '↻ 다시 실행' : '▶ 시연 시작';
      select.disabled = startBtn.disabled;
      body.hidden = !run && !err;
      if (body.hidden) { replace(body); return; }
      const errBand = err ? h('div', { class: 'demo-error', role: 'alert', 'data-part': 'demo-error' }, h('span', { class: 'grow' }, err.status === 409 ? '이미 실행 중 — 끝나면 다시 시작할 수 있습니다' : err.status === 503 ? `Docker 에 연결할 수 없습니다 — ${err.message.replace(/^\d+ · /, '')}` : err.unsupported ? err.message : `시연을 시작하지 못했습니다 — ${err.message}`),
        err.status === 409 || err.unsupported ? null : h('button', { type: 'button', class: 'btn btn-outline btn-xs', 'data-action': 'demo-retry', onclick: retry }, '다시 시도')) : null;
      if (!run) { replace(body, errBand); return; }
      const running = run.status === 'running';
      const sec = Math.max(0, Math.round(((running || !run.finishedAt ? Date.now() : Date.parse(run.finishedAt)) - Date.parse(run.startedAt)) / 1000));
      const rail = h('ol', { class: 'rail', 'data-part': 'demo-rail' }, STEPS.map((t, i) => h('li', { 'data-step': i + 1, 'data-state': p.done[i] ? 'done' : p.active === i ? 'active' : 'todo' },
        h('span', { class: 'rail-dot', 'aria-hidden': true }, p.done[i] ? '✓' : String(i + 1)), h('span', { class: 'rail-label' }, t))));
      const tl = session && session.isolation && session.isolation.timeline;
      const res = running ? null : resultLine();
      replace(body, errBand,
        h('div', { class: 'demo-meta small' }, h('span', { class: 'muted' }, `${run.scenario} · `, h('span', { class: 'mono' }, run.container)),
          h('span', { class: `num${running ? ' accent' : ' muted'}`, 'data-part': 'demo-elapsed' }, running ? `실행 중 · ${sec}초 경과` : `${sec}초 걸림`), run.simulated ? h('span', { class: 'badge badge-level-normal' }, '모의 재생') : null, h('span', { class: 'push-right' }),
          run.installId ? h('a', { ...U.to(`#/installs?id=${encodeURIComponent(run.installId)}`, { status: 'all' }), class: 'link', 'data-action': 'demo-install' }, '설치 검사에서 보기 →') : null),
        rail,
        tl ? U.timelineBar(tl, { compact: true }) : null,
        res ? h('p', { class: 'demo-result', 'data-part': 'demo-result', 'data-outcome': res[0] }, res[1]) : null);
    }
    // 첫 위반 → 설치 시트 자동 열림(한 실행에 한 번)
    function autoOpen() {
      if (!run || !run.installId || openedFor === run.id) return;
      if (progress().done[3]) { openedFor = run.id; U.go(`#/installs?id=${encodeURIComponent(run.installId)}`, { status: 'all' }); }
    }
    const tick = () => {
      if (!root.isConnected) { U.listeners.delete(tick); clearInterval(timer); return; }
      if (state.source !== 'live') { // 시뮬: 모의 서버 상태를 바로 본다(데모 제어 · API 로 시작한 실행도 보인다)
        const d = U.srv.demo; const cur = d.running || d.last || null; if (cur && (!run || run.id !== cur.id || run.status !== cur.status || run.finishedAt !== cur.finishedAt)) run = JSON.parse(JSON.stringify(cur));
        if (run && run.installId) { const s = state.installs.find((x) => x.id === run.installId); if (s) session = Object.assign({}, s, { status: window.MOCK.statusOf(s) }); }
        draw(); autoOpen(); return;
      }
      // live: 실행 중 2초 폴링(끝나면 10초 — 다른 곳에서 시작한 실행을 알아채려고)
      const every = run && run.status === 'running' ? POLL_MS : POLL_MS * 5;
      if (Date.now() - pollAt >= every) { pollAt = Date.now(); refresh().then(() => { draw(); autoOpen(); }).catch(fail); return; }
      draw(); autoOpen();
    };
    U.listeners.add(tick);
    timer = setInterval(tick, 500);
    refresh().then(() => draw(true)).catch((e) => { if (!e.unsupported) fail(e); draw(true); });
    draw(true);
    return root;
  }

  // ── 상태 신호등 [10/30 계약 §5] ──
  function signals() {
    const root = h('div', { class: 'signals', 'data-part': 'signals', role: 'group', 'aria-label': '상태 신호등' });
    let lic; // undefined 확인 중 · null 없음(404) · 'unknown' 조회 실패
    const load = () => U.auth.api.getLicense().then((l) => { lic = l; draw(true); }).catch((e) => { lic = e.status === 404 ? null : 'unknown'; draw(true); });
    let sig = '';
    function draw(force) {
      const i = state.info || {}, n = i.notify, A = U.auth;
      // 문구는 React SignalPills.tsx 와 같게(11/02 결정 — 「이름 · 값」 한 문구, 모바일에서도 이름을 숨기지 않는다)
      const g = i.source === 'gadget' ? ['ok', '가젯 · 커널 감시 중'] : i.source === 'mock' ? ['warn', '가젯 · 모의 이벤트'] : ['off', '가젯 · 미확인'];
      const d = i.dnsResolve === 'ok' ? ['ok', '도메인 판단 켜짐'] : i.dnsResolve === 'off' ? ['warn', '도메인 판단 · 통과 처리'] : ['off', '도메인 판단 · 미확인'];
      const k = i.enforceKill === true ? ['ok', '자동 격리 켜짐'] : i.enforceKill === false ? ['warn', '자동 격리 · 알림만'] : ['off', '자동 격리 · 미확인'];
      const nt = !n ? ['off', '알림 · 미확인'] : n.failed > 0 && n.lastError ? ['danger', `알림 · 실패 ${fmt.num(n.failed)}건`] : !n.enabled || !(n.channels || []).length ? ['warn', '알림 · 미설정'] : ['ok', `알림 · 채널 ${n.channels.length}`];
      const lt = lic === undefined || lic === 'unknown' ? ['off', '라이선스 · 미확인'] : lic === null ? ['danger', '라이선스 없음'] : A.licenseTone(lic) === 'danger' ? ['danger', '라이선스 만료'] : [A.licenseTone(lic) === 'warn' ? 'warn' : 'ok', `라이선스 · ${A.daysLeft(lic)}일 남음`];
      const items = [['gadget', g, ''], ['dns', d, ''], ['kill', k, ''], ['notify', nt, ''], ['license', lt, 'license']];
      const next = JSON.stringify(items);
      if (!force && next === sig) return; sig = next;
      replace(root, items.map(([key, [tone, text], tab]) => h('button', { type: 'button', class: `signal tone-${tone}`, 'data-signal': key, 'data-tone': tone, title: `${text} — 설정에서 보기`,
        onclick: () => U.go(`#/settings${tab ? `?tab=${tab}` : ''}`) }, h('i', { class: 'signal-dot', 'aria-hidden': true }), h('span', { class: 'signal-val' }, text))));
    }
    draw(true); load();
    const fn = () => { if (!root.isConnected) { U.listeners.delete(fn); return; } draw(); };
    U.listeners.add(fn);
    return root;
  }

  U.demoPanel = demoPanel; U.signals = signals; U.DEMO_SCENARIO_TEXT = SCENARIOS; U.DEMO_STEPS = STEPS;
})();
