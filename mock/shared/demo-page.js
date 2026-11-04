// SupplyGuard 목업 — 「시연」 페이지(#/demo) [11/04e B — 대시보드 시연 카드를 독립 페이지로]. 녹화 대본 장면 2~4 용 — 1920×1080 한 화면.
//   노출: 관리자 + 서버 시연 켜짐(/api/info.demo) — 대시보드 시연 카드와 같은 조건(사이드바 메뉴도 같은 조건으로 생기고 없어진다)
//   왼쪽 = 시나리오 고르기 + 실행(동시 1개 · 90초 — 실행 중이면 이유) / 가운데 = 실시간 단계 흐름(시작 → 커널 이벤트 → 규칙 판정 → 증거 수집 → 격리 · 통과, 도착 시각 · 직전 대비 ms)
//   오른쪽 = 「왜」 카드: 무엇을(패키지 · 컨테이너 · 프로세스) · 왜(규칙 · 판정 · 조건 · 이벤트 원문 강조 · 연쇄 진행) · 어떻게(증거 · 증거 ms · kill ms) + 보고서 · 정책 링크
// 데이터(sim · live 같은 경로): GET /api/demo(Run.explain — decidedBy · sequence) · GET /api/installs/{installId}(패키지 · 컨테이너 · isolation.timeline · caseId) · GET /api/evidence?container= · 실시간 스트림(그 컨테이너 이벤트)
//   필드가 없으면 그 칸만 「정보 없음」. decidedBy null = 위반 없음(통과)
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, state, fmt } = U;
  // [키, 이름, 한 줄 설명, 예상 결과] — 순서는 백엔드 GET /api/demo scenarios 와 같다
  const SCN = [
    ['all', '전부 순서대로', '아래 다섯 공격을 차례로 — 첫 격리에서 멈춤', 'isolated'],
    ['shell', '외부 스크립트 실행 + 비밀 파일 접근', 'sh -c "wget … | sh" → /etc/shadow', 'isolated'],
    ['revshell', '리버스 셸 포트 4444', 'connect 203.0.113.7:4444', 'isolated'],
    ['direct-ip', 'DNS 없이 공인 IP 접속', 'connect 203.0.113.7:443 · 도메인 조회 없음', 'isolated'],
    ['domain', '예약 도메인 example.com 접속', 'dns example.com → connect :443', 'isolated'],
    ['dns-exfil', 'DNS 질의로 데이터 실어 보내기', '48자 라벨 A 질의 + TXT 질의', 'isolated'],
    ['benign', '정상 설치 대조군', 'pip sg-demo-benign — 위반 없이 통과', 'passed'],
    ['chain', '연쇄 규칙(다운로드 → 연결 → 비밀 파일)', 'wget 실행 → 외부 연결 → /root/.netrc', 'isolated'],
  ];
  const LONG = {
    all: '설치 샌드박스에서 다섯 가지 공격 행동을 차례로 흘립니다. 실제와 같게 첫 격리(kill)에서 멈춥니다.',
    shell: 'post-install 단계에서 셸로 외부 스크립트를 받아 실행하고(| sh) 계정 파일을 엽니다 — 무해한 시뮬(TEST-NET 주소).',
    revshell: '리버스 셸에 흔한 포트 4444 로 나가는 연결을 엽니다(TEST-NET, 연결되지 않음).',
    'direct-ip': '도메인 조회 없이 공인 IP 로 바로 붙습니다 — trace_dns 가 켜져 있으면 directIp 규칙으로 판정합니다.',
    domain: '허용 목록 밖 예약 도메인(example.com)을 질의하고 연결합니다.',
    'dns-exfil': '긴 hex 라벨 · TXT 질의로 데이터를 실어 보내는 패턴(예약 TLD .example)입니다.',
    benign: '정상 패키지를 설치합니다. 정책에 걸리는 행동이 없어 격리 없이 「통과」로 끝나는 모습을 보여 줍니다.',
    chain: '연쇄 규칙 chain-download-secrets(dryRun — 시연용 시험 운영)의 진행을 보여 줍니다. 기본 정책 no-shell-download 가 1단계(wget 실행)에서 먼저 격리하므로 연쇄는 1/3 에서 멈춥니다(연쇄 완성 장면은 따로 녹화).',
  };
  const EXPECT = { isolated: '격리 예상', passed: '통과 예상' };
  const STEPS = [['start', '설치 시작'], ['events', '커널 이벤트'], ['match', '규칙 판정'], ['evidence', '증거 수집'], ['outcome', '결과']];
  // 페이지 상태는 화면을 옮겨도 남는다(돌아오면 마지막 실행)
  let scenario = 'shell';
  const cache = { runId: null, session: null, evidence: undefined, evFor: null };

  const allowed = () => U.can() && !!(state.info && state.info.demo);
  const ms3 = (iso) => { const d = new Date(iso); return `${fmt.time(iso)}.${String(d.getMilliseconds()).padStart(3, '0')}`; };
  const none = (t) => h('span', { class: 'why-none' }, t || '정보 없음');
  const rawOf = (e) => (!e ? '' : e.kind === 'exec' ? e.args || e.comm || '' : e.kind === 'open' ? e.path || '' : e.kind === 'dns' ? `${e.dstHost || ''} (${e.qtype || ''})` : e.dstHost ? `${e.dstIp}:${e.dstPort} (${e.dstHost})` : `${e.dstIp}:${e.dstPort}`);
  // 판정 사유에서 걸린 부분(따옴표 안 · 경로 · 주소 · 이름)을 찾아 원문에서 강조 — 원문에 실제로 있는 가장 긴 조각
  function markRaw(text, reason) {
    const why = String(reason || '').replace(/^[^:]+:\s*/, '');
    const cands = [...why.matchAll(/"([^"]+)"/g)].map((m) => m[1]).concat(why.split(/\s+/).map((t) => t.replace(/^[(「]+|[)」,.]+$/g, '')).filter((t) => t.length >= 3));
    const hit = cands.filter((c) => text.includes(c)).sort((a, b) => b.length - a.length)[0];
    if (!hit) return text;
    const i = text.indexOf(hit);
    return [text.slice(0, i), h('mark', null, hit), text.slice(i + hit.length)];
  }
  const verdictOf = (d) => (!d ? null : d.action !== 'kill' ? 'alert' : d.enforced ? 'killed' : 'held');
  const VERDICT_KO = { killed: '격리', held: '격리 대상(dryRun — 알림만)', alert: '경고' };
  const VERDICT_CLS = { killed: 'badge-level-killed', held: 'badge-level-held', alert: 'badge-level-alert' };

  U.screens['/demo'] = {
    title: '시연',
    mount(page) {
      let run = null, session = null, err = null, starting = false, pollAt = 0, sig = '', alive = true;
      const root = h('div', { class: 'demo-host' });
      page.append(root);
      const tick = () => { if (!alive) return; poll(); };
      const timer = setInterval(tick, 400);
      async function refresh() {
        const d = await U.api.demo();
        run = d.running || d.last || null; err = err && err.status === 409 && run && run.status === 'running' ? err : null;
        if (run && cache.runId !== run.id) { cache.runId = run.id; cache.session = null; cache.evidence = undefined; cache.evFor = null; }
        session = run && run.installId ? await U.api.install(run.installId).catch(() => cache.session) : null;
        cache.session = session;
        // 증거: 격리된 실행만 · 끝난 뒤 한 번(GET /api/evidence?container=) — 없거나 실패면 undefined → 「정보 없음」
        if (run && run.status !== 'running' && cache.evFor !== run.id && session && session.status === 'isolated') {
          cache.evFor = run.id;
          U.api.evidence(run.container).then((list) => { cache.evidence = (list || []).find((x) => !session.containerId || x.containerId === session.containerId) || (list || [])[0] || null; draw(true); }).catch(() => { cache.evidence = null; draw(true); });
        }
      }
      function poll() {
        if (!allowed()) { draw(); return; }
        const every = state.source === 'live' ? (run && run.status === 'running' ? 1000 : 5000) : 400;
        if (Date.now() - pollAt < every) { draw(); return; }
        pollAt = Date.now();
        refresh().then(() => draw()).catch((e) => { if (!e.unsupported) err = e; draw(); });
      }
      async function start() {
        if (starting || (run && run.status === 'running')) return;
        starting = true; err = null; draw(true);
        try { run = await U.api.demoRun({ scenario }); cache.runId = run.id; cache.session = null; cache.evidence = undefined; cache.evFor = null; session = null; await refresh(); }
        catch (e) { err = e; if (e.status === 409) await refresh().catch(() => {}); }
        starting = false; pollAt = Date.now(); draw(true);
      }
      // 그 컨테이너의 이벤트(실시간 스트림) — 시간 순. 스트림에 없으면 세션의 위반 이벤트로
      function events() {
        if (!run) return [];
        const vs = state.verdicts.filter((v) => v.event.containerName === run.container).slice().reverse();
        if (vs.length) return vs;
        return session ? session.violations.map((v) => Object.assign({}, v)) : [];
      }
      function model() {
        const x = run && run.explain, dec0 = x ? x.decidedBy : undefined;
        const dec = dec0 === null && run && run.status === 'running' ? undefined : dec0; // 실행 중 null = 아직 판정 없음(통과는 끝난 뒤에만)
        const fallback = session && session.violations.length ? session.violations.find((v) => v.enforced) || session.violations[0] : null;
        const d = dec !== undefined ? dec : fallback ? { ruleId: fallback.ruleId, action: fallback.action, dryRun: !!fallback.dryRun, enforced: !!fallback.enforced, reason: fallback.reason, event: fallback.event } : run && run.status !== 'running' && session ? null : undefined;
        const tl = session && session.isolation && session.isolation.timeline;
        const running = !!(run && run.status === 'running');
        const evs = events();
        const count = session ? Object.values(session.activity.kinds).reduce((n, k) => n + k, 0) : evs.length;
        const lv = verdictOf(d);
        const outcome = !run ? null : running ? 'running' : run.status === 'refused' ? 'refused' : run.status === 'timeout' ? 'timeout' : run.status === 'failed' ? 'failed'
          : lv === 'killed' || (session && session.status === 'isolated') ? 'isolated' : lv === 'held' ? 'detected' : lv === 'alert' ? 'warned' : 'passed';
        return { x, d, tl, running, evs, count, lv, outcome, seq: x ? x.sequence : null };
      }
      function stepsOf(m) {
        const fin = run && !m.running;
        const at = (iso) => (iso && !Number.isNaN(Date.parse(iso)) ? iso : null);
        const out = [];
        out.push({ key: 'start', at: run ? at(run.startedAt) : null, state: run ? 'done' : 'todo', body: run ? h('span', { class: 'mono' }, run.container) : null });
        const first = m.evs[0] ? m.evs[0].event.timestamp : null;
        out.push({ key: 'events', at: at(first), state: m.count ? 'done' : m.running ? 'active' : fin ? 'done' : 'todo', body: eventsBody(m) });
        let match;
        if (m.d) match = { at: at((m.tl && m.tl.matchedAt) || (m.d.event && m.d.event.timestamp)), state: 'done', body: [h('code', { class: 'mono' }, m.d.ruleId), ' ', h('span', { class: `badge ${VERDICT_CLS[m.lv]}` }, VERDICT_KO[m.lv])] };
        // 통과: 마지막 이벤트까지 모두 판정한 시각
        else if (m.d === null && fin) match = { at: at((m.evs[m.evs.length - 1] || { event: {} }).event.timestamp || run.finishedAt), state: 'done', body: h('span', { class: 'tone-ok' }, '위반 없음 — 설치 중 행동이 모든 정책을 통과') };
        else match = { at: null, state: m.running && m.count ? 'active' : fin ? 'done' : 'todo', body: fin ? none() : h('span', { class: 'muted' }, '판정 기다리는 중') };
        out.push(Object.assign({ key: 'match' }, match));
        const evMs = m.tl && m.tl.evidenceDoneAt && m.tl.evidenceStartedAt ? Date.parse(m.tl.evidenceDoneAt) - Date.parse(m.tl.evidenceStartedAt) : null;
        if (m.tl && m.tl.evidenceDoneAt) out.push({ key: 'evidence', at: at(m.tl.evidenceDoneAt), state: 'done', body: h('span', null, `로그 · 파일 변경 · 프로세스 — ${fmt.num(evMs)} ms`) });
        else if (fin && m.outcome !== 'isolated') out.push({ key: 'evidence', at: null, state: 'skip', body: h('span', { class: 'muted' }, m.d ? '건너뜀 — 격리하지 않아 모으지 않음' : '건너뜀 — 위반 없음') });
        else out.push({ key: 'evidence', at: null, state: fin ? 'done' : m.lv === 'killed' ? 'active' : 'todo', body: fin ? none() : null });
        const oc = m.outcome;
        const ocAt = oc === 'isolated' ? at((m.tl && m.tl.killedAt) || run.finishedAt) : fin ? at(run.finishedAt) : null;
        const ocText = { isolated: `격리(kill)${run && run.exitCode != null ? ` — 종료 코드 ${run.exitCode}` : ''}`, passed: `통과${run && run.exitCode != null ? ` — 종료 코드 ${run.exitCode}` : ''}`, detected: '탐지(격리 안 함 — 시연용 dryRun)', warned: '경고 — 격리 정책에는 걸리지 않음', refused: '거부 — 차단 목록', timeout: '시간 초과 — 90초', failed: '실패' }[oc];
        out.push({ key: 'outcome', at: ocAt, state: fin ? 'done' : m.lv === 'killed' ? 'active' : 'todo', body: ocText ? h('span', { class: `oc-${oc}` }, ocText) : null });
        let prev = null;
        for (const s of out) { if (s.at) { s.delta = prev != null ? Math.max(0, Date.parse(s.at) - prev) : null; prev = Date.parse(s.at); } }
        return out;
      }
      function eventsBody(m) {
        const lines = m.evs.slice(-6);
        return h('div', { class: 'ev-box' },
          h('div', { class: 'ev-count', 'data-part': 'event-count' }, h('b', { class: 'num' }, fmt.num(m.count)), '건', m.running ? h('i', { class: 'live-dot', 'aria-hidden': true }) : null),
          lines.length ? h('ol', { class: 'ev-lines', 'data-part': 'event-lines' }, lines.map((v) => h('li', { class: v.matched ? 'hit' : '' },
            h('span', { class: 'num mono muted' }, ms3(v.event.timestamp)), U.kindBadge(v.event.kind), h('span', { class: 'mono ev-comm' }, v.event.comm || ''), h('span', { class: 'mono ev-raw', title: rawOf(v.event) }, rawOf(v.event)),
            v.matched ? U.verdictBadge(v) : null))) : h('p', { class: 'small muted' }, m.running ? '첫 이벤트를 기다리는 중…' : '이벤트 없음'));
      }
      function scenarioCol() {
        const isRunning = !!(run && run.status === 'running');
        const sec = isRunning ? Math.max(0, Math.round((Date.now() - Date.parse(run.startedAt)) / 1000)) : 0;
        const note = isRunning ? `실행 중 — 동시 1개 · 최대 90초(${sec}초 경과). 끝나면 다시 시작할 수 있습니다.` : '한 번에 하나만 · 90초 안에 끝나지 않으면 멈춥니다. 컨테이너는 끝나면 지웁니다.';
        const errBand = err ? h('div', { class: 'demo-error', role: 'alert', 'data-part': 'demo-error' }, h('span', { class: 'grow' }, err.status === 409 ? '이미 실행 중 — 끝나면 다시 시작할 수 있습니다' : err.status === 503 ? `Docker 에 연결할 수 없습니다 — ${err.message.replace(/^\d+ · /, '')}` : err.unsupported ? err.message : `시연을 시작하지 못했습니다 — ${err.message}`)) : null;
        return U.panel({ title: '시나리오', sub: run && run.simulated ? '모의 재생' : '설치 샌드박스', attrs: { 'data-col': 'scenarios' }, class: 'demo-col', body: h('div', { class: 'demo-col-body', 'data-fill': '' },
          h('ul', { class: 'scn-list', role: 'list' }, SCN.map(([k, ko, desc, exp]) => h('li', null, h('button', { type: 'button', class: `scn-item ${scenario === k ? 'on' : ''}`, 'data-scenario': k, 'aria-pressed': String(scenario === k), disabled: isRunning || starting || null, onclick: () => { scenario = k; draw(true); } },
            h('span', { class: 'scn-top' }, h('b', null, ko), h('span', { class: `scn-expect exp-${exp}`, 'data-part': 'expect', 'data-expect': exp }, EXPECT[exp])),
            h('span', { class: 'small muted mono scn-desc' }, desc))))),
          h('p', { class: 'scn-long small', 'data-part': 'scenario-desc' }, LONG[scenario]),
          h('div', { class: 'run-box' },
            h('button', { type: 'button', class: 'btn btn-primary run-btn', 'data-action': 'demo-run', disabled: isRunning || starting || null, onclick: start }, isRunning || starting ? '↻ 실행 중…' : '▶ 시연 시작'),
            h('p', { class: 'small muted', 'data-part': 'run-note' }, note), errBand)) });
      }
      function flowCol(m, steps) {
        const sec = run ? Math.max(0, Math.round(((m.running || !run.finishedAt ? Date.now() : Date.parse(run.finishedAt)) - Date.parse(run.startedAt)) / 1000)) : 0;
        const SC = Object.fromEntries(SCN.map((x) => [x[0], x[1]]));
        const oc = m.outcome;
        const seq = m.seq;
        const seqLine = seq && !seq.completed && oc === 'isolated' ? `기본 정책이 1단계에서 먼저 막음 · 연쇄 진행 ${seq.steps.filter((s) => s.matched).length}/${seq.steps.length}(dryRun 연쇄 규칙 ${seq.ruleId})` : null;
        const OC = { running: `실행 중 · ${sec}초 경과`, isolated: `격리됨 — ${m.d ? m.d.ruleId : '규칙'}${m.tl && m.tl.killedAt ? ` · 탐지→kill ${fmt.num(Date.parse(m.tl.killedAt) - Date.parse(m.tl.detectedAt))} ms` : ''}`, passed: '통과 — 위반 없음(대조군)', detected: '탐지(격리 안 함 — 시연용 dryRun)', warned: '경고 — 격리 정책에는 걸리지 않음', refused: '거부됨(차단 목록) — 차단 목록에 있어 설치 전 거부됨, 차단 해제 후 다시', timeout: '시간 초과 — 90초 안에 끝나지 않아 멈춤', failed: `실패${run && run.exitCode != null ? ` — 종료 코드 ${run.exitCode}` : ''}` };
        return U.panel({ title: '실시간 단계', sub: run ? `${SC[run.scenario] || run.scenario} · ${sec}초` : '시나리오를 고르고 시작하세요', attrs: { 'data-col': 'flow' }, class: 'demo-col', body: h('div', { class: 'demo-col-body', 'data-fill': '' },
          h('ol', { class: 'flow', 'data-part': 'demo-steps' }, STEPS.map(([k, ko], i) => { const s = steps.find((x) => x.key === k);
            return h('li', { 'data-step': k, 'data-state': s.state, 'data-at': s.at || '', 'data-delta-ms': s.delta == null ? '' : String(s.delta) },
              h('span', { class: 'flow-dot', 'aria-hidden': true }, s.state === 'done' ? '✓' : s.state === 'skip' ? '–' : String(i + 1)),
              h('div', { class: 'flow-main' }, h('div', { class: 'flow-head' }, h('b', null, k === 'start' && run && !run.installId ? '컨테이너 시작' : ko),
                h('span', { class: 'flow-time num mono', 'data-part': 'step-at' }, s.at ? ms3(s.at) : ''), h('span', { class: 'flow-delta num', 'data-part': 'step-delta' }, s.delta == null ? '' : `+${fmt.num(s.delta)} ms`)),
                s.body ? h('div', { class: 'flow-body' }, s.body) : null)); })),
          oc ? h('div', { class: `demo-outcome oc-${oc}`, 'data-part': 'demo-outcome', 'data-outcome': oc }, h('b', null, OC[oc] || oc), seqLine ? h('span', { class: 'small', 'data-part': 'seq-line' }, seqLine) : null) : null) });
      }
      function whyCol(m) {
        const d = m.d, s = session, ev = d && d.event;
        const title = !run ? '왜' : m.outcome === 'passed' ? '왜 통과했나' : m.outcome === 'isolated' ? '왜 격리됐나' : '왜';
        const row = (k, v) => [h('dt', null, k), h('dd', null, v)];
        const what = h('section', { class: 'why-sec', 'data-why': 'what' }, h('h3', null, '무엇을'), h('dl', { class: 'dl tight why-dl' },
          row('패키지', s ? h('span', { class: 'mono' }, `${s.manager} ${(s.packages || []).join(' ')}`) : none()),
          row('컨테이너', run ? h('span', { class: 'mono' }, run.container, s && s.containerId ? h('span', { class: 'muted' }, ` · ${fmt.shortId(s.containerId)}`) : null) : none()),
          row('프로세스', ev ? h('span', { class: 'mono' }, `${ev.comm || '?'} · pid ${ev.pid != null ? ev.pid : '?'}`) : d === null ? '—' : none())));
        let whyBody;
        if (!run) whyBody = h('p', { class: 'small muted' }, '실행하면 판정을 만든 규칙과 이벤트가 여기에 나옵니다.');
        else if (d === null) whyBody = h('p', { class: 'why-pass' }, '걸린 규칙 없음 — 설치하는 동안 정책에 걸린 행동이 없었습니다(정상 대조군).');
        else if (d === undefined) whyBody = m.running ? h('p', { class: 'small muted' }, '판정 기다리는 중…') : none();
        else {
          const raw = rawOf(ev);
          whyBody = [h('div', { class: 'why-rule-line' }, h('code', { class: 'mono why-rule', 'data-part': 'why-rule' }, d.ruleId), h('span', { class: `badge ${VERDICT_CLS[m.lv]}` }, VERDICT_KO[m.lv])),
            d.description ? h('p', { class: 'small muted' }, d.description) : null,
            h('p', { class: 'why-cond', 'data-part': 'why-condition' }, d.condition ? d.condition : none('조건 — 정보 없음')),
            ev ? h('div', { class: 'why-event', 'data-part': 'why-event' }, U.kindBadge(ev.kind), h('code', { class: 'mono' }, markRaw(raw, d.reason)), ev.timestamp ? h('span', { class: 'small muted num' }, ms3(ev.timestamp)) : null) : none(),
            d.reason ? h('p', { class: 'small muted mono why-reason' }, d.reason) : null];
        }
        const seq = m.seq;
        const seqEl = seq ? h('div', { class: 'why-seq', 'data-part': 'seq' },
          h('div', { class: 'why-seq-head' }, h('b', null, `연쇄 ${seq.ruleId}`), h('span', { class: 'badge badge-level-held' }, seq.dryRun ? 'dryRun' : seq.action), h('span', { class: 'small muted' }, `${seq.windowSeconds}초 안 · 진행 ${seq.steps.filter((x) => x.matched).length}/${seq.steps.length}${seq.completed ? ' · 완성' : ''}`)),
          h('ol', { class: 'seq-steps', 'data-part': 'seq-steps' }, seq.steps.map((st, i) => h('li', { 'data-kind': st.kind, 'data-matched': String(!!st.matched), class: st.matched ? 'on' : '' },
            h('span', { class: `step-no step-${st.kind}` }, `${i + 1} ${U.KIND_SHORT[st.kind] || st.kind}`),
            h('span', { class: 'seq-main' }, h('span', { class: 'small' }, st.condition || ''), st.event ? h('code', { class: 'mono small' }, st.event.detail || '') : h('span', { class: 'small muted' }, '아직 — 이어지지 않음')),
            h('span', { class: 'small num muted', 'data-part': 'seq-gap' }, st.gapMs != null ? `+${(st.gapMs / 1000).toFixed(1)}초` : ''))))) : null;
        // 어떻게: 증거 · ms
        const tl = m.tl, killed = m.outcome === 'isolated';
        const evx = cache.evidence;
        let evEl;
        if (!killed) evEl = h('p', { class: 'small muted' }, m.running ? '격리되면 kill 직전에 모읍니다' : '격리하지 않아 증거를 모으지 않았습니다');
        else if (evx === undefined && run && run.status === 'running') evEl = h('p', { class: 'small muted' }, '모으는 중…');
        else if (!evx) evEl = none('증거 — 정보 없음');
        else {
          const logs = String(evx.logs || '').split('\n').filter(Boolean);
          evEl = h('ul', { class: 'ev-list' },
            h('li', { 'data-ev': 'logs' }, h('b', null, '로그'), h('span', { class: 'num' }, ` ${logs.length}줄`), logs.length ? h('code', { class: 'mono small', title: logs[logs.length - 1] }, logs[logs.length - 1]) : null),
            h('li', { 'data-ev': 'changes' }, h('b', null, '파일 변경'), h('span', { class: 'num' }, ` ${(evx.changes || []).length}`), (evx.changes || [])[0] ? h('code', { class: 'mono small' }, `${evx.changes[0].kind} ${evx.changes[0].path}`) : null),
            h('li', { 'data-ev': 'processes' }, h('b', null, '프로세스'), h('span', { class: 'num' }, ` ${(evx.processes || []).length}`), (evx.processes || []).length ? h('code', { class: 'mono small' }, evx.processes[evx.processes.length - 1].cmd) : h('span', { class: 'small muted' }, evx.partial ? '모으지 못함(예산 0.7초 초과)' : '없음')));
        }
        const evMs = tl && tl.evidenceDoneAt && tl.evidenceStartedAt ? Date.parse(tl.evidenceDoneAt) - Date.parse(tl.evidenceStartedAt) : null;
        const killMs = tl && tl.killedAt && tl.detectedAt ? Date.parse(tl.killedAt) - Date.parse(tl.detectedAt) : null;
        const msRow = h('div', { class: 'why-ms' },
          h('span', { 'data-part': 'evidence-ms' }, '증거 수집 ', evMs != null ? h('b', { class: 'num' }, `${fmt.num(evMs)} ms`) : killed ? none() : '—'),
          h('span', { 'data-part': 'kill-ms' }, '탐지 → kill ', killMs != null ? h('b', { class: 'num' }, `${fmt.num(killMs)} ms`) : killed ? none() : '—'));
        const caseId = s && s.caseId;
        const links = run ? h('div', { class: 'row-actions why-links' },
          caseId || run.installId ? h('a', { href: caseId ? `#/report?case=${encodeURIComponent(caseId)}` : `#/report?install=${encodeURIComponent(run.installId)}`, class: 'btn btn-ghost btn-xs', 'data-action': 'open-report' }, '▤ 건 보고서 열기') : null,
          d && d.ruleId ? h('a', { href: `#/policies?id=${encodeURIComponent(d.ruleId)}`, class: 'btn btn-ghost btn-xs', 'data-action': 'open-policy' }, '§ 정책에서 이 규칙 보기') : null) : null;
        return U.panel({ title, sub: run ? (run.simulated ? '모의 재생 결과' : '실제 실행 결과') : '', attrs: { 'data-col': 'why' }, class: 'demo-col', body: h('div', { class: 'demo-col-body', 'data-fill': '', 'data-part': 'why' }, what,
          h('section', { class: 'why-sec', 'data-why': 'why' }, h('h3', null, '왜'), whyBody, seqEl),
          h('section', { class: 'why-sec', 'data-why': 'how' }, h('h3', null, '어떻게'), h('div', { 'data-part': 'why-evidence' }, evEl), msRow), links) });
      }
      function draw(force) {
        if (!alive) return;
        if (!allowed()) {
          const s0 = 'denied';
          if (sig !== s0) { sig = s0; replace(root, U.emptyState({ icon: '▶', title: '시연을 쓸 수 없습니다', hint: '관리자 계정이고 서버에서 시연(DEMO_ENABLED)을 켰을 때만 씁니다.' })); }
          return;
        }
        const m = model();
        const next = JSON.stringify([scenario, run && [run.id, run.status, run.finishedAt, run.explain], session && [session.status, session.violations.length, session.caseId, session.isolation, session.activity.kinds], m.evs.length, cache.evidence === undefined ? 'u' : !!cache.evidence, err && err.message, starting, m.running ? Math.floor(Date.now() / 1000) : 0]);
        if (!force && next === sig) return; sig = next;
        const steps = stepsOf(m);
        replace(root, h('div', { class: 'demo-page', 'data-part': 'demo-page' }, scenarioCol(), flowCol(m, steps), whyCol(m)));
      }
      U.listeners.add(tick);
      refresh().then(() => draw(true)).catch((e) => { if (!e.unsupported) err = e; draw(true); });
      draw(true);
      return { update: () => draw(), unmount() { alive = false; clearInterval(timer); U.listeners.delete(tick); } };
    },
  };
})();
