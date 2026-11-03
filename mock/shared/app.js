// SupplyGuard 목업 — 셸(사이드바·상단바) · 해시 라우터 · 공통 컴포넌트 · 실시간 시뮬레이션.
// React 앱(frontend/src)의 useEventStream + AppShell + components 를 바닐라 JS 로 옮긴 것.
(function () {
  'use strict';
  const M = window.MOCK;

  // ── DOM 헬퍼 ────────────────────────────────────────────
  function append(el, children) {
    for (const c of children.flat(Infinity)) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : String(c));
    }
  }
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style') el.style.cssText = v;
      else if (k === 'html') el.innerHTML = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'value') el.value = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    append(el, children);
    return el;
  }
  const NS = 'http://www.w3.org/2000/svg';
  function s(tag, attrs, ...children) {
    const el = document.createElementNS(NS, tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) if (v != null && v !== false) el.setAttribute(k, v);
    append(el, children);
    return el;
  }
  const $ = (sel, root) => (root || document).querySelector(sel);
  // replaceChildren 은 배열을 받지 않으므로(문자열로 바뀜) 항상 이 헬퍼로 자식을 갈아끼운다
  function replace(el, ...children) { el.replaceChildren(); append(el, children); }

  const timeFmt = new Intl.DateTimeFormat('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  const dateTimeFmt = new Intl.DateTimeFormat('ko-KR', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  const numFmt = new Intl.NumberFormat('ko-KR');
  const fmt = {
    time: (iso) => timeFmt.format(new Date(iso)),
    dateTime: (iso) => dateTimeFmt.format(new Date(iso)),
    num: (n) => numFmt.format(n),
    shortId: (id) => (id || '').slice(0, 12),
  };

  const KINDS = ['exec', 'open', 'connect', 'dns']; // dns [10/30 계약 §1] — 질의만, 상세 「<이름> (<질의 유형>)」
  // sequence [11/04]: 규칙에만 있는 kind(연쇄 규칙) — 이벤트 kind 가 아니라 KINDS(필터 · 이벤트 검증)에는 넣지 않는다
  const KIND_LONG = { exec: '실행', open: '파일', connect: '통신', dns: '도메인 조회', sequence: '연쇄' }; // 긴 이름(필터 · 배지 제목)
  const KIND_SHORT = { exec: '실행', open: '파일', connect: '통신', dns: '조회', sequence: '연쇄' }; // 짧은 라벨(정책 목록 · 타일 · 종합)
  const LEVEL_LABEL = { normal: '정상', alert: '경고', held: '격리 대상', killed: '격리됨' };
  const INSTALL_STATUS = { isolated: '격리', warned: '경고', passed: '통과', failed: '설치 실패', unknown: '결과 미확인', running: '진행 중', refused: '설치 전 거부' };
  // 용어 [10/15 목표]: 엔진이 내리는 것은 「탐지 결과」(LEVEL_LABEL), 사람이 내리는 것은 「판정」(DECISION_LABEL)
  const DECISION_LABEL = { pending: '판정 대기', malicious: '악성', false_positive: '오탐', none: '건 없음' };
  const ACTOR = '보안 담당자'; // 처리자 — 데모 계정 하나 (백엔드 설정 ACTOR_NAME 기본값)
  // 처리자 = 로그인한 계정의 이름 [10/20 A]. 시드 · 로그인 전은 ACTOR
  const actor = () => (window.UI && UI.state.auth && UI.state.auth.user && UI.state.auth.user.displayName) || ACTOR;
  const SANDBOX = 'sg-install-';
  const LIST_LABEL = { packages: '패키지', images: '이미지', hosts: '도메인' };
  // 건의 출처 · 링크 — 한 곳에서만 [10/20 J — React 와 같게]. 공급망 검사 건은 런타임 · 토폴로지가 아니라 검사 결과로
  const CASE_SOURCE = { install: '설치 검사', runtime: '런타임', scan: '공급망 검사' };
  const topoLink = (name) => ({ href: `#/topology?node=${encodeURIComponent(`c:${name}`)}`, state: { container: name } }); // 토폴로지: 컨테이너 노드(c:)는 주소, 컨테이너 필터는 상태
  // → { href, state } — 주소에는 링크용 값(id · node)만, 필터(설치 「전체」 · 토폴로지 컨테이너)는 상태로 [10/21b]. <a> 는 U.to(link), 이동은 U.go(link.href, link.state)
  const caseLink = (c, all) => (c.source === 'install' ? { href: `#/installs?id=${c.installId}`, state: all ? { status: 'all' } : null } : c.source === 'scan' ? { href: `#/scans?id=${c.scanId}` }
    : topoLink(c.container));
  const levelOf = (v) => (!v.matched ? 'normal' : v.action !== 'kill' ? 'alert' : v.enforced ? 'killed' : 'held');
  const detailOf = (e) => (e.kind === 'exec' ? e.args || e.comm : e.kind === 'open' ? e.path || '' : e.kind === 'dns' ? `${e.dstHost || ''} (${e.qtype || ''})` : e.dstHost ? `${e.dstIp}:${e.dstPort} (${e.dstHost})` : `${e.dstIp}:${e.dstPort}`);

  // ── 토폴로지 저장소 (frontend/src/lib/topology.ts) ──────
  const SEV = { normal: 0, alert: 1, held: 2, killed: 3 };
  const worse = (a, b) => (SEV[b] > SEV[a] ? b : a);
  class TopologyStore {
    constructor() { this.nodes = new Map(); this.edges = new Map(); }
    ingest(v) {
      const e = v.event; if (!e.containerName || e.containerName.startsWith(SANDBOX)) return; // 토폴로지는 런타임만 [10/15 목표]
      const now = new Date(e.timestamp).getTime() || Date.now();
      const level = levelOf(v);
      const c = this.touch(`c:${e.containerName}`, 'container', e.containerName, e.containerName, level, now, v);
      const p = this.touch(`p:${e.containerName}:${e.comm}`, 'process', e.comm, e.containerName, level, now, v);
      this.link(c.id, p.id, 'exec', level, now, v);
      if (e.kind === 'open' && e.path) { const f = this.touch(`f:${e.containerName}:${e.path}`, 'file', e.path, e.containerName, level, now, v); this.link(p.id, f.id, 'open', level, now, v); }
      else if (e.kind === 'connect') { const key = `${e.dstIp}:${e.dstPort}`; const label = e.dstHost ? `${e.dstHost}:${e.dstPort}` : key; const dn = this.touch(`d:${e.containerName}:${key}`, 'dest', label, e.containerName, level, now, v); if (e.dstHost) dn.label = label; this.link(p.id, dn.id, 'connect', level, now, v); }
      // DNS 질의 [10/30]: 목적지 노드처럼 그리되 kind 칩은 dns — 공격 체인에서는 「3 통신」 단계(connect 와 같은 단계, dns 먼저)
      else if (e.kind === 'dns' && e.dstHost) { const dn = this.touch(`q:${e.containerName}:${e.dstHost}:${e.qtype || ''}`, 'dest', detailOf(e), e.containerName, level, now, v); dn.dns = true; this.link(p.id, dn.id, 'dns', level, now, v); }
    }
    // mark: 횟수·최악 판정을 누적하고, 위반이면 kind 별 최악 판정(byKind)·규칙별 횟수(rules)·규칙의 kind(ruleKinds)를 기록한다.
    mark(x, level, now, v) {
      x.count++; x.level = worse(x.level, level); x.lastSeen = Math.max(x.lastSeen, now);
      if (!v.matched) return;
      const k = v.event.kind;
      x.violations++; x.rules.set(v.ruleId, (x.rules.get(v.ruleId) || 0) + 1); x.ruleKinds.set(v.ruleId, k);
      x.byKind[k] = worse(x.byKind[k] || 'normal', level);
      if (SEV[level] >= SEV[x.worstLevel || 'normal']) { x.worstLevel = level; x.reason = v.reason; x.lastViolation = now; }
    }
    touch(id, type, label, container, level, now, v) {
      let n = this.nodes.get(id);
      if (!n) { n = { id, type, label, container, level: 'normal', count: 0, violations: 0, rules: new Map(), ruleKinds: new Map(), byKind: {}, lastSeen: now }; this.nodes.set(id, n); }
      this.mark(n, level, now, v); return n;
    }
    link(source, target, kind, level, now, v) {
      const id = `${source}->${target}`;
      let ed = this.edges.get(id);
      if (!ed) { ed = { id, source, target, kind, level: 'normal', count: 0, violations: 0, rules: new Map(), ruleKinds: new Map(), byKind: {}, lastSeen: now }; this.edges.set(id, ed); }
      this.mark(ed, level, now, v);
    }
    snapshot(windowMs, container) {
      const now = Date.now(); const cut = now - windowMs;
      for (const [id, n] of this.nodes) if (now - n.lastSeen > 15 * 60000) this.nodes.delete(id);
      for (const [id, e] of this.edges) if (now - e.lastSeen > 15 * 60000) this.edges.delete(id);
      const leaves = new Map(), keep = new Set();
      for (const n of this.nodes.values()) {
        if (n.lastSeen < cut || (container && n.container !== container)) continue;
        if ((n.type === 'file' || n.type === 'dest') && n.level === 'normal') { const a = leaves.get(n.container) || []; a.push(n); leaves.set(n.container, a); continue; }
        keep.add(n.id);
      }
      for (const a of leaves.values()) { a.sort((x, y) => y.count - x.count); a.slice(0, 6).forEach((n) => keep.add(n.id)); }
      const edges = [...this.edges.values()].filter((e) => e.lastSeen >= cut && keep.has(e.source) && keep.has(e.target));
      const linked = new Set(edges.flatMap((e) => [e.source, e.target]));
      const nodes = [...keep].map((id) => this.nodes.get(id)).filter((n) => n.type === 'container' || linked.has(n.id));
      return { nodes, edges };
    }
    containers() { return [...this.nodes.values()].filter((n) => n.type === 'container').map((n) => n.label).sort(); }
  }

  // ── 상태 ────────────────────────────────────────────────
  const params = new URLSearchParams(location.search);
  const saved = (k, d) => { try { return localStorage.getItem(k) || d; } catch { return d; } };
  // ?fresh=1 — 빈 서버(설치 검사 · 감사 기록 없음). 처음 구축 흐름 · 빈 상태 시연용
  const fresh = params.get('fresh') === '1';
  const now0 = Date.now();
  const installs0 = fresh ? [] : M.buildInstalls(now0);
  const state = {
    // source: 'sim'(내장 시뮬레이션) | 'live'(실제 백엔드 REST+WS). ?source=live&api=http://127.0.0.1:8000 또는 데모 제어에서 바꾼다
    source: params.get('source') || saved('supplyguard.mock.source', 'sim'),
    apiBase: (params.get('api') || saved('supplyguard.mock.api', 'http://127.0.0.1:8000')).replace(/\/$/, ''),
    liveError: '',
    connected: true, paused: false, verdicts: [], unseen: 0, // 관리자 토큰 칸은 없앴다 — 쓰기는 로그인 역할(쿠키 세션)만 [10/20 결정 1]
    rules: JSON.parse(JSON.stringify(M.rules)),
    info: null, // 아래 simInfo() — /api/info 와 같은 모양
    stats: null, audit: fresh ? [] : M.buildAudit(now0, installs0), topology: new TopologyStore(),
    installs: installs0, installSeq: installs0.length, scans: [],
    // 판정 흐름 [10/15 목표] — 모의 서버가 들고 있는 건 · 제안 · 차단 목록 · 변경 이력 (API 계약 「데이터 모양」)
    cases: [], proposals: [], changes: [], blocklist: { packages: [], images: [], hosts: [] },
    seq: { case: 0, prop: 0, chg: 0, scan: 0 },
    // 서버 상태 모의 값 [10/20 도우미] — notify: 'webhook' | 'none', dnsResolve: 'on' | 'off'(trace_dns 가 안 떠 도메인 규칙 통과). 실제 백엔드에는 아직 없어 undefined(「미확인」)
    server: {},
    // 10/20 2차 시안: 로그인 세션(auth.js) · 이벤트 첫 로드 상태 · 끊긴 동안 채운 수 · 증거(kill 직전, 컨테이너 이름 → 최근 것부터)
    auth: null, eventsReady: false, eventsError: null, backfill: null, evidence: new Map(),
  };
  // 시뮬 서버의 /api/info [10/20 H] — notify(웹훅 · Slack 채널 상태) · discovery(fanotify | docker-events) · dnsResolve(ok | off).
  //   ?notify=off(채널 없음) · ?notify=fail(웹훅 실패 3회) · ?dns=off · ?discovery=fanotify
  const DOCKER_EVENTS_NOTE = '컨테이너 시작 직후 약 0.1초 안의 동작은 놓칠 수 있습니다';
  function simNotify() {
    const mode = params.get('notify'), at = new Date(Date.now() - 4 * 60000).toISOString();
    if (mode === 'off') return { enabled: false, channels: [], sent: 0, failed: 0, dropped: 0, suppressed: 0 };
    const fail = mode === 'fail';
    const chs = [{ name: 'webhook', host: 'hooks.example.test', sent: 12, failed: fail ? 3 : 0, dropped: 0, lastError: fail ? 'HTTP 502 Bad Gateway — 3번 다시 보내도 실패해 포기' : '', lastAt: at, queued: 0 },
      { name: 'slack', host: 'hooks.slack.com', sent: 12, failed: 0, dropped: 0, lastError: '', lastAt: at, queued: 0 }];
    return { enabled: true, channels: chs, sent: 24, failed: fail ? 3 : 0, dropped: 0, suppressed: 5, lastError: fail ? chs[0].lastError : '' };
  }
  const simInfo = () => { const disc = params.get('discovery') === 'fanotify' ? 'fanotify' : 'docker-events';
    // gadgets 는 그대로(exec · open · connect — dns 는 RESOLVE_DNS 로 켜는 trace_dns). demo: DEMO_ENABLED(시연 패널 — 시뮬은 ?demo=off 로 끈다) [10/30 계약 §2]
    return { source: 'mock', gadgets: ['exec', 'open', 'connect'], enforceKill: true, authRequired: true, gadgetVersion: 'v0.56.1', watchContainers: [], ignoreContainers: ['supplyguard-*'],
      dnsResolve: params.get('dns') === 'off' ? 'off' : 'ok', discovery: disc, discoveryNote: disc === 'docker-events' ? DOCKER_EVENTS_NOTE : '', notify: simNotify(), demo: params.get('demo') !== 'off', chat: params.get('ai') !== 'off' }; }; // chat: AI 도우미(OLLAMA_URL) — 시뮬은 ?ai=off 로 끈다 [11/02]
  // 도우미(guide.js)가 쓰는 요약 — /api/info 에서 만든다. live 에 값이 없으면 비워서 「미확인」
  function serverFromInfo(i) {
    const n = i && i.notify;
    return { notify: !n ? undefined : !n.enabled ? 'none' : n.failed ? 'failed' : 'webhook', dnsResolve: !i || !i.dnsResolve ? undefined : i.dnsResolve === 'off' ? 'off' : 'on' };
  }
  state.info = simInfo();
  state.server = state.source === 'live' ? {} : serverFromInfo(state.info);
  // 모의 지연 · 실패 [10/20 D] — ?latency=ms(첫 로드 스켈레톤 확인) · ?fail=audit,installs,scans,events(그 조회가 한 번 실패 → 「다시 시도」)
  //   10/20 결정 4: ?fail=이름:N 이면 N 번 실패(자동 재시도 확인) · ?retry=ms 로 자동 재시도 주기(기본 30초)를 줄인다
  const LATENCY = Math.max(0, Number(params.get('latency')) || 0);
  const failLeft = new Map((params.get('fail') || '').split(',').map((x) => x.trim()).filter(Boolean).map((x) => { const [k, n] = x.split(':'); return [k, Math.max(1, Number(n) || 1)]; }));
  const failHit = (name) => { const n = failLeft.get(name); if (!n) return false; if (n <= 1) failLeft.delete(name); else failLeft.set(name, n - 1); return true; };
  const RETRY_MS = Math.max(500, Number(params.get('retry')) || 30000);
  state.auditSeq = state.audit.reduce((m, a) => Math.max(m, a.id), 0);
  const listeners = new Set();
  const emit = () => { for (const f of listeners) f(); };

  // ── 시뮬레이션: mock 이벤트 소스 + 파이프라인 + 통계 ──────
  const sim = {
    containers: M.containers.map((c) => Object.assign({ id: M.hexId(Math.random, 64), killedAt: 0 }, c)),
    queue: [], seq: 0, total: 0, violations: 0, killed: [], perContainer: new Map(),
    recent: [], // 최근 60초 이벤트 시각
    trend: [], // 5초 버킷 120개 (10분)
    // 자동 공격은 기본 꺼짐 [10/15 목표] — 데모 대본은 「판정 대기 0」에서 시작하고, 런타임 공격은 데모 제어 「지금 실행」으로 일으킨다
    nextAttack: Infinity, interval: 100, attackEvery: 0, restartIn: 15000, rnd: Math.random, collectedLive: new Map(), bootMinute: Math.floor(Date.now() / 60000),
  };
  const rnd = (n) => Math.floor(Math.random() * n);
  function mkEvent(c, tpl, at) {
    const e = Object.assign({ timestamp: new Date(at).toISOString(), containerId: c.id, containerName: c.name, imageName: c.image, pid: 1000 + rnd(30000) }, tpl);
    // dnsTraced [10/20 I]: 이 connect 가 올 때 trace_dns 가 돌고 있었는지 — 도메인 판단이 꺼져 있으면 false(판단 불가, fail-open)
    if (e.kind === 'connect' && e.dnsTraced === undefined) e.dnsTraced = state.info.dnsResolve !== 'off';
    return e;
  }
  function bucketOf(t) { return Math.floor(t / 5000) * 5000; }
  function record(v, at) {
    const level = levelOf(v);
    sim.total++; sim.recent.push(at);
    // 종합(10/16): 수집량을 1분 단위로 쌓는다 — 실제 백엔드는 Postgres 에 1분 단위로 저장
    const mk = Math.floor(at / 60000); const mc = sim.collectedLive.get(mk) || { exec: 0, open: 0, connect: 0, dns: 0 }; mc[v.event.kind] = (mc[v.event.kind] || 0) + 1; sim.collectedLive.set(mk, mc);
    let b = sim.trend[sim.trend.length - 1];
    if (!b || b.ts !== bucketOf(at)) { b = { ts: bucketOf(at), t: new Date(bucketOf(at)).toISOString(), exec: 0, open: 0, connect: 0, dns: 0, violations: 0 }; sim.trend.push(b); if (sim.trend.length > 120) sim.trend.shift(); }
    b[v.event.kind] = (b[v.event.kind] || 0) + 1;
    if (v.matched) { sim.violations++; b.violations++; sim.perContainer.set(v.event.containerName, (sim.perContainer.get(v.event.containerName) || 0) + 1); }
  }
  // pipeline: 평가(탐지 결과) → (kill 이면) 격리 → 감사 로그 저장(위반만) · 런타임 건 → 큐
  // opts: silent(시드) · count(같은 이벤트 n 번) · session(설치 세션 — 감사 행에 install · caseId)
  function pipeline(c, e, at, opts) {
    const o = opts || {};
    const v = M.evaluate(state.rules, e);
    if (v.matched && v.action === 'kill') {
      if (!state.info.enforceKill || v.dryRun) v.dryRun = true;
      else if (c.killedAt) v.enforced = true; // 이미 격리 중 — 중복 kill 안 함
      else { v.enforced = true; c.killedAt = at; sim.killed.unshift({ id: c.id, name: c.name, at: new Date(at).toISOString() }); srv.collectEvidence(c, at, o.session); v.timeline = M.mkTimeline(e.timestamp, !!o.session); if (!o.silent && !o.session) UI.toast(`${c.name} 격리됨 — ${v.reason}`, { tone: 'danger', key: `kill:${c.name}`, action: { label: '이벤트 보기', go: '#/events', state: { verdict: 'kill' } } }); } // timeline: 격리 타임라인 [10/30 계약 §3]
    }
    record(v, at);
    state.topology.ingest(v);
    if (v.matched) {
      const lvl = levelOf(v);
      let caseId = null, rc = null;
      if (o.session) caseId = o.session.caseId;
      else if (!e.containerName.startsWith(SANDBOX)) { rc = srv.touchRuntimeCase(e, v, at, lvl === 'alert'); caseId = rc ? rc.id : null; } // 경고는 열린 건에만 묶인다
      const auditId = srv.storeAudit(v, o.count || 1, caseId, o.session ? { id: o.session.id, label: `${o.session.manager} ${o.session.packages.join(' ')}` } : null);
      // 격리 세션 · 런타임 건의 첫 kill 판정 → isolation { auditId, timeline } [10/30 계약 §3]
      if (v.timeline) { if (o.session && !o.session.isolation) o.session.isolation = { auditId, timeline: v.timeline }; if (rc && !rc.isolation) rc.isolation = { auditId, timeline: v.timeline }; }
    }
    if (v.matched && !o.silent) state.unseen++;
    if (!state.paused || o.silent) sim.queue.push(Object.assign({ key: ++sim.seq }, v));
    return v;
  }
  // 정상 이벤트 고르기 — 도메인 판단(trace_dns)이 꺼져 있으면 dns 이벤트 자체가 없다(dns 규칙은 자연히 미발동) [10/30]
  const dnsOff = () => state.info.dnsResolve === 'off';
  const normalOf = (c) => (dnsOff() ? c.normal.filter((t) => t.kind !== 'dns') : c.normal);
  const pickNormal = (c) => { const xs = normalOf(c); return xs[rnd(xs.length)]; };
  function tick() {
    const now = Date.now();
    for (const c of sim.containers) {
      if (c.killedAt) {
        if (c.blockedImage || now - c.killedAt < sim.restartIn) continue; // 차단 이미지는 다시 띄우지 않는다
        if (restart(c, now)) continue;
        UI.toast(`${c.name} 새 컨테이너 ID 로 재기동됨 (데모: 재배포)`, { tone: 'info', key: `restart:${c.name}` });
      }
      if (rnd(3) === 0) pipeline(c, mkEvent(c, pickNormal(c), now), now);
    }
    if (sim.attackEvery && now >= sim.nextAttack) { runAttack(now); sim.nextAttack = now + sim.attackEvery; }
  }
  // 재기동 — 이미지가 차단 목록에 있으면 기동 즉시 격리(사유 blocked-image)하고 true [10/15 목표]. 건은 새로 열지 않는다(이미 악성으로 판정된 이미지)
  function restart(c, now) {
    c.killedAt = 0; c.id = M.hexId(Math.random, 64);
    if (!state.blocklist.images.some((x) => x.value === c.image)) { c.blockedImage = false; return false; }
    c.killedAt = now; c.blockedImage = true;
    sim.killed.unshift({ id: c.id, name: c.name, at: new Date(now).toISOString(), reason: 'blocked-image' });
    // 감사 행은 그 차단을 만든 건의 caseId 로 남긴다(새 건 없음)
    const entry = state.blocklist.images.find((x) => x.value === c.image);
    const bv = { event: mkEvent(c, { kind: 'exec', comm: 'container-start', args: '' }, now), matched: true, ruleId: 'blocked-image', action: 'kill', reason: `차단된 이미지 ${c.image}`, enforced: true, timeline: M.mkTimeline(new Date(now).toISOString(), false) };
    record(bv, now); srv.storeAudit(bv, 1, entry ? entry.caseId : null, null);
    toast(`${c.name} 기동 즉시 격리 — 차단된 이미지 ${c.image}`, { tone: 'danger', key: `blocked:${c.name}`, action: { label: '차단 목록', go: '#/policies?id=__blocklist__' } });
    return true;
  }
  function runAttack(now, opts) {
    for (const c of sim.containers) if (c.attacker && !c.killedAt) for (const a of M.attack) pipeline(c, mkEvent(c, a, now), now, opts);
  }
  // 데모 제어 "지금 실행": 어떤 상태에서든 바로 시나리오 1→2→3 이 흐른다
  function runAttackNow() {
    if (state.source !== 'sim') { toast('실제 백엔드 모드 — 공격은 백엔드 mock 소스가 20초마다 자동 실행합니다', { tone: 'warn' }); return; }
    const now = Date.now();
    if (!state.connected) { state.connected = true; start(); }
    if (state.paused) { state.paused = false; toast('일시정지를 해제하고 공격 시나리오를 실행합니다', { tone: 'info' }); }
    for (const c of sim.containers) if (c.attacker && c.killedAt) { if (!restart(c, now)) toast(`${c.name} 재기동 (격리 중이던 컨테이너를 다시 띄움)`, { tone: 'info', key: `restart:${c.name}` }); }
    runAttack(now);
    sim.nextAttack = sim.attackEvery ? now + sim.attackEvery : Infinity;
    flush(); state.stats = snapshot(); emit();
    toast(`공격 시나리오 실행 — exec(curl|sh) → open(/etc/shadow) → connect(:4444) ${M.attack.length}개 이벤트`, { tone: 'danger', key: 'attack-run', action: { label: '이벤트 보기', go: '#/events' } });
  }
  // 데모 제어 「DNS 유출 질의 지금 실행」 [10/30]: 배포된 pkg-reqeusts 가 48자 hex 라벨 A 질의 + TXT 질의를 보낸다 → runtime-dns-exfil 경고 2건(기존 attack 시드와 따로)
  function runDnsExfilNow() {
    if (state.source !== 'sim') { toast('실제 백엔드 모드 — DNS 유출 질의는 deploy/demo/run-attacker.sh SCENARIO=dns-exfil 로 실행합니다', { tone: 'warn' }); return; }
    if (dnsOff()) { toast('도메인 판단이 꺼져 있어(trace_dns 없음) DNS 질의가 보이지 않습니다 — ?dns=off 를 빼고 다시 여세요', { tone: 'warn', key: 'dns-off' }); return; }
    const now = Date.now();
    if (!state.connected) { state.connected = true; start(); }
    if (state.paused) { state.paused = false; toast('일시정지를 해제하고 DNS 유출 질의를 실행합니다', { tone: 'info' }); }
    for (const c of sim.containers) if (c.attacker && c.killedAt) { if (!restart(c, now)) toast(`${c.name} 재기동 (격리 중이던 컨테이너를 다시 띄움)`, { tone: 'info', key: `restart:${c.name}` }); }
    for (const c of sim.containers) if (c.attacker && !c.killedAt) for (const a of M.dnsExfil) pipeline(c, mkEvent(c, a, now), now);
    flush(); state.stats = snapshot(); emit();
    toast(`DNS 유출 질의 실행 — ${M.dnsExfil.map((a) => `${a.dstHost.length > 24 ? a.dstHost.slice(0, 12) + '…' + a.dstHost.slice(-12) : a.dstHost} (${a.qtype})`).join(' · ')} ${M.dnsExfil.length}개 이벤트`, { tone: 'warn', key: 'dns-exfil-run', action: { label: '이벤트 보기', go: '#/events', state: { kind: 'dns' } } });
  }
  // 데모 제어 「설치 검사 실행」: sg-install 이 하는 일을 흉내 낸다 — 차단 확인 → 세션 시작 보고 → 감시 컨테이너 이벤트 → 끝 보고.
  // 차단된 패키지면 컨테이너를 띄우지 않고 「설치 전 거부」 세션만 남긴다(CLI 종료 코드 3) [10/15 목표].
  // 이벤트는 런타임 파이프라인도 그대로 지나가므로(같은 엔진) 이벤트 피드에도 보인다. kind = benign | malicious | warn | (테스트용) 세션 명세
  function runInstallDemo(kind) {
    if (state.source !== 'sim') { toast('실제 백엔드 모드 — 설치 검사는 CLI(sg-install)로 실행합니다', { tone: 'warn' }); return null; }
    const spec = kind && typeof kind === 'object' ? kind : M.demoSpecs[kind] || M.demoSpecs.benign;
    const chk = srv.blocklistCheck(spec.manager, spec.pkg);
    if (chk.blocked) {
      const id = srv.installsRefused({ manager: spec.manager, packages: [spec.pkg], value: chk.value }).id;
      emit();
      toast(`설치 전 거부 — 차단된 패키지 ${chk.value} (sg-install 종료 코드 3, 컨테이너 없음)`, { tone: 'danger', key: `install:${id}`, action: { label: '보기', go: `#/installs?id=${id}`, state: { status: 'all' } } });
      return id;
    }
    const s = M.newSession(spec, Date.now(), ++state.installSeq);
    state.installs.unshift(s); srv.autoScan(s); emit(); // 11/04 종합 판정: 세션 시작 보고(POST /api/installs) 때 서버가 같은 패키지의 정적 검사를 시작
    const label = `${s.manager} ${s.packages.join(' ')}`;
    toast(`설치 검사 시작 — sg-install ${label}`, { tone: 'info', key: `install:${s.id}`, replace: true });
    const c = { name: s.container, image: s.image, id: s.containerId, killedAt: 0 };
    spec.events.forEach(([tpl, n], i) => setTimeout(() => {
      if (tpl.kind === 'dns' && dnsOff()) return; // 도메인 판단 꺼짐 — dns 이벤트 없음 [10/30]
      const at = Date.now(); const v = pipeline(c, mkEvent(c, tpl, at), at, { count: n, session: s });
      M.addToSession(s, v.event, v, n); srv.syncInstallCase(s); emit();
    }, 400 + i * 180));
    setTimeout(() => {
      const end = new Date().toISOString(); s.containerExitedAt = end; s.finishedAt = end; s.exitCode = c.killedAt ? 137 : spec.exitCode;
      const st = M.statusOf(s); emit();
      toast(`설치 검사 결과: ${INSTALL_STATUS[st]} — ${label}`, { tone: st === 'isolated' ? 'danger' : st === 'warned' ? 'warn' : 'ok', key: `install:${s.id}`, replace: true, action: { label: '보기', go: `#/installs?id=${s.id}`, state: s.caseId ? null : { status: 'all' } } });
    }, 400 + spec.events.length * 180 + 600);
    return s.id;
  }
  // 테스트 · 데모용: 런타임 컨테이너 하나에 이벤트 하나를 흘린다
  function simEvent(name, tpl) {
    const c = sim.containers.find((x) => x.name === name); if (!c) return null;
    const at = Date.now(); const v = pipeline(c, mkEvent(c, tpl, at), at); flush(); emit(); return v;
  }
  function flush() {
    if (sim.queue.length) { const batch = sim.queue.reverse(); sim.queue = []; state.verdicts = batch.concat(state.verdicts).slice(0, 500); }
  }
  function snapshot() {
    const now = Date.now();
    sim.recent = sim.recent.filter((t) => now - t < 60000);
    const cut = now - 10 * 60000;
    const trend = sim.trend.filter((b) => b.ts >= cut);
    return {
      timestamp: new Date(now).toISOString(), totalEvents: sim.total, eventsLastMinute: sim.recent.length,
      eventsPerSec: sim.recent.filter((t) => now - t < 5000).length / 5, totalViolations: sim.violations,
      killed: sim.killed.slice(0, 20), killedCount: sim.killed.length,
      topContainers: [...sim.perContainer].map(([name, violations]) => ({ name, violations })).sort((a, b) => b.violations - a.violations).slice(0, 5),
      trend: trend.map(({ t, exec, open, connect, dns, violations }) => ({ t, exec, open, connect, dns: dns || 0, violations })),
      wsClients: 1, dropped: 0, enforceKill: state.info.enforceKill, source: 'mock',
    };
  }
  // 시작 시 최근 10분 정상 이벤트를 미리 채운다 (새로고침 직후 빈 화면 방지 — 실제 앱은 /api/events/recent). 공격은 넣지 않는다 [10/15 목표]
  function seed() {
    const start = Date.now() - 600000;
    for (let t = start; t < Date.now() - 500; t += 100) {
      for (const c of sim.containers) if (rnd(3) === 0) pipeline(c, mkEvent(c, pickNormal(c), t), t, { silent: true });
    }
    flush(); state.unseen = 0; state.stats = snapshot();
  }

  // ── 실시간 연결 상태 (WS) 시뮬레이션 ─────────────────────
  let tickTimer, flushTimer, statsTimer;
  function start() {
    stop();
    if (state.source === 'sim') { tickTimer = setInterval(tick, sim.interval); statsTimer = setInterval(() => { state.stats = snapshot(); }, 1000); }
    flushTimer = setInterval(() => { flush(); emit(); }, 250);
  }
  function stop() { clearInterval(tickTimer); clearInterval(flushTimer); clearInterval(statsTimer); }
  // 끊김 [10/20 D]: 상단 붉은 배너(셸) — 서버는 그동안에도 이벤트를 받는다. 다시 붙으면 끊긴 구간을 채우고(실제 앱: /api/events/recent) 「끊긴 동안 N건을 채웠습니다」
  function disconnect(ms) {
    if (state.source !== 'sim') { live.ws && live.ws.close(); return; } // 실제 모드: 소켓을 끊어 재연결 백오프를 그대로 본다
    if (!state.connected) return;
    const from = Date.now();
    state.connected = false; state.backfill = null; stop(); emit();
    setTimeout(() => {
      const to = Date.now(); let n = 0;
      for (let t = from; t < to; t += sim.interval) for (const c of sim.containers) if (!c.killedAt && rnd(3) === 0) { pipeline(c, mkEvent(c, pickNormal(c), t), t, { silent: true }); n++; }
      flush(); state.connected = true; state.backfill = { n, at: new Date(to).toISOString() }; start(); emit();
    }, ms || 3000);
  }

  // ── 실제 백엔드 (frontend/src/hooks/useEventStream.ts 와 같은 동작) ──
  const live = { ws: null, retry: null, attempt: 0, closed: false };
  async function fetchJSON(path, init) {
    const headers = new Headers((init && init.headers) || {});
    // 쿠키 세션 [10/20 A] — 목업과 백엔드를 같은 호스트 이름(127.0.0.1)으로 열어야 쿠키가 붙는다
    const res = await fetch(state.apiBase + path, Object.assign({ credentials: 'include' }, init, { headers }));
    // json: 백엔드가 JSON 오류 본문({error})을 줬는지 — 라우트 자체가 없으면 404 + 텍스트(= 백엔드 미지원, React isUnsupported 와 같은 기준)
    if (!res.ok) { let msg = res.statusText, json = false; try { msg = (await res.json()).error || msg; json = true; } catch { /* 본문 없음 */ } throw Object.assign(new Error(`${res.status} · ${msg}`), { status: res.status, json }); }
    if (res.status === 204) return null;
    return (res.headers.get('Content-Type') || '').includes('json') ? res.json() : res.text();
  }
  function liveConnect() {
    live.closed = false;
    const url = state.apiBase.replace(/^http/, 'ws') + '/ws/events';
    const ws = new WebSocket(url); live.ws = ws;
    ws.onopen = () => { live.attempt = 0; state.connected = true; state.liveError = ''; emit(); if (live.wasDown) { live.wasDown = false; liveBackfill(); } };
    ws.onclose = () => { state.connected = false; if (state.eventsReady) live.wasDown = true; emit(); if (live.closed) return; const delay = Math.min(1000 * 2 ** live.attempt, 10000); live.attempt++; live.retry = setTimeout(liveConnect, delay); };
    ws.onerror = () => { state.liveError = `${url} 연결 실패 — 백엔드가 떠 있고 ALLOWED_ORIGINS 에 ${location.origin} 이 있는지 확인`; };
    ws.onmessage = (e) => {
      let msg; try { msg = JSON.parse(e.data); } catch { return; }
      if (msg.type === 'verdict') { const v = msg.data; state.topology.ingest(v); if (v.matched) state.unseen++; if (!state.paused) sim.queue.push(Object.assign({ key: ++sim.seq }, v)); }
      else if (msg.type === 'stats') state.stats = msg.data;
    };
  }
  // 다시 붙으면 끊긴 구간을 REST 로 채운다 — 이미 받은 것(시각 · 컨테이너 · 종류 · 상세)은 건너뛴다
  const vKey = (v) => `${v.event.timestamp}|${v.event.containerId}|${v.event.kind}|${detailOf(v.event)}`;
  function liveBackfill() {
    const last = state.verdicts.length ? Date.parse(state.verdicts[0].event.timestamp) : 0;
    fetchJSON('/api/events/recent?limit=500').then((recent) => {
      const have = new Set(state.verdicts.map(vKey));
      const gap = recent.filter((v) => Date.parse(v.event.timestamp) >= last && !have.has(vKey(v)));
      [...gap].reverse().forEach((v) => state.topology.ingest(v));
      state.verdicts = gap.map((v) => Object.assign({ key: ++sim.seq }, v)).concat(state.verdicts).slice(0, 500);
      state.backfill = { n: gap.length, at: new Date().toISOString() }; emit();
    }).catch(() => { /* 다음 재연결에서 다시 */ });
  }
  async function liveStart(quiet) {
    state.verdicts = []; state.stats = null; state.unseen = 0; state.topology = new TopologyStore(); state.liveError = '';
    if (!quiet) { state.eventsReady = false; state.eventsError = null; }
    start(); liveConnect();
    try {
      const [info, recent, stats, rules] = await Promise.all([fetchJSON('/api/info'), fetchJSON('/api/events/recent?limit=500'), fetchJSON('/api/stats'), fetchJSON('/api/policies')]);
      state.info = info; state.server = serverFromInfo(info); state.stats = stats; state.rules = rules || [];
      [...recent].reverse().forEach((v) => state.topology.ingest(v));
      state.verdicts = recent.map((v) => Object.assign({ key: ++sim.seq }, v)); state.eventsReady = true; state.eventsError = null;
      emit(); toast(`실제 백엔드 연결: ${state.apiBase} (${info.source} 소스 · IG ${info.gadgetVersion})`, { tone: 'ok' });
    } catch (e) { state.eventsError = Object.assign(new Error(`${state.apiBase} — ${e.message}`), { status: e.status }); emit(); } // 셸 붉은 배너(이벤트를 불러오지 못했습니다 + 다시 시도)
  }
  // 이벤트 첫 로드 [10/20 D] — sim 은 ?latency=ms 만큼 늦게, ?fail=events 면 한 번 실패(「다시 시도」로 다시 부른다)
  // quiet [10/20 결정 4]: 자동 재시도 — 스켈레톤으로 바꾸지 않고, 실패하면 오류를 새로(다음 주기), 성공하면 목록
  function loadEvents(quiet) {
    if (state.source === 'live') { liveStop(); liveStart(quiet); return; }
    if (!quiet) { state.eventsError = null; state.eventsReady = false; emit(); }
    setTimeout(() => {
      if (failHit('events')) { state.eventsError = httpErr(503, '모의 오류 — 이벤트 서버가 응답하지 않습니다'); emit(); return; }
      state.eventsError = null; seed(); state.eventsReady = true; start(); emit();
    }, LATENCY);
  }
  function liveStop() { live.closed = true; clearTimeout(live.retry); if (live.ws) live.ws.close(); live.ws = null; }
  function setSource(source, apiBase) {
    try { localStorage.setItem('supplyguard.mock.source', source); if (apiBase) localStorage.setItem('supplyguard.mock.api', apiBase); } catch { /* 저장소 차단 */ }
    stop(); liveStop();
    state.source = source; if (apiBase) state.apiBase = apiBase.replace(/\/$/, '');
    if (source !== 'live') state.info = simInfo();
    state.server = source === 'live' ? {} : serverFromInfo(state.info);
    if (source === 'live') { liveStart(); }
    else {
      state.verdicts = []; state.stats = null; state.unseen = 0; state.topology = new TopologyStore(); state.liveError = '';
      state.rules = JSON.parse(JSON.stringify(M.rules));
      sim.total = 0; sim.violations = 0; sim.killed = []; sim.perContainer = new Map(); sim.recent = []; sim.trend = []; sim.queue = [];
      for (const c of sim.containers) { c.killedAt = 0; c.blockedImage = false; c.id = M.hexId(Math.random, 64); }
      seed(); state.eventsReady = true; state.eventsError = null; state.connected = true; start(); toast('내장 시뮬레이션으로 전환', { tone: 'info' });
    }
    emit();
  }

  // ── 모의 서버 (sim) — 판정 흐름 [10/15 목표]. Claude Docs 「API 계약」 탭의 데이터 모양 · 동작 규칙을 그대로 따른다 ──
  const clone = (x) => JSON.parse(JSON.stringify(x));
  const iso = (at) => new Date(at || Date.now()).toISOString();
  const nextId = (k, prefix) => `${prefix}-${String(++state.seq[k]).padStart(4, '0')}`;
  const httpErr = (status, msg) => Object.assign(new Error(`${status} · ${msg}`), { status });
  const SEV_ORDER = ['normal', 'alert', 'held', 'killed'];
  const srv = {
    caseById: (id) => state.cases.find((c) => c.id === id),
    // 감사 로그 저장 — 위반만, 같은 이벤트 n 번이면 n 행
    storeAudit(v, n, caseId, install) {
      let first = null;
      for (let i = 0; i < n; i++) { const row = Object.assign({}, v, { id: ++state.auditSeq, caseId, install: install || null }); delete row.key; state.audit.unshift(row); if (first === null) first = row.id; }
      return first; // 첫 행 id — 격리 세션 · 건의 isolation.auditId [10/30]
    },
    // 건 열기(설치): 세션 결과가 격리 또는 경고가 되는 순간 세션당 1개. 위반 수 · 규칙 · 최악 탐지 결과는 세션에서 다시 센다
    syncInstallCase(s) {
      const st = M.statusOf(s);
      if (!s.caseId && (st === 'isolated' || st === 'warned')) {
        const c = { id: nextId('case', 'case'), source: 'install', installId: s.id, container: s.container, label: `${s.manager} ${s.packages.join(' ')}`, image: s.image, package: M.pkgKey(s.manager, s.packages[0]),
          openedAt: iso(), level: 'normal', violations: 0, ruleIds: [], state: 'open', decision: 'pending', decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null };
        state.cases.unshift(c); s.caseId = c.id;
        for (const a of state.audit) if (a.install && a.install.id === s.id) a.caseId = c.id;
      }
      const c = srv.caseById(s.caseId); if (!c) return;
      if (s.isolation && !c.isolation) c.isolation = clone(s.isolation); // 격리 세션의 첫 kill 판정 [10/30 계약 §3]
      c.violations = s.violations.reduce((n, v) => n + (v.count || 1), 0);
      c.ruleIds = [...new Set(s.violations.map((v) => v.ruleId))];
      c.level = s.violations.map(levelOf).reduce((a, b) => (SEV_ORDER.indexOf(b) > SEV_ORDER.indexOf(a) ? b : a), 'normal');
    },
    // 건 열기(런타임): sg-install-* 가 아닌 컨테이너에 격리됨 · 격리 대상이 나오면, 그 이름으로 열린(open · decided) 건이 없을 때 새 건. 있으면 위반 수만 늘린다
    // joinOnly(경고): 열린 건이 있을 때만 그 건에 더하고, 없으면 null — 경고만으로 새 건은 열지 않는다 [10/15 3차]
    touchRuntimeCase(e, v, at, joinOnly) {
      let c = state.cases.find((x) => x.source === 'runtime' && x.container === e.containerName && (x.state === 'open' || x.state === 'decided'));
      if (!c && joinOnly) return null;
      if (!c) {
        c = { id: nextId('case', 'case'), source: 'runtime', installId: null, container: e.containerName, label: e.containerName, image: e.imageName,
          openedAt: iso(at), level: 'normal', violations: 0, ruleIds: [], state: 'open', decision: 'pending', decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null, isolation: null }; // isolation: 런타임 격리 건의 첫 kill 판정 [10/30]
        state.cases.unshift(c);
      }
      c.violations++; if (!c.ruleIds.includes(v.ruleId)) c.ruleIds.push(v.ruleId);
      const lvl = levelOf(v); if (SEV_ORDER.indexOf(lvl) > SEV_ORDER.indexOf(c.level)) c.level = lvl;
      return c;
    },
    // 판정 → 제안 만들기 (동작 규칙 표 — 백엔드 review/cases.go 와 같은 규칙) → { changes, notes }
    // 악성: 설치 = 세션의 패키지 전부 차단, 런타임 = 이미지 차단. 위반 통신의 도메인 차단 — 어느 규칙의 allowHosts 에 있는 도메인 · IP 만 있는 통신은 빼고 안내 [10/15 3차]
    // 오탐: 걸린 규칙마다 가장 좁은 예외 — 파일 allowPaths · 통신은 규칙에 원래 allowHosts 가 있고 도메인을 알면 allowHosts, 아니면 allowCidrs IP/32.
    //       실행 규칙 · 예외로 안 풀리는 금지 목록(deny*) · 시스템 규칙 · blocked-image 는 변경 없이 안내만
    proposalChanges(c, decision) {
      const rows = state.audit.filter((a) => a.caseId === c.id);
      const out = [], seen = new Set(), notes = [];
      const add = (ch) => { const k = JSON.stringify(ch); if (!seen.has(k)) { seen.add(k); out.push(ch); } };
      const note = (n) => { if (!notes.includes(n)) notes.push(n); };
      const blocked = (list, value) => state.blocklist[list].some((x) => x.value === value);
      const hostIn = (pat, host) => { pat = pat.toLowerCase().replace(/\.$/, ''); return host === pat || host.endsWith('.' + pat); };
      if (decision === 'malicious') {
        if (c.source === 'scan') { for (const k of c.packages || [c.package]) if (!blocked('packages', k)) add({ op: 'block', list: 'packages', value: k }); } // 공급망 검사에서 올린 것(10/16 · 10/20 여러 패키지)
        else if (c.source === 'install') {
          const s = state.installs.find((x) => x.id === c.installId);
          const keys = s ? s.packages.map((p) => M.pkgKey(s.manager, p)) : [c.package];
          for (const k of keys) if (!blocked('packages', k)) add({ op: 'block', list: 'packages', value: k });
        } else if (!blocked('images', c.image)) add({ op: 'block', list: 'images', value: c.image });
        for (const a of rows) {
          if (a.event.kind !== 'connect') continue;
          const host = (a.event.dstHost || '').toLowerCase().replace(/\.$/, '');
          if (!host) { note(`${a.event.dstIp} 은 도메인을 몰라 도메인 차단을 만들지 않았습니다`); continue; }
          const by = state.rules.find((r) => (r.allowHosts || []).some((h) => hostIn(h, host)));
          if (by) { note(`도메인 ${host} 은 규칙 ${by.id} 의 허용 도메인이라 차단하지 않았습니다`); continue; }
          if (!blocked('hosts', host)) add({ op: 'block', list: 'hosts', value: host });
        }
        return { changes: out, notes };
      }
      let work = clone(state.rules);
      const hadHosts = new Set(work.filter((r) => (r.allowHosts || []).length).map((r) => r.id));
      for (const a of rows) {
        if (a.ruleId === 'blocked-image') { note('이미지 차단은 예외가 아니라 차단 목록에서 해제합니다'); continue; }
        // 연쇄 규칙 [11/04 — 백엔드 review/cases.go 와 같은 문구]: 상태 없는 재평가로는 다시 맞히지 못해 빈 제안이 된다 — 안내만
        if ((work.find((r) => r.id === a.ruleId) || {}).kind === 'sequence') { note(`연쇄 규칙 ${a.ruleId} 은 자동 예외를 만들지 않습니다 — 정책 탭에서 직접 수정하세요`); continue; }
        for (let i = 0; i <= work.length; i++) {
          const v = M.evaluate(work, a.event); if (!v.matched) break;
          if (v.ruleId === M.SYSTEM_RULE) { note(`도메인 ${a.event.dstHost} 은 차단 목록에 있습니다 — 차단 목록에서 해제하세요`); break; }
          const rule = work.find((r) => r.id === v.ruleId), e = a.event; let field = null, value = null;
          if (e.kind === 'open' && e.path) { field = 'allowPaths'; value = e.path; }
          else if (e.kind === 'dns') { // DNS 질의 규칙 [10/30]: 규칙에 원래 허용 도메인이 있을 때만 그 도메인을 더한다(없는 규칙에 allowHosts 를 넣으면 다른 질의가 전부 위반이 된다)
            const name = (e.dstHost || '').toLowerCase().replace(/\.$/, '');
            if (name && hadHosts.has(rule.id)) { field = 'allowHosts'; value = name; } else { note(`DNS 규칙 ${rule.id} 은 허용 도메인 목록이 없어 자동 예외를 만들지 않습니다 — 정책 탭에서 직접 수정하세요`); break; }
          }
          else if (e.kind === 'connect') {
            const host = (e.dstHost || '').toLowerCase().replace(/\.$/, '');
            if (host && hadHosts.has(rule.id)) { field = 'allowHosts'; value = host; } else { field = 'allowCidrs'; value = `${e.dstIp}/32`; }
          }
          if (!field) { note(`실행 규칙 ${rule.id} 은 자동 예외를 만들지 않습니다 — 정책 탭에서 직접 수정하세요`); break; }
          const trial = srv.rulesWith([{ op: 'except', ruleId: rule.id, field, value }], work);
          const again = M.evaluate(trial, a.event);
          if (again.matched && again.ruleId === rule.id) { note(`규칙 ${rule.id} 은 금지 목록에 걸려 예외로 풀 수 없습니다 — 정책 탭에서 직접 수정하세요`); break; }
          work = trial;
          add({ op: 'except', ruleId: rule.id, field, value });
        }
      }
      return { changes: out, notes };
    },
    decide(id, body, at) {
      const c = srv.caseById(id);
      if (!c) throw httpErr(404, '건 없음');
      if (c.state !== 'open') throw httpErr(409, '이미 판정된 건');
      const decision = body && body.decision;
      if (!['malicious', 'false_positive'].includes(decision)) throw httpErr(400, 'decision 은 malicious | false_positive');
      c.decision = decision; c.state = 'decided'; c.decidedAt = iso(at); c.decidedBy = actor(); c.note = (body && body.note) || '';
      const { changes, notes } = srv.proposalChanges(c, decision);
      const p = { id: nextId('prop', 'prop'), caseId: c.id, decision, state: 'draft', createdAt: c.decidedAt, createdBy: actor(), appliedAt: null, appliedBy: null, changes, notes };
      state.proposals.unshift(p); c.proposalId = p.id;
      return { case: clone(c), proposal: clone(p) };
    },
    // 제안을 적용한 정책 사본(규칙 예외 + blocklist-hosts 도메인)으로 저장된 감사 로그를 다시 평가해, 탐지 결과가 바뀌는 행만 돌려준다.
    // 패키지 · 이미지 차단은 과거 이벤트를 바꾸지 않는다 — 화면이 「다음 설치 · 기동부터」로 따로 보인다
    rulesWith(changes, base) {
      const rules = clone(base || state.rules);
      for (const ch of changes) {
        if (ch.op === 'except') { const r = rules.find((x) => x.id === ch.ruleId); if (r && !(r[ch.field] || []).includes(ch.value)) r[ch.field] = [...(r[ch.field] || []), ch.value]; }
        if (ch.op === 'block' && ch.list === 'hosts') { const r = rules.find((x) => x.id === M.SYSTEM_RULE); if (r && !(r.denyHosts || []).includes(ch.value)) r.denyHosts = [...(r.denyHosts || []), ch.value]; }
      }
      return rules;
    },
    preview(id) {
      const p = state.proposals.find((x) => x.id === id); if (!p) throw httpErr(404, '제안 없음');
      const nextOnly = p.changes.filter((x) => x.op === 'block' && x.list !== 'hosts').map((x) => ({ list: x.list, value: x.value }));
      return Object.assign(srv.reevaluate(srv.rulesWith(p.changes)), { nextOnly });
    },
    // 정책 하나를 바꾼(또는 더한) 규칙 사본으로 감사 로그를 다시 평가 — 저장 전 확인 [10/16 정책 개편]. POST /api/policies/preview {rule} → Preview
    previewRule(rule) {
      const rules = clone(state.rules); const i = rules.findIndex((x) => x.id === rule.id);
      if (i >= 0) rules[i] = clone(rule); else rules.unshift(clone(rule));
      return srv.reevaluate(rules);
    },
    reevaluate(rules) {
      const changed = [];
      const lv = (v, prev) => (!v.matched ? 'normal' : v.action !== 'kill' ? 'alert' : v.dryRun || prev === 'held' ? 'held' : 'killed');
      for (const a of state.audit) {
        // 연쇄가 이긴 행 [11/04]: 상태 없는 평가로는 지금 규칙으로도 다시 맞지 않는다 — 백엔드처럼 지금 · 다음 규칙을 둘 다 다시 평가해 비교(저장된 탐지 결과와 비교하지 않음)
        const seqRow = a.sequence && a.ruleId === a.sequence.ruleId;
        const before = seqRow ? lv(M.evaluate(state.rules, a.event)) : levelOf(a); const v = M.evaluate(rules, a.event);
        const after = lv(v, before);
        if (after !== before) changed.push({ auditId: a.id, before, after, container: a.event.containerName, ruleId: a.ruleId });
      }
      const blocking = (l) => l === 'killed' || l === 'held';
      return { evaluated: state.audit.length, changed, counts: { toNormal: changed.filter((x) => x.after === 'normal').length, toBlocked: changed.filter((x) => blocking(x.after) && !blocking(x.before)).length } };
    },
    // ── 공급망 검사(10/16) — POST /api/scans → 백엔드가 격리된 검사 컨테이너에서 GuardDog(코드) · OSV-Scanner(의존성)를 돌린다 ──
    scanStart(body, opts) {
      const b = body || {}, t = { kind: b.kind }, o = opts || {};
      if (b.kind === 'package') {
        if (!['pip', 'npm'].includes(b.manager)) throw httpErr(400, 'manager 는 pip | npm');
        const name = String(b.name || '').trim(); if (!/^(@[\w.-]+\/)?[\w.-]+$/.test(name)) throw httpErr(400, '패키지 이름을 확인하세요');
        Object.assign(t, { manager: b.manager, name, version: String(b.version || '').trim(), label: `${b.manager} ${name}${b.version ? (b.manager === 'pip' ? '==' : '@') + b.version : ''}` });
      } else if (b.kind === 'repo') {
        const m = String(b.url || '').trim().match(/^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(\.git)?\/?$/); if (!m) throw httpErr(400, 'https://github.com/<소유자>/<저장소> 형식으로 써 주세요');
        Object.assign(t, { url: `https://github.com/${m[1]}/${m[2]}`, name: m[2], label: `github.com/${m[1]}/${m[2]}` });
      } else if (b.kind === 'file') {
        if (!b.fileName) throw httpErr(400, '파일을 고르세요'); if (b.size > 50 * 1024 * 1024) throw httpErr(413, '파일은 50MB 까지 올릴 수 있습니다');
        Object.assign(t, { fileName: b.fileName, size: b.size, label: b.fileName });
      } else throw httpErr(400, 'kind 는 package | repo | file');
      if (o.label) t.label = o.label; // 자동 검사(11/04): 최신 버전으로 받은 건 라벨에 버전을 붙이지 않는다(받은 버전은 target.version)
      const sc = { id: nextId('scan', 'scan'), target: t, status: 'running', startedAt: iso(), finishedAt: null, verdict: null, risk: null, engines: M.scanFixtures.engines.map((e) => ({ name: e.name, version: e.version })), findings: [], vulns: [], files: {}, caseId: null,
        trigger: o.trigger || 'manual', installId: o.installId || null }; // trigger: manual | install(11/04 자동 검사) · installId: 이 검사를 시작한 설치 세션
      state.scans.unshift(sc);
      setTimeout(() => { srv.scanFinish(sc); emit(); }, 1200);
      return { id: sc.id };
    },
    // 끝: 목업은 실측 결과(MOCK.scanFixtures)를 돌려준다 — 이름(pip reqeusts · requests), GitHub psf/requests, requirements.txt
    scanFinish(sc) {
      const t = sc.target, F = M.scanFixtures;
      const key = t.kind === 'package' ? `${t.manager}:${t.name.toLowerCase()}` : t.kind === 'repo' ? `pip:${t.name.toLowerCase()}` : null;
      const gd = key && F.guarddog[key];
      const isDeps = t.kind === 'file' && /requirements.*\.txt$|package-lock\.json$/.test(t.fileName);
      if (gd) { sc.risk = gd.risk; sc.findings = gd.findings.map((f) => Object.assign({}, f)); sc.files = Object.assign({}, gd.files); }
      else if (!isDeps) sc.risk = { score: 0, label: 'no_risks_detected' };
      if (isDeps) sc.vulns = F.osv['requirements.txt'].map((v) => Object.assign({}, v));
      // 패키지 목록(차단 후보, W4 · 10/20 G) — 저장소 · 파일 검사만. 잠금 파일마다 한 행(같은 패키지가 여러 번 나올 수 있다)
      const pk = isDeps ? F.packages['requirements.txt'] : t.kind === 'repo' && t.name.toLowerCase() === 'requests' ? F.packages['repo:requests'] : null;
      sc.packages = pk ? pk.map((x) => Object.assign({}, x)) : [];
      if (t.kind === 'repo' && pk) sc.vulns = F.osv['repo:requests'].map((v) => Object.assign({}, v));
      // 11/02: 패키지 이름 검사도 자기 이름 · 버전을 OSV 로(백엔드는 잠금 파일을 만들어 OSV-Scanner) · 테스트 코드는 따로(점수 · 판정 제외)
      const own = t.kind === 'package' && F.osv[`own:${t.manager}:${t.name.toLowerCase()}@${t.version || ''}`];
      if (own) sc.vulns = own.map((v) => Object.assign({}, v));
      const tests = t.kind === 'repo' && F.tests[`repo:${t.name.toLowerCase()}`];
      if (tests) sc.findings = sc.findings.concat(tests.map((f) => Object.assign({ test: true }, f)));
      // 판정(11/03 결정, 백엔드 scan/verdict.go 와 같다): 악성 = 점수 ≥ 5 그리고 설치 시점 규칙 1개 이상 · 취약 = 알려진 취약점 · 주의 = 점수 ≥ 5 인데 런타임 휴리스틱 규칙만 · 그 외 정상
      const body = sc.findings.filter((f) => f.category === 'threat' && !f.test);
      sc.installThreats = body.filter((f) => M.isInstallTimeRule(f.rule)).length;
      const risky = sc.risk && sc.risk.score >= 5;
      sc.verdict = risky && sc.installThreats ? 'malicious' : sc.vulns.length ? 'vulnerable' : risky ? 'caution' : 'clean';
      sc.status = 'done'; sc.finishedAt = iso();
    },
    scanView(sc, full) {
      const v = clone(sc);
      Object.assign(v, { installThreats: sc.installThreats || 0, threats: sc.findings.filter((f) => f.category === 'threat' && !f.test).length, capabilities: sc.findings.filter((f) => f.category === 'capability' && !f.test).length, testFindings: sc.findings.filter((f) => f.test).length, vulnCount: sc.vulns.reduce((n, x) => n + x.count, 0), vulnMax: sc.vulns.reduce((m, x) => Math.max(m, Number(x.maxSeverity)), 0) || null });
      if (!full) { delete v.findings; delete v.files; delete v.vulns; delete v.packages; }
      else if (!v.packages) v.packages = [];
      return v;
    },
    // ── 종합 판정(11/04 설계, 2026-11-03 승인) — sg-install 세션 시작 때 같은 패키지(첫 패키지)의 정적 검사를 자동으로 시작 ──
    //   대상: pip ==X · npm @X.Y.Z 는 그 버전, 범위(>= ~= ^ @4 @latest) · 미지정은 최신(받은 버전 = target.version). [extras] · ; 표식은 뗀다
    //   건너뜀(scanSkip): local(. / ~ 로 시작 · git+ · URL · file: · .whl/.tar.gz) · unsupported(cargo) · invalid(이름이 namePat 밖) · off(검사기 없음 · Ping 실패) · busy(동시 1 + 대기열 4 가득)
    //   같은 manager:정규화 이름:버전 — 실행 중이면 합류 · 24시간 안 done 은 재사용 · failed 는 재검사. 거부(refused) 세션은 시작하지 않는다
    scannerUp: true, scanSlots: 5, // SCAN_CONCURRENCY 1 + SCAN_QUEUE 4
    autoScanTarget(manager, raw) {
      if (!['pip', 'npm'].includes(manager)) return { skip: 'unsupported' };
      const p = String(raw || '').trim();
      if (/^[./~]/.test(p) || /^git\+/i.test(p) || /^[a-z][\w+.-]*:\/\//i.test(p) || /^file:/i.test(p) || /\.(whl|tar\.gz)$/i.test(p)) return { skip: 'local' };
      let name = '', version = '', exact = false;
      if (manager === 'pip') {
        const m = p.split(';')[0].trim().match(/^([^\s[=<>!~;]+)\s*(\[[^\]]*\])?\s*(.*)$/);
        if (!m || (m[3] && !/^[=<>!~]/.test(m[3]))) return { skip: 'invalid' };
        name = m[1].toLowerCase();
        const ex = m[3].match(/^===?\s*([\w.+!-]+)$/);
        if (ex) { version = ex[1]; exact = true; }
      } else {
        const at = p.lastIndexOf('@');
        name = at > 0 ? p.slice(0, at) : p;
        const v = at > 0 ? p.slice(at + 1) : '';
        if (/^\d+\.\d+\.\d+([-+][\w.-]+)?$/.test(v)) { version = v; exact = true; }
      }
      if (!/^(@[\w.-]+\/)?[\w.-]+$/.test(name)) return { skip: 'invalid' };
      if (!exact) version = M.scanFixtures.latest[`${manager}:${name}`] || '1.0.0'; // 목업: 레지스트리 최신 대신 고정값
      return { manager, name, version, exact, label: `${manager} ${name}${exact ? (manager === 'pip' ? '==' : '@') + version : ''}` };
    },
    autoScan(s) {
      if (s.refusedBy) return null;
      const t = srv.autoScanTarget(s.manager, s.packages[0] || '');
      s.scanId = null; s.scanSkip = '';
      if (t.skip) { s.scanSkip = t.skip; return null; }
      const same = (x) => x.target.kind === 'package' && x.target.manager === t.manager && x.target.name.toLowerCase() === t.name && (x.target.version || '') === t.version;
      const hit = state.scans.find((x) => same(x) && (x.status === 'running' || (x.status === 'done' && Date.now() - Date.parse(x.finishedAt) < 86400e3)));
      if (hit) { s.scanId = hit.id; return hit.id; }
      if (!srv.scannerUp) { s.scanSkip = 'off'; return null; }
      if (state.scans.filter((x) => x.status === 'running').length >= srv.scanSlots) { s.scanSkip = 'busy'; return null; }
      s.scanId = srv.scanStart({ kind: 'package', manager: t.manager, name: t.name, version: t.version }, { trigger: 'install', label: t.label, installId: s.id }).id;
      return s.scanId;
    },
    // 설치 세션 응답의 scan — 읽을 때 계산(API 계약 11/04). 옛 세션(scanId · scanSkip 없음)은 null → 필드를 두지 않는다
    scanOfSession(s) {
      if (s.scanSkip) return { id: '', status: 'skipped', label: `${s.manager} ${s.packages[0] || ''}`, version: '', riskScore: null, installThreats: 0, threats: 0, vulnCount: 0, error: '', skip: s.scanSkip, reused: false };
      const sc = s.scanId && state.scans.find((x) => x.id === s.scanId); if (!sc) return null;
      const v = srv.scanView(sc, false);
      const out = { id: sc.id, status: sc.status, label: sc.target.label, version: sc.target.version || '', riskScore: sc.risk ? sc.risk.score : null, installThreats: v.installThreats, threats: v.threats, vulnCount: v.vulnCount, error: sc.error || '', skip: '', reused: sc.installId !== s.id };
      if (sc.status === 'done') out.verdict = sc.verdict;
      return out;
    },
    // 차단 목록에 올리기: 공급망 검사 건(source scan)을 열고 「악성」으로 판정 → 패키지 차단 제안(기존 흐름: 미리보기 → 적용)
    // body.packages [W4 · 10/20 G]: 저장소 · 파일 검사 결과에서 고른 패키지 [{manager?, name, version?}] — 비우면 패키지 검사의 그 패키지(지금처럼 한 번에)
    scanBlock(id, body, reason) {
      const sc = state.scans.find((x) => x.id === id); if (!sc) throw httpErr(404, '검사 없음');
      const picked = body && Array.isArray(body.packages) && body.packages.length ? body.packages : null;
      if (!picked && sc.target.kind !== 'package') throw httpErr(400, '저장소 · 파일 검사는 차단할 패키지를 고르세요(packages)');
      let keys;
      if (picked) {
        keys = [];
        for (const p of picked) {
          const hit = (sc.packages || []).find((x) => x.name === p.name && (!p.manager || x.manager === p.manager));
          const mgr = p.manager || (hit && hit.manager); if (!hit || !mgr) throw httpErr(400, `검사 결과에 없거나 차단 목록이 다루지 않는 패키지: ${p.name}`);
          const k = M.pkgKey(mgr, p.name); if (!keys.includes(k)) keys.push(k);
        }
      } else keys = [M.pkgKey(sc.target.manager, sc.target.name)];
      // 고른 패키지마다 새 건(공급망 검사 건 하나에 패키지 여러 개) — 같은 묶음을 다시 올리면 열린 제안을 돌려준다
      const sig = keys.join(' ');
      let c = state.cases.find((x) => x.source === 'scan' && x.scanId === sc.id && (x.packages || [x.package]).join(' ') === sig);
      if (!c) {
        c = { id: nextId('case', 'case'), source: 'scan', installId: null, scanId: sc.id, container: '', label: picked ? `${sc.target.label} · 패키지 ${keys.length}개` : sc.target.label, image: '', package: keys[0], packages: keys,
          openedAt: iso(), level: sc.verdict === 'malicious' ? 'killed' : 'alert', violations: picked ? keys.length : sc.findings.filter((f) => f.category === 'threat').length, ruleIds: picked ? ['osv-vulnerable'] : [...new Set(sc.findings.filter((f) => f.category === 'threat').map((f) => f.rule))], state: 'open', decision: 'pending', decidedAt: null, decidedBy: null, note: '', proposalId: null, closedAt: null };
        state.cases.unshift(c); if (!picked) sc.caseId = c.id;
      }
      if (c.proposalId) return { proposalId: c.proposalId, caseId: c.id };
      const { proposal } = srv.decide(c.id, { decision: 'malicious', note: reason || (picked ? `공급망 검사 ${sc.id} — 고른 패키지 ${keys.join(', ')}` : `공급망 검사 ${sc.id} — 위험 점수 ${sc.risk ? sc.risk.score : '—'}`) });
      return { proposalId: proposal.id, caseId: c.id };
    },
    // eBPF 수집 종합(10/16) — GET /api/summary?range=1h|24h|7d. 저장된 기록(감사 로그 · 세션 · 건 · 차단 목록) + 1분 단위 수집량
    overview(range) {
      const R = { '1h': [60, 60], '24h': [24, 3600], '7d': [28, 21600] }[range] || [24, 3600];
      const [n, step] = R, stepMs = step * 1000, end = Math.ceil(Date.now() / stepMs) * stepMs, from = end - n * stepMs;
      // 켜기 전 수집량은 목업용 합성값(하루 주기 + 결정적 잡음), 켠 뒤는 실제로 흘러간 시뮬레이션 이벤트
      const synth = (m, k) => { const base = { exec: 18, open: 120, connect: 34, dns: 9 }[k]; const day = 0.65 + 0.35 * Math.sin(((m % 1440) / 1440) * 2 * Math.PI - 1.2); const noise = ((Math.imul(m ^ { exec: 7, open: 13, connect: 29, dns: 11 }[k], 2654435761) >>> 0) % 100) / 100; return Math.round(base * day * (0.8 + 0.4 * noise)); };
      const series = Array.from({ length: n }, (_, i) => ({ t: new Date(from + i * stepMs).toISOString(), exec: 0, open: 0, connect: 0, dns: 0, killed: 0, alert: 0 }));
      const bi = (ms) => Math.floor((ms - from) / stepMs);
      for (let m = Math.floor(from / 60000); m < Math.floor(end / 60000); m++) {
        const b = series[bi(m * 60000)]; if (!b) continue;
        const live = sim.collectedLive.get(m);
        for (const k of KINDS) b[k] += m < sim.bootMinute ? synth(m, k) : live ? live[k] || 0 : 0;
      }
      const rows = state.audit.filter((a) => Date.parse(a.event.timestamp) >= from);
      const vio = { total: rows.length, killed: 0, alert: 0, held: 0 };
      const byRule = new Map(), byCtr = new Map(), isolated = new Set();
      for (const a of rows) {
        const l = levelOf(a); vio[l === 'normal' ? 'alert' : l]++;
        const b = series[bi(Date.parse(a.event.timestamp))]; if (b) b[l === 'killed' || l === 'held' ? 'killed' : 'alert']++;
        if (l === 'killed') isolated.add(a.event.containerName);
        const top = (m, k) => { const x = m.get(k) || { count: 0, level: 'alert' }; x.count++; if (SEV_ORDER.indexOf(l) > SEV_ORDER.indexOf(x.level)) x.level = l; m.set(k, x); };
        if (a.ruleId) top(byRule, a.ruleId); top(byCtr, a.install ? a.install.label : a.event.containerName);
      }
      const sorted = (m, key) => [...m.entries()].sort((x, y) => y[1].count - x[1].count || String(x[0]).localeCompare(String(y[0]))).slice(0, 10).map(([k, v]) => ({ [key]: k, count: v.count, level: v.level }));
      const ins = state.installs.filter((x) => Date.parse(x.startedAt) >= from).map((x) => M.statusOf(x));
      const st = (k) => ins.filter((x) => x === k).length;
      const dec = state.cases.filter((c) => c.decidedAt && Date.parse(c.decidedAt) >= from);
      const collected = { total: 0, byKind: { exec: 0, open: 0, connect: 0, dns: 0 } };
      for (const b of series) for (const k of KINDS) { collected.byKind[k] += b[k]; collected.total += b[k]; }
      // 격리 지연 [10/30 계약 §3] — 범위 안 killedAt 이 있는 행, ms = killedAt − detectedAt. 없으면 count 0 · 나머지 null
      const lat = rows.filter((a) => a.timeline && a.timeline.killedAt).map((a) => Date.parse(a.timeline.killedAt) - Date.parse(a.timeline.detectedAt)).sort((x, y) => x - y);
      const q = (p) => (lat.length ? lat[Math.min(lat.length - 1, Math.ceil(p * lat.length) - 1)] : null);
      const isolation = { count: lat.length, medianMs: lat.length ? (lat.length % 2 ? lat[(lat.length - 1) / 2] : Math.round((lat[lat.length / 2 - 1] + lat[lat.length / 2]) / 2)) : null, p95Ms: q(0.95), maxMs: lat.length ? lat[lat.length - 1] : null };
      return { range: ['1h', '24h', '7d'].includes(range) ? range : '24h', from: new Date(from).toISOString(), to: new Date(end).toISOString(), bucketSec: step,
        collected, violations: vio, isolatedContainers: isolated.size, isolation, series, topRules: sorted(byRule, 'ruleId'), topContainers: sorted(byCtr, 'container'),
        installs: { total: ins.length, passed: st('passed'), isolated: st('isolated'), warned: st('warned'), refused: st('refused'), failed: st('failed') + st('unknown'), running: st('running') },
        decisions: { malicious: dec.filter((c) => c.decision === 'malicious').length, falsePositive: dec.filter((c) => c.decision === 'false_positive').length, pending: state.cases.filter((c) => c.state === 'open').length },
        blocklist: { packages: state.blocklist.packages.length, images: state.blocklist.images.length, hosts: state.blocklist.hosts.length } };
    },
    summary(changes) {
      if (!changes.length) return '변경 없음 (건만 종결)';
      const parts = [];
      for (const ch of changes.filter((x) => x.op === 'block' && x.list !== 'hosts')) parts.push(`${LIST_LABEL[ch.list]} ${ch.value} 차단`);
      const hosts = changes.filter((x) => x.op === 'block' && x.list === 'hosts').length; if (hosts) parts.push(`도메인 ${hosts}개 차단`);
      const ex = changes.filter((x) => x.op === 'except'); if (ex.length) parts.push(`예외 ${ex.length}개 (${[...new Set(ex.map((x) => x.ruleId))].join(', ')})`);
      return parts.join(' · ');
    },
    // 적용 — 한 번에: 차단 목록 추가 · 규칙 필드에 값 추가 · 엔진 리로드(state.rules 교체) · Change 기록 · 제안 applied · 건 closed
    // reason [10/20 B]: 확인 대화상자의 사유(선택) — 변경 이력(Change.reason)에 남는다. 계약 추가(안): POST …/apply {reason?}
    apply(id, at, reason) {
      const p = state.proposals.find((x) => x.id === id); if (!p) throw httpErr(404, '제안 없음');
      if (p.state !== 'draft') throw httpErr(409, '초안이 아닌 제안');
      const t = iso(at), c = srv.caseById(p.caseId);
      state.rules = srv.rulesWith(p.changes);
      for (const ch of p.changes) if (ch.op === 'block' && !state.blocklist[ch.list].some((x) => x.value === ch.value)) state.blocklist[ch.list].push({ value: ch.value, caseId: p.caseId, at: t, by: actor() });
      const chg = { id: nextId('chg', 'chg'), at: t, by: actor(), kind: 'proposal_applied', caseId: p.caseId, proposalId: p.id, summary: srv.summary(p.changes), reason: reason || '' };
      state.changes.unshift(chg);
      p.state = 'applied'; p.appliedAt = t; p.appliedBy = actor();
      if (c) { c.state = 'closed'; c.closedAt = t; }
      return { proposal: clone(p), case: c ? clone(c) : null, change: clone(chg) };
    },
    discard(id, reason) {
      const p = state.proposals.find((x) => x.id === id); if (!p) throw httpErr(404, '제안 없음');
      if (p.state !== 'draft') throw httpErr(409, '초안이 아닌 제안');
      const c = srv.caseById(p.caseId); p.state = 'discarded'; p.reason = reason || '';
      if (c) { c.state = 'closed'; c.closedAt = iso(); }
      return { proposal: clone(p), case: c ? clone(c) : null };
    },
    unblock(list, value, reason) {
      const arr = state.blocklist[list]; if (!arr) throw httpErr(400, 'list 는 packages | images | hosts');
      const i = arr.findIndex((x) => x.value === value); if (i < 0) throw httpErr(404, '차단 목록에 없음');
      const [entry] = arr.splice(i, 1);
      if (list === 'hosts') { const r = state.rules.find((x) => x.id === M.SYSTEM_RULE); if (r) r.denyHosts = (r.denyHosts || []).filter((x) => x !== value); }
      if (list === 'images') for (const c of sim.containers) if (c.image === value) c.blockedImage = false; // 다음 재기동부터 다시 뜬다
      state.changes.unshift({ id: nextId('chg', 'chg'), at: iso(), by: actor(), kind: 'blocklist_remove', caseId: entry.caseId, proposalId: null, summary: `${LIST_LABEL[list]} ${value} 차단 해제`, reason: reason || '' });
    },
    recordChange(kind, summary) { state.changes.unshift({ id: nextId('chg', 'chg'), at: iso(), by: actor(), kind, caseId: null, proposalId: null, summary }); },
    // ── 영향 미리 계산 [10/20 B] — 확인 대화상자의 「함께 일어나는 일」. 모의 서버 상태만 읽는다(바꾸지 않음) ──
    sameImage(image) { return sim.containers.filter((x) => x.image === image).length; },
    // 판정 미리보기 [10/20 결정 7] — POST /api/cases/{id}/preview {decision} → {changes, effects:[{kind, text}]}. 상태를 바꾸지 않는다(판정 전 「함께 일어나는 일」)
    //   kind: proposal(만들 제안 초안) · image(같은 이미지 컨테이너) · case(건 상태 · 처리자) · note(자동으로 못 만든 것 안내). 열린 건만(판정된 건 409), decision 이 틀리면 400 — decide 와 같은 규칙
    casePreview(id, body) {
      const c = srv.caseById(id);
      if (!c) throw httpErr(404, '건 없음');
      if (c.state !== 'open') throw httpErr(409, '이미 판정된 건');
      const decision = body && body.decision;
      if (!['malicious', 'false_positive'].includes(decision)) throw httpErr(400, 'decision 은 malicious | false_positive');
      const { changes, notes } = srv.proposalChanges(c, decision);
      const effects = [], add = (kind, text) => effects.push({ kind, text });
      const blocks = changes.filter((x) => x.op === 'block'), ex = changes.filter((x) => x.op === 'except');
      if (decision === 'malicious') add('proposal', blocks.length ? `차단 제안 초안 — ${blocks.map((x) => `${LIST_LABEL[x.list]} ${x.value}`).join(' · ')} (아직 차단 목록에 넣지 않음, 정책에서 미리보기 후 적용)` : '새로 차단할 대상이 없습니다(이미 차단 목록에 있음) — 적용하면 건만 종결');
      else add('proposal', ex.length ? `예외 제안 초안 — ${ex.map((x) => `${x.ruleId} ${x.field} += ${x.value}`).join(' · ')} (정책에서 미리보기 후 적용)` : '자동 예외가 없습니다 — 정책 탭에서 직접 고칩니다');
      const img = blocks.find((x) => x.list === 'images');
      if (img) add('image', `적용하면 같은 이미지 컨테이너 ${srv.sameImage(img.value)}개가 다음 시작 때 격리됩니다`);
      add('case', `건 ${c.id} 판정 대기 → ${decision === 'malicious' ? '악성' : '오탐'} (판정 · 변경 이력에 처리자 ${actor()})`);
      for (const n of notes) add('note', n);
      return { changes: clone(changes), effects };
    },
    impactApply(p, pv) {
      const out = [], blocks = p.changes.filter((x) => x.op === 'block'), ex = p.changes.filter((x) => x.op === 'except');
      if (blocks.length) { const by = (l) => blocks.filter((x) => x.list === l).length; out.push(`차단 목록 +${blocks.length} (${['packages', 'images', 'hosts'].filter(by).map((l) => `${LIST_LABEL[l]} ${by(l)}`).join(' · ')})`); }
      for (const b of blocks.filter((x) => x.list === 'packages')) out.push(`다음 sg-install 부터 ${b.value} 는 설치 전 거부(컨테이너를 띄우지 않음)`);
      for (const b of blocks.filter((x) => x.list === 'images')) out.push(`같은 이미지 컨테이너 ${srv.sameImage(b.value)}개 다음 시작 때 격리 (${b.value})`);
      if (blocks.some((x) => x.list === 'hosts')) out.push(`도메인 차단은 시스템 규칙 ${M.SYSTEM_RULE} 로 바로 집행(런타임 · 설치 모두)`);
      if (ex.length) out.push(`규칙 예외 +${ex.length} (${[...new Set(ex.map((x) => x.ruleId))].join(', ')}) — 엔진에 바로 반영`);
      if (pv && !pv.error) out.push(`과거 위반 ${pv.changed.length}건의 탐지 결과가 바뀜 (통과로 ${pv.counts.toNormal} · 차단으로 ${pv.counts.toBlocked})`);
      out.push(`건 ${p.caseId} 종결 · 변경 이력에 남음`);
      return out;
    },
    impactUnblock(list, value) {
      if (list === 'packages') return [`다음 설치부터 ${value} 를 다시 설치할 수 있습니다(설치 검사는 그대로 감시)`, '변경 이력에 「차단 해제」로 남습니다'];
      if (list === 'images') return [`같은 이미지 컨테이너 ${srv.sameImage(value)}개가 다음 재기동부터 다시 뜹니다`, '변경 이력에 「차단 해제」로 남습니다'];
      return [`시스템 규칙 ${M.SYSTEM_RULE} 에서 ${value} 를 빼 바로 통신을 허용합니다`, '변경 이력에 「차단 해제」로 남습니다'];
    },
    // ── 새 기본 규칙 [10/20 F] — GET /api/policies/defaults: 기본 정책 파일(M.defaultRules)과 지금 규칙 비교. 설명 · 꺼짐 · dryRun 은 사용자 값이라 비교하지 않는다 ──
    policyDefaults() {
      // 키 정렬은 안쪽 객체까지 [11/04 — 연쇄 규칙 steps 의 단계 객체가 YAML 왕복으로 키 순서가 바뀌어도 같게]
      const sortKeys = (v) => (Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.keys(v).sort().reduce((o, k) => { o[k] = sortKeys(v[k]); return o; }, {}) : v);
      const norm = (r) => { const x = clone(r); delete x.description; delete x.disabled; delete x.dryRun; return JSON.stringify(sortKeys(x)); };
      const cur = new Map(state.rules.map((r) => [r.id, r]));
      const missing = [], differs = [];
      for (const d of M.defaultRules) { const c = cur.get(d.id); if (!c) missing.push(clone(d)); else if (norm(c) !== norm(d)) differs.push({ id: d.id, default: clone(d), current: clone(c) }); }
      return { missing, differs };
    },
    // ── 증거 [10/20 I] — kill 직전에 모은 로그 · docker diff · docker top (GET /api/evidence?container=) ──
    collectEvidence(c, at, session) {
      const tpl = session ? M.evidenceTemplate.install(`${session.manager} ${session.packages.join(' ')}`) : M.evidenceTemplate.runtime();
      const ev = Object.assign({ id: `ev-${String(state.evidence.size + 1).padStart(4, '0')}-${Math.floor(at / 1000)}`, containerId: c.id, containerName: c.name, image: c.image, collectedAt: iso(at) }, tpl);
      state.evidence.set(c.name, [ev].concat(state.evidence.get(c.name) || []));
    },
    // ── 알림 테스트 발송 [10/20 H] — POST /api/notify/test → 202. 발송은 비동기라 1~2초 뒤 /api/info 의 sent · failed 를 다시 읽는다 ──
    notifyTest() {
      const n = state.info.notify; if (!n || !n.enabled) throw httpErr(409, '알림 채널이 없습니다 — NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL 을 설정하세요');
      setTimeout(() => { for (const ch of n.channels) { if (ch.lastError) { ch.failed++; n.failed++; } else { ch.sent++; n.sent++; ch.lastAt = iso(); } } state.server = serverFromInfo(state.info); emit(); }, 900);
      return clone(n);
    },
    blocklistCheck(manager, pkg) {
      const value = M.pkgKey(manager, pkg); const e = state.blocklist.packages.find((x) => x.value === value);
      return { blocked: !!e, value, caseId: e ? e.caseId : null };
    },
    // ── 시연 실행 [10/30 계약 §2] — GET /api/demo · POST /api/demo/run {scenario}. DEMO_ENABLED(state.info.demo) 가 아니면 404.
    //   mock 소스: 컨테이너 없이 같은 세션(pip ./reqeusts, sg-install-demo-<unix>) · 같은 이벤트 순서를 모의 재생(simulated: true), 첫 kill 판정에서 멈춘다.
    //   ① 차단 목록이면 거부 세션 + status refused ② 세션 생성 ③~⑤ 이벤트 재생 → finish ⑥ 동시 1개(running 이면 409) ⑦ 변경 이력 demo_run ──
    demo: { running: null, last: null, timer: 0 },
    demoGet() {
      if (!state.info.demo) throw Object.assign(httpErr(404, 'Not Found'), { json: false });
      return { enabled: true, scenarios: M.DEMO_SCENARIOS.slice(), running: srv.demo.running ? clone(srv.demo.running) : null, last: srv.demo.last ? clone(srv.demo.last) : null };
    },
    demoRun(body) {
      if (!state.info.demo) throw Object.assign(httpErr(404, 'Not Found'), { json: false });
      const scenario = body && body.scenario;
      if (!M.DEMO_SCENARIOS.includes(scenario)) throw httpErr(400, 'scenario: all | shell | revshell | direct-ip | domain | dns-exfil');
      if (srv.demo.running) throw Object.assign(httpErr(409, '시연이 이미 실행 중입니다'), { running: clone(srv.demo.running) });
      const unix = Math.floor(Date.now() / 1000);
      const run = { id: `demo-${unix}`, scenario, container: `sg-install-demo-${unix}`, installId: null, startedAt: iso(), finishedAt: null, status: 'running', exitCode: null, simulated: true };
      srv.recordChange('demo_run', `시연 실행: ${scenario}`);
      const chk = srv.blocklistCheck('pip', './reqeusts');
      if (chk.blocked) { // sg-install 처럼 거부 세션(refused)만 남긴다 — 화면은 「차단 목록에 있어 설치 전 거부됨 — 차단 해제 후 다시」
        run.installId = srv.installsRefused({ manager: 'pip', packages: ['./reqeusts'], value: chk.value }).id;
        Object.assign(run, { status: 'refused', finishedAt: iso(), exitCode: 3 }); srv.demo.last = run; emit(); return clone(run);
      }
      const s = M.newSession({ manager: 'pip', pkg: './reqeusts' }, Date.now(), ++state.installSeq);
      s.container = run.container; s.demo = true; state.installs.unshift(s); run.installId = s.id; srv.autoScan(s); // 11/04: ./reqeusts 는 로컬 — 건너뜀
      srv.demo.running = run; emit();
      const c = { name: s.container, image: s.image, id: s.containerId, killedAt: 0 };
      const events = [...M.demoSpecs.dnsExfil.events.slice(0, 2), ...M.demoEvents(scenario).map((a) => [a, 1])]; // pip install · pypi 연결 → 시나리오
      let i = 0;
      const finish = (status) => {
        const end = iso(); s.containerExitedAt = end; s.finishedAt = end; s.exitCode = c.killedAt ? 137 : 0;
        Object.assign(run, { status: status || 'finished', finishedAt: end, exitCode: s.exitCode }); srv.demo.last = run; srv.demo.running = null; srv.demo.timer = 0; emit();
      };
      const step = () => {
        if (c.killedAt || i >= events.length) { srv.demo.timer = setTimeout(() => finish(), 500); return; } // 첫 kill 판정에서 멈춘다(실제와 같게)
        const [tpl, n] = events[i++];
        if (!(tpl.kind === 'dns' && dnsOff())) { const at = Date.now(); const v = pipeline(c, mkEvent(c, tpl, at), at, { count: n, session: s }); M.addToSession(s, v.event, v, n); srv.syncInstallCase(s); emit(); }
        srv.demo.timer = setTimeout(step, 450);
      };
      srv.demo.timer = setTimeout(step, 900); // ① 컨테이너 시작 → ② 설치 진행(pip 이벤트) → ③ 시나리오 이벤트
      return clone(run);
    },
    installsRefused(body) {
      const at = Date.now(), s = M.newSession({ manager: body.manager, pkg: (body.packages || [])[0] }, at, ++state.installSeq);
      Object.assign(s, { packages: body.packages || [], container: null, containerId: null, image: null, finishedAt: iso(at), exitCode: 3, refusedBy: { list: 'packages', value: body.value } });
      state.installs.unshift(s);
      return { id: s.id };
    },
  };
  // 시드: 어제 격리된 세션(colourama · crossenv)은 이미 「악성」으로 판정 · 적용돼 있다 — 차단 목록 · 변경 이력이 비어 있지 않게 [10/15 목표]
  [...state.installs].sort((a, b) => Date.parse(a.startedAt) - Date.parse(b.startedAt)).forEach((s) => {
    srv.syncInstallCase(s);
    const c = srv.caseById(s.caseId); if (!c) return;
    c.openedAt = s.containerExitedAt || s.startedAt;
    if (M.statusOf(s) === 'isolated') srv.collectEvidence({ id: s.containerId, name: s.container, image: s.image }, Date.parse(s.containerExitedAt || s.startedAt), s); // 시드 격리 세션의 증거
    if (!s.seedDecided) return;
    const t = Date.parse(s.startedAt) + s.seedDecided.afterMins * 60000;
    const { proposal } = srv.decide(c.id, { decision: s.seedDecided.decision, note: '' }, t);
    srv.apply(proposal.id, t + 60000);
  });
  // 시드: 연쇄 규칙 예시 행 [11/04 결정] — 실제 백엔드처럼 런타임 격리 대상 → 건 → 「악성」 판정 · 종결된 과거 건으로 묶는다.
  //   제안 · 차단 목록 · 변경 이력은 만들지 않는다(다른 시드 값이 그대로이게)
  {
    const a = state.audit.find((x) => x.sequence && !x.caseId);
    if (a) {
      const at = Date.parse(a.event.timestamp), c = srv.touchRuntimeCase(a.event, a, at, false);
      a.caseId = c.id;
      Object.assign(c, { state: 'closed', decision: 'malicious', decidedAt: iso(at + 7 * 60000), decidedBy: '보안 담당자', closedAt: iso(at + 8 * 60000) });
    }
  }

  // ── 화면이 쓰는 데이터 API — sim 은 모의 서버(srv), live 는 REST (frontend/src/lib/api.ts 와 같은 계약) ──
  // 계약: Claude Docs 「SupplyGuard 개발 문서」 › 「API 계약」 탭(엔드포인트 표). 이름 · 모양을 그대로 따른다 [10/15 목표]
  //   CLI (Authorization: Bearer SANDBOX_TOKEN — mock 소스는 토큰 없이)
  //     POST /api/installs {manager, packages[], container, image} → {id}   ·  PUT /api/installs/{id}/finish {exitCode}
  //     GET  /api/blocklist/check?manager&package → {blocked, value, caseId}  ·  POST /api/installs/refused {manager, packages[], value} → {id}
  //   화면 (쿠키 세션 — 쓰기는 관리자 역할, 조회자는 403)
  //     GET  /api/installs?status&manager&limit · GET /api/installs/{id}
  //     GET  /api/cases?state&source · GET /api/cases/{id} · POST /api/cases/{id}/decide {decision, note} → {case, proposal} (판정된 건 409)
  //     POST /api/cases/{id}/preview {decision} → {changes, effects:[{kind, text}]} — 판정 전 「함께 일어나는 일」, 상태 안 바뀜(판정된 건 409 · 조회자 허용) [10/20 결정 7]
  //     POST /api/proposals/{id}/apply {reason?} · …/discard {reason?} · DELETE /api/blocklist/{list}/{value} {reason?} → 변경 이력 Change.reason [10/20 결정 7 — 이름 확인]
  //     GET  /api/proposals?state · POST /api/proposals/{id}/preview → {evaluated, changed[], counts} · POST …/apply · POST …/discard (draft 아니면 409)
  //     GET  /api/blocklist · DELETE /api/blocklist/{list}/{value} · GET /api/changes?limit · GET /api/osv?ecosystem&name
  //   결과 미확인: 컨테이너가 끝난 뒤 10분 안에 finish 보고가 없으면 백엔드가 unknown 으로 둔다
  // 실제 백엔드 모드는 같은 경로를 쿠키 세션으로 부른다 [10/21 React 맞춤]. 라우트가 없으면(404 텍스트 · 501) 그 영역만 「백엔드 미지원」
  const installView = (s) => { const v = Object.assign(clone(s), { status: M.statusOf(s), violationCount: s.violations.reduce((n, x) => n + (x.count || 1), 0) }); delete v.seedDecided; delete v.scanSkip; const sc = srv.scanOfSession(s); if (sc) v.scan = sc; return v; }; // scan: 11/04 종합 판정(scanId 는 저장 필드, scanSkip 은 scan.skip 으로)
  const unsupportedErr = (what) => Object.assign(new Error(`백엔드 미지원 — ${what || '설치 세션 API(GET /api/installs)'}가 아직 백엔드에 없습니다`), { unsupported: true });
  const isUnsupported = (e) => !!e && ((e.status === 404 && !e.json) || e.status === 501);
  // 모의 서버 응답 [10/20]: ?latency 만큼 늦게 · ?fail 에 있는 이름은 한 번 실패 · 조회자의 쓰기는 403(실제 백엔드 auth 미들웨어와 같은 문구)
  const simCall = (name, fn, write) => (...args) => {
    const run = () => {
      if (failHit(name)) throw httpErr(503, '모의 오류 — 서버가 응답하지 않습니다');
      if (write && state.auth && state.auth.user && state.auth.user.role !== 'admin') throw httpErr(403, '조회자는 읽기만 할 수 있습니다');
      return fn(...args);
    };
    // 지연이 없으면 예전처럼 마이크로태스크로 바로 답한다(화면 반응 · 기존 회귀의 타이밍 유지)
    return LATENCY ? new Promise((ok, no) => setTimeout(() => { try { ok(run()); } catch (e) { no(e); } }, LATENCY)) : Promise.resolve().then(run);
  };
  // simOr: sim 은 모의 서버(fn), live 는 실제 백엔드(liveFn — fetchJSON). live 가 라우트 없음이면 「백엔드 미지원」 오류로 바꾼다
  const simOr = (what, fn, liveFn, name, write) => { const f = simCall(name || '', fn, write); return (...args) => (state.source === 'live' ? Promise.resolve().then(() => liveFn(...args)).catch((e) => Promise.reject(isUnsupported(e) ? unsupportedErr(what) : e)) : f(...args)); };
  const qs = (p) => { const q = new URLSearchParams(); for (const [k, v] of Object.entries(p || {})) if (v !== undefined && v !== null && v !== '') q.set(k, String(v)); const t = q.toString(); return t ? `?${t}` : ''; };
  const enc = encodeURIComponent;
  const post = (path, body, method) => fetchJSON(path, { method: method || 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  // 실제 백엔드의 nil 슬라이스(null)를 화면이 쓰는 빈 값으로
  const scanNorm = (d) => Object.assign(d, { findings: d.findings || [], vulns: d.vulns || [], packages: d.packages || [], files: d.files || {}, engines: d.engines || [] });
  const installNorm = (x) => Object.assign(x, { packages: x.packages || [], violations: x.violations || [], activity: Object.assign({ kinds: { exec: 0, open: 0, connect: 0, dns: 0 }, hosts: [], programs: [] }, x.activity || {}) });
  const caseNorm = (c) => Object.assign(c, { ruleIds: c.ruleIds || [] });
  const WRITE = true;
  const osvCache = new Map();
  // OSV 조회 이름: 매니저 → 생태계, 패키지는 정규화(로컬 디렉터리 basename · 버전 표기 제거)
  const osvQuery = (manager, pkg) => ({ ecosystem: M.ECOSYSTEM[manager] || manager, name: M.pkgName(pkg) });
  const api = {
    installs: simOr(null, (p) => { const q = p || {}; return state.installs.map(installView).filter((s) => (!q.status || s.status === q.status) && (!q.manager || s.manager === q.manager)).slice(0, Math.min(q.limit || 50, 500)); }, (p) => fetchJSON(`/api/installs${qs(Object.assign({ limit: 500 }, p))}`).then((r) => (r || []).map(installNorm)), 'installs'), // 최신순, 기본 50 · 상한 500 (live 는 React 처럼 500)
    install: simOr(null, (id) => { const s = state.installs.find((x) => x.id === id); if (!s) throw httpErr(404, '세션 없음'); return installView(s); }, (id) => fetchJSON(`/api/installs/${enc(id)}`).then(installNorm)),
    blocklistCheck: simOr('차단 확인 API(GET /api/blocklist/check)', (p) => srv.blocklistCheck(p.manager, p.package), (p) => fetchJSON(`/api/blocklist/check${qs({ manager: p.manager, package: p.package })}`)),
    installsRefused: simOr('거부 보고 API(POST /api/installs/refused)', (body) => { const r = srv.installsRefused(body); emit(); return r; }, (body) => post('/api/installs/refused', body)),
    cases: simOr('판정 API(GET /api/cases)', (p) => { const q = p || {}; return clone(state.cases.filter((c) => (!q.state || c.state === q.state) && (!q.source || c.source === q.source))); }, (p) => fetchJSON(`/api/cases${qs({ state: (p || {}).state, source: (p || {}).source })}`).then((r) => (r || []).map(caseNorm))),
    case: simOr('판정 API(GET /api/cases)', (id) => { const c = srv.caseById(id); if (!c) throw httpErr(404, '건 없음'); return clone(c); }, (id) => fetchJSON(`/api/cases/${enc(id)}`).then(caseNorm)),
    decide: simOr('판정 API(POST /api/cases/{id}/decide)', (id, body) => { const r = srv.decide(id, body); emit(); return r; }, (id, body) => post(`/api/cases/${enc(id)}/decide`, { decision: body && body.decision, note: (body && body.note) || '' }), 'decide', WRITE),
    proposals: simOr('제안 API(GET /api/proposals)', (p) => { const q = p || {}; return clone(state.proposals.filter((x) => !q.state || x.state === q.state)); }, (p) => fetchJSON(`/api/proposals${qs({ state: (p || {}).state })}`).then((r) => (r || []).map((x) => Object.assign(x, { changes: x.changes || [], notes: x.notes || [] })))),
    preview: simOr('제안 API(POST /api/proposals/{id}/preview)', (id) => srv.preview(id), (id) => fetchJSON(`/api/proposals/${enc(id)}/preview`, { method: 'POST' }).then((r) => Object.assign(r, { changed: r.changed || [], nextOnly: r.nextOnly || [] }))),
    scans: simOr('공급망 검사 API(GET /api/scans)', () => state.scans.map((x) => srv.scanView(x, false)), () => fetchJSON('/api/scans').then((r) => r || []), 'scans'),
    scan: simOr('공급망 검사 API(GET /api/scans/{id})', (id) => { const x = state.scans.find((y) => y.id === id); if (!x) throw httpErr(404, '검사 없음'); return srv.scanView(x, true); }, (id) => fetchJSON(`/api/scans/${enc(id)}`).then(scanNorm)),
    // live 파일 검사는 multipart(kind=file, file=…) — React api.startScan 과 같다
    startScan: simOr('공급망 검사 API(POST /api/scans)', (body) => { const r = srv.scanStart(body); emit(); return r; }, (body) => { if (body && body.kind === 'file') { const fd = new FormData(); fd.append('kind', 'file'); if (body.file) fd.append('file', body.file, body.fileName); return fetchJSON('/api/scans', { method: 'POST', body: fd }); } return post('/api/scans', body); }, 'startScan', WRITE),
    // body = {packages:[{manager?, name, version?}]} (저장소 · 파일 검사) · 없으면 패키지 검사의 그 패키지. reason 은 계약 추가(안)
    scanBlock: simOr('공급망 검사 API(POST /api/scans/{id}/block)', (id, body, reason) => { const r = srv.scanBlock(id, body, reason); emit(); return r; }, (id, body, reason) => post(`/api/scans/${enc(id)}/block`, Object.assign({}, body && body.packages ? { packages: body.packages } : {}, reason ? { reason } : {})), 'scanBlock', WRITE),
    summary: (range) => (state.source === 'live' ? fetchJSON(`/api/summary?range=${encodeURIComponent(range || '24h')}`) : Promise.resolve().then(() => srv.overview(range || '24h'))),
    previewRule: (rule) => (state.source === 'live' ? fetchJSON('/api/policies/preview', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rule) }) : Promise.resolve().then(() => srv.previewRule(rule))),
    // live 응답은 {proposal, case} — 화면 토스트가 쓰는 change.summary 는 제안의 변경으로 만든다
    apply: simOr('제안 API(POST /api/proposals/{id}/apply)', (id, body) => { const r = srv.apply(id, undefined, body && body.reason); emit(); return r; }, (id, body) => post(`/api/proposals/${enc(id)}/apply`, { reason: (body && body.reason) || '' }).then((r) => Object.assign({ change: { summary: srv.summary((r && r.proposal && r.proposal.changes) || []) } }, r)), 'apply', WRITE),
    discard: simOr('제안 API(POST /api/proposals/{id}/discard)', (id, body) => { const r = srv.discard(id, body && body.reason); emit(); return r; }, (id, body) => post(`/api/proposals/${enc(id)}/discard`, { reason: (body && body.reason) || '' }), 'discard', WRITE),
    blocklist: simOr('차단 목록 API(GET /api/blocklist)', () => clone(state.blocklist), () => fetchJSON('/api/blocklist').then((b) => ({ packages: (b && b.packages) || [], images: (b && b.images) || [], hosts: (b && b.hosts) || [] }))),
    unblock: simOr('차단 목록 API(DELETE /api/blocklist)', (list, value, body) => { srv.unblock(list, value, body && body.reason); emit(); return null; }, (list, value, body) => post(`/api/blocklist/${enc(list)}/${enc(value)}`, { reason: (body && body.reason) || '' }, 'DELETE'), 'unblock', WRITE),
    // 시연 실행 [10/30 계약 §2] — GET /api/demo(조회자 포함) · POST /api/demo/run {scenario}(관리자만: 조회자 403 · 400 · 409 · 503)
    demo: simOr('시연 API(GET /api/demo)', () => srv.demoGet(), () => fetchJSON('/api/demo'), 'demo'),
    demoRun: simOr('시연 API(POST /api/demo/run)', (body) => srv.demoRun(body), (body) => post('/api/demo/run', { scenario: body && body.scenario }), 'demoRun', WRITE),
    // 10/20 2차 시안 — 새 기본 규칙 · 증거 · 알림 테스트 · 서버 정보 (실제 백엔드에 있는 경로)
    policyDefaults: () => (state.source === 'live' ? fetchJSON('/api/policies/defaults') : simCall('defaults', () => srv.policyDefaults())()),
    evidence: (container) => (state.source === 'live' ? fetchJSON(`/api/evidence?container=${encodeURIComponent(container)}`) : simCall('evidence', () => clone(state.evidence.get(container) || []))()),
    notifyTest: () => (state.source === 'live' ? fetchJSON('/api/notify/test', { method: 'POST' }) : simCall('notifyTest', () => srv.notifyTest(), WRITE)()),
    info: () => (state.source === 'live' ? fetchJSON('/api/info').then((i) => { state.info = i; state.server = serverFromInfo(i); emit(); return i; }) : Promise.resolve(clone(state.info))),
    // 판정 미리보기 [10/20 결정 7] — 서버가 계산한다(화면 계산 impactDecide 를 모의 서버로 옮김). 조회자도 부를 수 있다(읽기)
    //   실제 백엔드에 아직 없으면(404 · 405) 안내 한 줄로 대신한다
    casePreview: (id, body) => (state.source === 'live'
      ? fetchJSON(`/api/cases/${encodeURIComponent(id)}/preview`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
        .catch((e) => (e.status === 404 || e.status === 405 ? { changes: [], effects: [{ kind: 'note', text: '판정하면 제안 초안이 생깁니다 — 정책 화면에서 미리보기 후 적용합니다(백엔드에 판정 미리보기 API 가 아직 없음)' }] } : Promise.reject(e)))
      : simCall('casePreview', () => srv.casePreview(id, body))()),
    // 적용 · 해제 확인의 영향 — 제안 미리보기 결과와 차단 목록으로 만든다(sim)
    impactApply: (p, pv) => Promise.resolve().then(() => srv.impactApply(p, pv)),
    impactUnblock: (l, v) => Promise.resolve().then(() => srv.impactUnblock(l, v)),
    changes: simOr('변경 이력 API(GET /api/changes)', (p) => clone(state.changes.slice(0, (p && p.limit) || 200)), (p) => fetchJSON(`/api/changes${qs({ limit: (p && p.limit) || 100 })}`).then((r) => r || []), 'changes'),
    // 목업은 브라우저에서 osv.dev 를 직접 부른다(CORS 허용 확인 2026-10-15). 실제 앱은 GET /api/osv. 실패해도 error 를 채워 돌려준다(화면이 깨지지 않게)
    osv: ({ ecosystem, name }) => {
      const key = `${ecosystem}:${name}`;
      if (osvCache.has(key)) return osvCache.get(key);
      const ctl = new AbortController(); const timer = setTimeout(() => ctl.abort(), 5000);
      const pr = fetch('https://api.osv.dev/v1/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ package: { name, ecosystem } }), signal: ctl.signal })
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
        .then((d) => ({ ecosystem, name, vulns: (d.vulns || []).length, ids: (d.vulns || []).map((v) => v.id), queriedAt: iso(), source: 'osv.dev', error: null }))
        .catch((e) => { osvCache.delete(key); return { ecosystem, name, vulns: null, ids: [], queriedAt: iso(), source: 'osv.dev', error: e.name === 'AbortError' ? '시간 초과(5초)' : e.message || '네트워크 오류' }; })
        .finally(() => clearTimeout(timer));
      osvCache.set(key, pr);
      return pr;
    },
    listRules: () => (state.source === 'live' ? fetchJSON('/api/policies').then((rs) => { state.rules = rs || []; return state.rules; }) : Promise.resolve(state.rules)),
    saveRule: (r) => (state.source === 'live' ? fetchJSON('/api/policies', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(r) }) : Promise.resolve().then(() => {
      if (r.id === M.SYSTEM_RULE) throw httpErr(403, '차단 목록에서 관리하는 시스템 규칙 — 직접 편집할 수 없습니다');
      // 연쇄 규칙 검사(백엔드 rules.Rule.Validate V2~V8 · V5) — 문구는 screens.js sequenceErrors 한 곳(UI.srv.ruleErrors), 오류는 모두 줄바꿈으로 422 [11/04 React 맞춤]
      const bad = srv.ruleErrors ? srv.ruleErrors(r) : []; if (bad.length) throw httpErr(422, bad.join('\n'));
      const i = state.rules.findIndex((x) => x.id === r.id); if (i >= 0) state.rules[i] = r; else state.rules.splice(Math.max(0, state.rules.findIndex((x) => x.id === M.SYSTEM_RULE)), 0, r);
      srv.recordChange('policy_edit', `정책 ${r.id} 저장`); return r;
    })),
    deleteRule: (id) => (state.source === 'live' ? fetchJSON(`/api/policies/${encodeURIComponent(id)}`, { method: 'DELETE' }) : Promise.resolve().then(() => {
      if (id === M.SYSTEM_RULE) throw httpErr(403, '차단 목록에서 관리하는 시스템 규칙 — 지울 수 없습니다');
      state.rules = state.rules.filter((x) => x.id !== id); srv.recordChange('policy_edit', `정책 ${id} 삭제`);
    })),
    exportYaml: () => (state.source === 'live' ? fetchJSON('/api/policies/export') : Promise.resolve(null)),
    applyYaml: (yaml) => (state.source === 'live' ? fetchJSON('/api/policies', { method: 'PUT', headers: { 'Content-Type': 'application/yaml' }, body: yaml }).then((rs) => { state.rules = rs; return rs; }) : Promise.resolve(null)),
    // sim 의 전체 교체(화면이 YAML 을 해석한 결과) — 시스템 규칙은 그대로 둔다
    replaceRules: (rs) => { const sys = state.rules.find((x) => x.id === M.SYSTEM_RULE); state.rules = rs.filter((x) => x.id !== M.SYSTEM_RULE).concat(sys ? [sys] : []); srv.recordChange('policy_replace', `정책 ${rs.length}개 전체 교체`); return state.rules; },
    audit: (p) => {
      if (state.source === 'live') { const q = new URLSearchParams(); for (const [k, v] of Object.entries(p)) if (v !== undefined && v !== '') q.set(k, String(v)); return fetchJSON(`/api/audit?${q}`); }
      return simCall('audit', () => auditRows(p))();
    },
  };
  function auditRows(p) {
    {
      const since = p.since ? new Date(p.since).getTime() : 0, until = p.until ? new Date(p.until).getTime() : Infinity;
      let rows = state.audit.filter((a) => { const t = new Date(a.event.timestamp).getTime(); return (!p.kind || a.event.kind === p.kind) && (!p.action || a.action === p.action) && (!p.rule || (a.ruleId || '').includes(p.rule)) && (!p.container || a.event.containerName.includes(p.container)) && t >= since && t <= until && (!p.before || a.id < p.before); });
      return clone(rows.slice(0, p.limit || 100));
    }
  }

  // ── 공통 컴포넌트 ────────────────────────────────────────
  const kindBadge = (kind) => h('span', { class: `badge badge-kind badge-kind-${kind}` }, kind);
  function verdictBadge(v) {
    const level = levelOf(v);
    const title = level === 'held' ? (v.enforceError ? `격리 실패: ${v.enforceError}` : 'dry-run — 알림만 보냄') : null;
    return h('span', { class: `badge badge-level badge-level-${level}`, title }, LEVEL_LABEL[level]);
  }
  // 숫자 카운트업(600ms) [10/30 계약 §7 모션] — el.textContent 를 from → to 로. prefers-reduced-motion 이면 바로 쓴다
  const reducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function countUp(el, to, format) {
    const f = format || ((n) => fmt.num(n)); const from = Number(el.dataset.countup || 0);
    if (!Number.isFinite(to)) { el.textContent = String(to); return; }
    el.dataset.countup = String(to);
    if (reducedMotion() || from === to || Math.abs(to - from) > 1e6) { el.textContent = f(to); return; }
    const t0 = performance.now(), dur = 600;
    const tick = (now) => { const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3); el.textContent = f(Math.round(from + (to - from) * e)); if (p < 1) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  }
  function kpi({ label, value, hint, tone, key, href }) {
    const box = h('div', { class: 'kpi', 'data-kpi': key }, h('div', { class: 'kpi-label' }, label), h('div', { class: `kpi-value num tone-${tone || 'default'}` }, value), hint ? h('div', { class: 'kpi-hint' }, hint) : null);
    return href ? h('a', { href, class: 'kpi-link' }, box) : box;
  }
  const statusBadge = (st) => h('span', { class: `badge st st-${st}`, 'data-status': st }, INSTALL_STATUS[st]);
  // 판정(사람의 결론) 배지 — pending · malicious · false_positive · none(건 없음)
  const decisionBadge = (d) => h('span', { class: `badge dec dec-${d || 'none'}`, 'data-decision': d || 'none' }, DECISION_LABEL[d || 'none']);

  // ── 판정 흐름 공통 부품 [10/15 목표] — 공격 체인 · 판정 버튼 · 미리보기 표는 여기 한 곳에만 있다 ──
  const KIND_ORDER = { exec: 1, open: 2, dns: 2.5, connect: 3 }; // dns 는 「3 통신」 단계(connect 와 같은 단계), 정렬은 dns 먼저 [10/30]
  const KIND_STEP = { exec: '1 실행', open: '2 파일', connect: '3 통신', dns: '3 통신' };
  const fakeVerdict = (level) => ({ matched: level !== 'normal', action: level === 'alert' ? 'alert' : 'kill', enforced: level === 'killed' });
  // 공격 체인: steps = [{ id?, kind, label, title?, rules[], level }]. onPick 이 있으면 단계가 버튼(토폴로지), 없으면 정적(설치 검사 시트)
  function attackChain(steps, opts) {
    const o = opts || {}, max = o.maxChars || 22; // 긴 인자 · 경로는 가운데 말줄임 — 끝(… | sh, :4444)이 보이게
    const label = (t) => ellipsize(String(t), max);
    const sorted = [...steps].sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || SEV[b.level] - SEV[a.level] || (a.at || 0) - (b.at || 0));
    return h('ol', { class: 'chain-steps', 'data-part': 'attack-chain' }, sorted.map((st) => {
      const inner = [h('span', { class: `step-no step-${st.kind}` }, KIND_STEP[st.kind]), h('span', { class: 'step-label mono', title: st.title || st.label }, label(st.label)),
        h('span', { class: 'step-rule small muted', title: (st.rules || []).join(', ') }, (st.rules || [])[0] || ''), verdictBadge(fakeVerdict(st.level))];
      return h('li', null, o.onPick ? h('button', { type: 'button', class: `chain-step ${o.selectedId && o.selectedId === st.id ? 'on' : ''}`, onclick: () => o.onPick(st) }, inner) : h('div', { class: 'chain-step static' }, inner));
    }));
  }
  // 설치 검사 시트용 단계 — 통신은 토폴로지 목적지 노드처럼 「도메인:포트」(없으면 IP:포트), 전체는 툴팁
  const chainFromVerdicts = (vs) => vs.map((v) => { const e = v.event; return { kind: e.kind, label: e.kind === 'connect' ? `${e.dstHost || e.dstIp}:${e.dstPort}` : detailOf(e), title: detailOf(e), rules: [v.ruleId], level: levelOf(v), at: Date.parse(e.timestamp) }; });
  // 판정 버튼: 열린 건이면 「악성 확정」 · 「오탐」, 판정된 건이면 결과 · 처리자 · 시각(+ 제안 적용 대기 / 종결)
  function decisionBar(c, opts) {
    const o = opts || {};
    const root = h('div', { class: 'decision', 'data-part': 'decision', 'data-case-id': c.id });
    if (c.state === 'open') {
      // 판정 칸 = 질문 · 큰 버튼 2개 · 안내 한 줄 [10/15 3차 — React DecisionBox 모습]. 시트 아래에 고정된다
      // 10/20 B: 메모 칸 대신 확인 대화상자(대상 · 함께 일어나는 일 · 사유 · 되돌리기)에서 사유를 받는다. 조회자는 버튼을 그리지 않는다
      const what = c.label || c.package || c.container;
      root.classList.add('decision-v');
      if (!UI.can()) {
        append(root, [h('div', { class: 'row-inline' }, h('span', { class: 'decision-q' }, o.question || '이 건은 악성인가?'), decisionBadge('pending')),
          h('p', { class: 'small muted', 'data-part': 'viewer-note' }, '판정은 관리자가 합니다 — 조회자는 결과만 봅니다')]);
        return root;
      }
      const go = (d) => UI.confirmDialog({ title: d === 'malicious' ? '악성 확정' : '오탐으로 판정', target: `${what} · 건 ${c.id}`, effects: api.casePreview(c.id, { decision: d }).then((r) => r.effects), // 서버 판정 미리보기 [10/20 결정 7] tone: d === 'malicious' ? 'danger' : 'primary', okLabel: d === 'malicious' ? '악성 확정' : '오탐으로 판정',
        undo: d === 'malicious' ? '판정은 이력에 남습니다. 정책 화면에서 제안을 「버림」하면 차단 없이 건만 종결됩니다' : '정책 화면에서 제안을 「버림」하면 예외 없이 건만 종결됩니다' })
        .then((r) => r && api.decide(c.id, { decision: d, note: r.reason }).then(({ proposal }) => {
          toast(d === 'malicious' ? `${what} 악성 확정 — 차단 제안 ${proposal.id} 초안을 만들었습니다` : `${what} 오탐 — 예외 제안 ${proposal.id} 초안을 만들었습니다`, { tone: 'ok', key: 'decide', replace: true, action: { label: '제안 보기 →', go: `#/policies?proposal=${proposal.id}` } });
          if (o.onDone) o.onDone();
        })).catch((e) => toast(`판정 실패: ${e.message}`, { tone: 'danger' }));
      append(root, [h('div', { class: 'row-inline' }, h('span', { class: 'decision-q' }, o.question || '이 건은 악성인가?'), decisionBadge('pending')),
        h('div', { class: 'decision-btns' },
          h('button', { type: 'button', class: 'btn btn-danger', 'aria-label': '악성 확정', title: '차단 제안을 만든다(패키지 · 이미지 · 도메인)', onclick: () => go('malicious') }, '악성 확정'),
          h('button', { type: 'button', class: 'btn btn-outline', 'aria-label': '오탐', title: '걸린 규칙에 가장 좁은 예외 제안을 만든다', onclick: () => go('false_positive') }, '오탐')),
        h('p', { class: 'small muted' }, '악성 확정 → 차단 제안 / 오탐 → 걸린 규칙에 예외 제안 (정책에서 미리보기 후 적용)')]);
    } else {
      append(root, [h('span', { class: 'row-inline' }, h('span', { class: 'small muted' }, '판정'), decisionBadge(c.decision), h('span', { class: 'small muted num' }, `${c.decidedBy} · ${fmt.dateTime(c.decidedAt)}`)),
        c.state === 'decided' ? h('a', { href: `#/policies?proposal=${c.proposalId}`, class: 'link small' }, '제안 적용 대기 → 정책') : h('span', { class: 'small muted' }, `종결 · ${fmt.dateTime(c.closedAt)}`)]);
    }
    return root;
  }
  // 미리보기 표: preview 결과 + 제안 → 바뀌는 건수 · 목록 + 「다음 설치 · 기동부터」(패키지 · 이미지 차단) + 실행 규칙 안내
  function previewView(p, r, auditById) {
    const root = h('section', { class: 'sheet-section', 'data-part': 'preview' }, h('h3', null, '미리보기 — 적용하면 무엇이 달라지나'));
    if (!r) { root.append(h('p', { class: 'small muted' }, '계산 중…')); return root; }
    // 「다음 설치 · 기동부터」 = 미리보기 응답의 nextOnly(패키지 · 이미지 차단). 옛 응답이면 제안에서 고른다
    const next = r.nextOnly || p.changes.filter((x) => x.op === 'block' && x.list !== 'hosts');
    if (r.error) { root.append(h('p', { class: 'small tone-danger' }, `미리보기 실패: ${r.error}`)); return root; }
    root.append(h('p', { 'data-preview-count': '' }, `감사 로그 ${fmt.num(r.evaluated)}건을 다시 평가 — 탐지 결과가 바뀌는 과거 위반 `, h('b', { class: 'num' }, `${r.changed.length}건`),
      r.changed.length ? ` (통과로 ${r.counts.toNormal}건 · 차단으로 ${r.counts.toBlocked}건)` : ''));
    if (r.changed.length) root.append(h('div', { class: 'preview-table' }, h('table', { class: 'table compact' },
      h('thead', null, h('tr', null, ['#', '시각', '대상', '규칙', '탐지 결과'].map((t) => h('th', null, t)))),
      h('tbody', null, r.changed.slice(0, 50).map((x) => { const a = auditById(x.auditId); return h('tr', null,
        h('td', { class: 'num muted' }, x.auditId), h('td', { class: 'num mono nowrap' }, a ? fmt.dateTime(a.event.timestamp) : '—'),
        h('td', { class: 'trunc-cell', title: x.container }, a && a.install ? a.install.label : x.container), h('td', { class: 'mono small' }, x.ruleId),
        h('td', { class: 'nowrap' }, verdictBadge(fakeVerdict(x.before)), ' → ', verdictBadge(fakeVerdict(x.after)))); })))));
    if (next.length) root.append(h('div', { class: 'note-box', 'data-preview-next': '' }, h('b', null, '다음 설치 · 기동부터 적용 — 과거 이벤트는 바뀌지 않습니다'),
      h('ul', { class: 'mono small' }, next.map((x) => h('li', null, `${LIST_LABEL[x.list]} ${x.value}`)))));
    return root;
  }
  // 격리 타임라인 막대 [10/30 계약 §3] — 구간: 탐지→판정(info) · 증거(warn) · 격리(danger) · 알림(accent), 각 ms 라벨, 합계 「격리까지 0.42초」. 없는 구간은 「—」
  //   설치 시트 결과 칸 · 토폴로지 판정 카드 · 보고서 · 시연 패널 ⑤ 가 같은 부품을 쓴다
  function timelineBar(tl, opts) {
    const o = opts || {};
    const t = (k) => (tl && tl[k] ? Date.parse(tl[k]) : null);
    const seg = (k, label, a, b, tone) => ({ k, label, tone, ms: a != null && b != null && b >= a ? b - a : null });
    const segs = [seg('match', '탐지→판정', t('detectedAt'), t('matchedAt'), 'info'), seg('evidence', '증거', t('evidenceStartedAt'), t('evidenceDoneAt'), 'warn'),
      seg('kill', '격리', t('evidenceDoneAt') != null ? t('evidenceDoneAt') : t('matchedAt'), t('killedAt'), 'danger'), seg('notify', '알림', t('killedAt'), t('notifiedAt'), 'accent')];
    const total = t('detectedAt') != null && t('killedAt') != null ? t('killedAt') - t('detectedAt') : null;
    const sum = segs.reduce((n, x) => n + (x.ms || 0), 0) || 1;
    const totalText = total == null ? '격리까지 —' : `격리까지 ${(total / 1000).toFixed(2)}초`;
    return h('div', { class: `tl ${o.compact ? 'compact' : ''}`, 'data-part': 'timeline', 'data-total-ms': total == null ? '' : String(total) },
      h('div', { class: 'tl-bar', role: 'img', 'aria-label': `격리 타임라인 — ${segs.map((x) => `${x.label} ${x.ms == null ? '—' : x.ms + ' ms'}`).join(', ')}, ${totalText}` },
        segs.map((x) => h('i', { class: `tl-seg tl-${x.tone}`, 'data-seg': x.k, style: `flex-grow:${x.ms ? Math.max(x.ms, sum * 0.05) : 0}`, title: `${x.label} ${x.ms == null ? '—' : x.ms + ' ms'}` }))),
      h('div', { class: 'tl-legend small' }, segs.map((x) => h('span', { 'data-seg': x.k, 'data-ms': x.ms == null ? '' : String(x.ms) }, h('i', { class: `sw tl-${x.tone}`, 'aria-hidden': true }), `${x.label} `, h('b', { class: 'num' }, x.ms == null ? '—' : `${x.ms} ms`))),
        h('b', { class: 'tl-total num push-right', 'data-part': 'timeline-total' }, totalText)));
  }
  // 오른쪽 상세 시트 — 목록 위치는 그대로, 열린 항목은 URL(?id=)에 남긴다
  // foot: 본문 스크롤과 따로 아래에 고정되는 칸(예: 판정)
  function sheet({ kind, title, actions, body, foot, onClose }) {
    return h('aside', { class: 'panel sheet', 'data-sheet': kind, 'aria-label': typeof title === 'string' ? title : '상세' },
      h('header', { class: 'panel-head' }, h('h2', null, title), h('div', { class: 'panel-actions' }, actions, h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-label': '닫기', onclick: onClose }, '✕'))),
      h('div', { class: 'sheet-body' }, body), foot ? h('div', { class: 'sheet-foot', 'data-part': 'sheet-foot' }, foot) : null);
  }
  function panel({ title, actions, body, class: cls }) {
    return h('section', { class: `panel ${cls || ''}` }, h('header', { class: 'panel-head' }, h('h2', null, title), actions ? h('div', { class: 'panel-actions' }, actions) : null), h('div', { class: 'panel-body' }, body));
  }
  const empty = (text) => h('div', { class: 'empty' }, text);
  function pauseToggle() {
    const b = h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => { state.paused = !state.paused; emit(); } });
    const sync = () => { b.className = `btn btn-xs ${state.paused ? 'btn-warn-soft' : 'btn-ghost'}`; b.textContent = state.paused ? '▶ 재개' : '⏸ 일시정지'; };
    sync(); b.sync = sync; return b;
  }
  // 두 번 눌러 확정하는 버튼(confirmButton)은 10/20 B 에서 확인 대화상자(UI.confirmDialog, ui-kit.js)로 바꿨다
  function switchEl(checked, onchange) {
    const el = h('span', { class: `switch ${checked ? 'on' : ''}`, role: 'switch', 'aria-checked': String(checked), tabindex: '0' }, h('span', { class: 'knob' }));
    const toggle = () => { checked = !checked; el.classList.toggle('on', checked); el.setAttribute('aria-checked', String(checked)); onchange(checked); };
    el.addEventListener('click', toggle);
    el.addEventListener('keydown', (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); toggle(); } });
    return el;
  }
  function select(opts, value, onchange, attrs) {
    return h('select', Object.assign({ class: 'ctl', onchange: (e) => onchange(e.target.value) }, attrs), opts.map(([v, label]) => h('option', { value: v, selected: v === value }, label)));
  }

  // 가상 스크롤 피드 (EventFeed.tsx) — 40px 고정 행, 보이는 행만 그린다
  function feed({ full, showImage = true, onSelect, empty: emptyText }) {
    const ROW = 40, OVER = 8;
    const list = h('ul', { class: 'feed-list' });
    const scroller = h('div', { class: 'feed-scroll' }, list);
    const head = full ? h('div', { class: 'feed-head' }, h('span', { class: 'c-time' }, '시각'), h('span', { class: 'c-name' }, '컨테이너'), h('span', { class: 'c-img' }, '이미지'), h('span', { class: 'c-kind' }, '종류'), h('span', { class: 'c-detail' }, '상세 (인자 · 경로 · 목적지)'), h('span', { class: 'c-rule' }, '규칙'), h('span', { class: 'c-verdict' }, '탐지 결과')) : null;
    const root = h('div', { class: `feed ${full ? 'feed-full' : ''}` }, head, scroller);
    let rows = [], selectedKey = null, emptyEl = null, seenKey = -1, firstDraw = true; // seenKey: 이미 그린 가장 큰 key — 그보다 크면 새 위반 행(하이라이트 1.2초, danger-soft → 투명) [10/30 모션]
    const freshAt = new Map(); const FRESH_MS = 1200;
    function rowEl(v, i) {
      const level = levelOf(v);
      if (!firstDraw && v.matched && v.key > seenKey && !freshAt.has(v.key)) freshAt.set(v.key, Date.now());
      const age = freshAt.has(v.key) ? Date.now() - freshAt.get(v.key) : Infinity, fresh = age < FRESH_MS;
      const li = h('li', { class: `feed-row ${onSelect ? 'clickable' : ''} ${v.key === selectedKey ? 'selected' : level === 'killed' || level === 'held' ? 'danger' : ''} ${fresh ? 'fresh' : ''}`, style: `top:${i * ROW}px;height:${ROW}px;${fresh ? `animation-delay:-${age}ms` : ''}`, 'data-key': v.key },
        h('span', { class: 'c-time num mono' }, fmt.time(v.event.timestamp)),
        h('span', { class: 'c-name', title: v.event.containerName }, v.event.containerName),
        full && showImage ? h('span', { class: 'c-img', title: v.event.imageName }, v.event.imageName) : null,
        h('span', { class: 'c-kind' }, kindBadge(v.event.kind)),
        h('span', { class: 'c-detail mono', title: detailOf(v.event) }, detailOf(v.event)),
        full ? h('span', { class: 'c-rule', title: v.reason }, v.ruleId || '—') : v.matched ? h('span', { class: 'c-rule-inline', title: v.reason }, v.ruleId) : null,
        h('span', { class: 'c-verdict' }, verdictBadge(v)));
      if (onSelect) { li.addEventListener('click', () => onSelect(v)); UI.rowKeys(li, () => onSelect(v)); } // 키보드로 열기 [10/20 D]
      return li;
    }
    function draw() {
      // 빈 목록도 「첫 그리기」다(11/02 수정 — 빈 이벤트 화면에서 처음 들어온 위반이 하이라이트되지 않던 결함. React EventFeed 와 같게)
      if (!rows.length) { list.replaceChildren(); list.style.height = '0px'; if (!emptyEl) { emptyEl = empty(emptyText || '이벤트 수신 대기 중'); scroller.append(emptyEl); } firstDraw = false; return; }
      if (emptyEl) { emptyEl.remove(); emptyEl = null; }
      const height = scroller.clientHeight || 400, top = scroller.scrollTop;
      const start = Math.max(0, Math.floor(top / ROW) - OVER), end = Math.min(rows.length, Math.ceil((top + height) / ROW) + OVER);
      list.style.height = rows.length * ROW + 'px';
      const frag = document.createDocumentFragment();
      for (let i = start; i < end; i++) frag.append(rowEl(rows[i], i));
      // 다시 그려도 키보드 포커스는 같은 행에 남긴다(스트림이 250ms 마다 갱신)
      const fk = list.contains(document.activeElement) ? document.activeElement.dataset.key : null;
      replace(list, frag);
      if (fk) { const el = list.querySelector(`[data-key="${fk}"]`); if (el) el.focus({ preventScroll: true }); }
      const maxKey = rows.reduce((m, v) => (v.key > m ? v.key : m), -1); if (maxKey > seenKey) setTimeout(() => { seenKey = Math.max(seenKey, maxKey); }, 50); firstDraw = false;
      if (freshAt.size > 200) for (const [k, t] of freshAt) if (Date.now() - t > FRESH_MS) freshAt.delete(k);
    }
    scroller.addEventListener('scroll', draw);
    new ResizeObserver(draw).observe(scroller);
    root.set = (r) => { rows = r; draw(); };
    root.select = (k) => { selectedKey = k; draw(); };
    root.setShowImage = (v) => { showImage = v; root.classList.toggle('no-img', !v); draw(); };
    return root;
  }

  // 분당 위반 — stats.trend(5초 버킷)를 1분으로 묶어 최근 n분 막대로. 빈 분도 0 막대로 남긴다
  function perMinute(trend, minutes) {
    const n = minutes || 10, cur = Math.floor(Date.now() / 60000), out = [];
    for (let i = n - 1; i >= 0; i--) out.push({ m: cur - i, t: new Date((cur - i) * 60000).toISOString(), n: 0 });
    for (const b of trend || []) { const o = out.find((x) => x.m === Math.floor(Date.parse(b.t) / 60000)); if (o) o.n += b.violations || 0; }
    return out;
  }
  function barChart({ name }) {
    const root = h('div', { class: 'chart bars', 'data-chart': name });
    let data = [];
    function draw() {
      root.replaceChildren();
      const W = root.clientWidth || 480, H = root.clientHeight || 160;
      const m = { t: 10, r: 8, b: 24, l: 32 };
      const iw = W - m.l - m.r, ih = H - m.t - m.b;
      const max = Math.max(4, ...data.map((d) => d.n));
      const y = (v) => m.t + ih - (v / max) * ih;
      const slot = iw / Math.max(1, data.length), bw = Math.max(4, slot * 0.62);
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img', 'aria-label': '분당 위반 막대' });
      for (const v of [0, Math.round(max / 2), max]) svg.append(s('line', { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: v ? 'grid' : 'axis' }), s('text', { x: m.l - 6, y: y(v) + 4, 'text-anchor': 'end', class: 'tick' }, v));
      data.forEach((d, i) => {
        const x = m.l + i * slot + (slot - bw) / 2, hgt = Math.max(2, ih - (y(d.n) - m.t));
        svg.append(s('rect', { x, y: m.t + ih - hgt, width: bw, height: hgt, rx: 2, class: `bar ${d.n ? '' : 'zero'}` }, s('title', null, `${fmt.time(d.t).slice(0, 5)} · 위반 ${d.n}건`)));
        if (i % 2 === (data.length - 1) % 2) svg.append(s('text', { x: x + bw / 2, y: H - 6, 'text-anchor': 'middle', class: 'tick' }, fmt.time(d.t).slice(0, 5)));
      });
      root.append(svg);
    }
    new ResizeObserver(draw).observe(root);
    root.set = (d) => { data = d || []; draw(); };
    return root;
  }

  // 토폴로지 그래프 — 컨테이너 → 프로세스 → 파일/목적지 3열 고정 레이아웃 SVG.
  // 엣지 위에는 글자를 두지 않는다(화살표와 겹침). 종류는 말단 노드 안의 kind 칩으로, 횟수는 ×N 으로 보인다.
  const NODE = { w: 240, leafW: 290, h: 34, rowH: 56, colX: { container: 0, process: 330, file: 690, dest: 690 } };
  // SVG 색은 CSS 토큰에서 읽는다(라이트 · 다크) [10/30 계약 §7] — 전환 뒤 다시 그릴 때 반영
  const cssVar = (name, fallback) => { const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim(); return v || fallback || ''; };
  const nodeStyle = () => ({ normal: [cssVar('--topo-node'), cssVar('--topo-node-border'), cssVar('--topo-node-text')], alert: [cssVar('--warn-soft'), cssVar('--warn'), cssVar('--warn-text')], held: [cssVar('--danger-soft'), cssVar('--danger'), cssVar('--danger-text')], killed: [cssVar('--danger'), cssVar('--danger'), cssVar('--text-inverse')] });
  const edgeColor = () => ({ normal: cssVar('--topo-edge'), alert: cssVar('--warn'), held: cssVar('--danger'), killed: cssVar('--danger') });
  const ICON = { container: '▣', process: '⚙', file: '▤', dest: '◎' };
  const chipColor = () => ({ open: [cssVar('--k-open-soft'), cssVar('--k-open')], connect: [cssVar('--k-connect-soft'), cssVar('--k-connect')], dns: [cssVar('--warn-soft'), cssVar('--warn-text')] }); // dns 칩은 amber [10/30]
  const ellipsize = (t, max) => (t.length <= max ? t : t.slice(0, Math.max(4, Math.floor(max * 0.35))) + '…' + t.slice(-(max - Math.floor(max * 0.35) - 1)));
  function layoutTopology(nodes, edges) {
    const children = new Map(); for (const e of edges) children.set(e.source, [...(children.get(e.source) || []), e.target]);
    const byId = new Map(nodes.map((n) => [n.id, n])); const pos = new Map(); let row = 0;
    const containers = nodes.filter((n) => n.type === 'container').sort((a, b) => (SEV[b.level] - SEV[a.level]) || a.label.localeCompare(b.label));
    for (const c of containers) {
      const start = row;
      const procs = (children.get(c.id) || []).map((id) => byId.get(id)).filter(Boolean).sort((a, b) => (SEV[b.level] - SEV[a.level]) || a.label.localeCompare(b.label));
      for (const p of procs) {
        const pStart = row;
        const leaves = (children.get(p.id) || []).map((id) => byId.get(id)).filter(Boolean).sort((a, b) => (SEV[b.level] - SEV[a.level]) || (a.type === b.type ? a.label.localeCompare(b.label) : a.type === 'file' ? -1 : 1));
        for (const l of leaves) pos.set(l.id, { x: NODE.colX[l.type], y: row++ * NODE.rowH });
        if (!leaves.length) row++;
        pos.set(p.id, { x: NODE.colX.process, y: ((pStart + row - 1) / 2) * NODE.rowH });
      }
      if (row === start) row++;
      pos.set(c.id, { x: NODE.colX.container, y: ((start + row - 1) / 2) * NODE.rowH });
      row++;
    }
    return { pos, rows: row };
  }
  function topologyGraph({ onSelect } = {}) {
    const root = h('div', { class: 'topo' });
    let snap = { nodes: [], edges: [] }, selectedId = null;
    function draw() {
      const { nodes, edges } = snap;
      replace(root);
      if (!nodes.length) { root.append(empty('표시할 활동 없음 — 이벤트가 들어오면 그래프가 그려집니다. 데모 제어 → 지금 실행으로 공격 시나리오를 바로 볼 수 있습니다.')); return; }
      const { pos, rows } = layoutTopology(nodes, edges);
      const NODE_STYLE = nodeStyle(), EDGE_COLOR = edgeColor(), CHIP = chipColor(), ACCENT = cssVar('--accent', '#4f46e5'), INV = cssVar('--text-inverse', '#fff');
      const W = NODE.colX.file + NODE.leafW + 24, Hh = Math.max(1, rows) * NODE.rowH + 16;
      const svg = s('svg', { viewBox: `-12 -8 ${W} ${Hh}`, class: 'topo-svg', style: `min-height:${Math.min(Hh, 2000)}px` });
      const defs = s('defs');
      for (const [lv, c] of Object.entries(EDGE_COLOR)) defs.append(s('marker', { id: `arrow-${lv}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, s('path', { d: 'M0,0 L10,5 L0,10 z', fill: c })));
      svg.append(defs);
      const edgeEls = [];
      for (const e of edges) {
        const a = pos.get(e.source), b = pos.get(e.target); if (!a || !b) continue;
        const aw = byType(e.source) === 'container' || byType(e.source) === 'process' ? NODE.w : NODE.leafW;
        const x1 = a.x + aw, y1 = a.y + NODE.h / 2, x2 = b.x, y2 = b.y + NODE.h / 2, c = (x1 + x2) / 2;
        const touches = selectedId && (e.source === selectedId || e.target === selectedId);
        const el = s('path', { d: `M${x1},${y1} C${c},${y1} ${c},${y2} ${x2},${y2}`, fill: 'none', stroke: EDGE_COLOR[e.level], 'stroke-width': e.level === 'normal' ? 1.25 : 2.25, 'marker-end': `url(#arrow-${e.level})`, class: `edge ${e.level !== 'normal' ? 'edge-hot' : ''} ${selectedId ? (touches ? 'hl' : 'dim') : ''}`, 'data-src': e.source, 'data-dst': e.target }, s('title', null, `${e.kind} ×${e.count}${e.violations ? ` · 위반 ${e.violations}` : ''}`));
        svg.append(el); edgeEls.push(el);
      }
      function byType(id) { const n = nodes.find((x) => x.id === id); return n ? n.type : 'file'; }
      for (const n of nodes) {
        const p = pos.get(n.id); if (!p) continue; const [bg, bd, fg] = NODE_STYLE[n.level];
        const leaf = n.type === 'file' || n.type === 'dest'; const w = leaf ? NODE.leafW : NODE.w;
        const g = s('g', { transform: `translate(${p.x},${p.y})`, class: `node ${n.id === selectedId ? 'selected' : ''} ${onSelect ? 'clickable' : ''}`, tabindex: onSelect ? 0 : null, role: onSelect ? 'button' : null },
          s('title', null, `${n.label}\n${n.count}회${n.violations ? ` · 위반 ${n.violations}` : ''}${n.reason ? `\n${n.reason}` : ''}`));
        g.append(s('rect', { width: w, height: NODE.h, rx: 8, fill: bg, stroke: n.id === selectedId ? ACCENT : bd, 'stroke-width': n.id === selectedId ? 2 : 1, 'stroke-dasharray': n.level === 'held' ? '4 3' : null }));
        let x = 10;
        if (leaf) { const kind = n.type === 'file' ? 'open' : n.dns ? 'dns' : 'connect'; const [cb, cf] = n.level === 'killed' ? ['rgba(255,255,255,.22)', INV] : CHIP[kind]; g.append(s('rect', { x: 8, y: 8, width: 54, height: 18, rx: 4, fill: cb }), s('text', { x: 35, y: 21, 'text-anchor': 'middle', fill: cf, class: 'node-chip' }, kind)); x = 70; }
        else { g.append(s('text', { x: 10, y: 22, class: 'node-icon', fill: fg }, ICON[n.type])); x = 30; }
        const countW = n.count > 1 ? 36 : 0;
        const statusW = n.type === 'container' && n.level !== 'normal' ? 62 : 0;
        const maxChars = Math.floor((w - x - 12 - countW - statusW) / (leaf ? 6.7 : 7));
        g.append(s('text', { x, y: 22, fill: fg, class: leaf ? 'node-mono' : 'node-label' }, ellipsize(n.label, maxChars)));
        if (statusW) { const label = LEVEL_LABEL[n.level]; const bx = w - 8 - statusW - countW; g.append(s('rect', { x: bx, y: 8, width: statusW, height: 18, rx: 9, fill: n.level === 'killed' ? 'rgba(255,255,255,.22)' : n.level === 'alert' ? cssVar('--warn-line') : cssVar('--danger-line') }), s('text', { x: bx + statusW / 2, y: 21, 'text-anchor': 'middle', fill: n.level === 'killed' ? INV : fg, class: 'node-chip' }, label)); }
        if (countW) g.append(s('text', { x: w - 10, y: 22, 'text-anchor': 'end', fill: fg, class: 'node-count', opacity: .75 }, `×${n.count}`));
        if (onSelect) {
          g.addEventListener('click', () => onSelect(n));
          g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); onSelect(n); } });
          g.addEventListener('mouseenter', () => { for (const el of edgeEls) { const on = el.dataset.src === n.id || el.dataset.dst === n.id; el.classList.toggle('hl', on); el.classList.toggle('dim', !on); } });
          g.addEventListener('mouseleave', () => { for (const el of edgeEls) { const touches = selectedId && (el.dataset.src === selectedId || el.dataset.dst === selectedId); el.classList.toggle('hl', !!touches); el.classList.toggle('dim', !!selectedId && !touches); } });
        }
        svg.append(g);
      }
      root.append(svg);
    }
    root.set = (sn) => { snap = sn; draw(); };
    root.select = (id) => { selectedId = id; draw(); };
    return root;
  }

  // ── 토스트 ──────────────────────────────────────────────
  // key 가 같은 토스트는 하나로 묶는다: 기본은 ×N 으로 세고, replace 면 글만 바꾼다. 8초 뒤 닫히고, 묶일 때마다 시간을 다시 잰다.
  // 누적은 종 아이콘 배지가 맡는다. action = { label, go(주소) | run(함수) }
  const TOAST_TTL = 8000;
  const toastByKey = new Map();
  function toast(text, opts) {
    const region = $('#toasts'); if (!region) return;
    const o = opts || {};
    let t = o.key ? toastByKey.get(o.key) : null;
    if (!t || !t.el.isConnected || t.closed) {
      t = { n: 0, text: h('span', { class: 'toast-text' }), count: h('b', { class: 'toast-count' }), slot: h('span', { class: 'toast-slot' }) };
      const close = () => { t.closed = true; clearTimeout(t.timer); t.el.classList.add('out'); setTimeout(() => t.el.remove(), 300); };
      t.close = close;
      t.el = h('div', { class: 'toast', role: 'status' }, h('span', { class: 'grow' }, t.text, t.count), t.slot, h('button', { type: 'button', class: 'toast-x', 'aria-label': '닫기', onclick: close }, '×'));
      if (o.key) toastByKey.set(o.key, t);
    }
    t.n = o.replace ? 1 : t.n + 1;
    t.el.className = `toast toast-${o.tone || 'info'}`;
    t.text.textContent = text; t.count.textContent = t.n > 1 ? ` ×${t.n}` : '';
    replace(t.slot, o.action ? (o.action.run
      ? h('button', { type: 'button', class: 'toast-action', onclick: () => { t.close(); o.action.run(); } }, o.action.label)
      : h('a', Object.assign(to(o.action.go, o.action.state), { class: 'toast-action', onclick: () => t.close() }), o.action.label)) : null);
    region.append(t.el);
    while (region.children.length > 4) region.firstChild.remove();
    clearTimeout(t.timer); t.timer = setTimeout(t.close, TOAST_TTL);
  }

  // ── 라우터 ──────────────────────────────────────────────
  function route() {
    const hash = location.hash.replace(/^#/, '') || '/';
    const [path, qs] = hash.split('?');
    return { path: path === '' ? '/' : path, query: new URLSearchParams(qs || '') };
  }
  function navigate(path, query) {
    const q = query ? new URLSearchParams(query) : null; const qs = q && [...q].length ? '?' + q.toString() : '';
    location.hash = path + qs;
  }
  function setQuery(patch) {
    const { path, query } = route();
    for (const [k, v] of Object.entries(patch)) { if (v === '' || v == null) query.delete(k); else query.set(k, v); }
    history.replaceState(null, '', '#' + path + ([...query].length ? '?' + query.toString() : ''));
  }
  // 주소에는 링크용 값만 [10/21b — 필터를 주소에 남기면 보안 취약성이 올라간다(사용자)]. id · proposal · tab · view, node 는 컨테이너(c:)만.
  //   필터 · 미리 채우기 값은 화면 상태: 화면 안 링크는 go(href, state) · to(href, state) 로 넘기고, 화면을 다시 열거나 새로고침하면 기본값.
  //   주소로 들어온 필터(옛 링크 · 알림)는 takeQuery 가 한 번 읽어 초기값으로 넘긴 뒤 주소에서 지운다. 옛 view=history 는 changes 로
  const LINK_KEYS = ['id', 'proposal', 'tab', 'view', 'node', 'case', 'install']; // case · install: 보고서 #/report?case= · ?install= [10/30 계약 §5]
  let navState = null;
  function go(href, st) {
    const target = '#' + String(href || '/').replace(/^#/, '');
    navState = st || null;
    if (location.hash === target) mount(); else location.hash = target;
  }
  const to = (href, st) => { if (href && typeof href === 'object') { st = href.state; href = href.href; } return { href, 'data-nav': st ? JSON.stringify(st) : null }; }; // <a> 속성(링크 객체도 받는다) — 클릭은 아래 위임 처리기가 go 로
  function onNavClick(e) {
    const a = e.target.closest ? e.target.closest('a[data-nav]') : null;
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return; // 새 탭은 주소만(필터 없이 기본값)
    e.preventDefault(); go(a.getAttribute('href'), JSON.parse(a.dataset.nav));
  }
  function takeQuery() {
    const { path, query } = route();
    const keep = new URLSearchParams(), out = new URLSearchParams();
    for (const [k, v] of query) {
      if (LINK_KEYS.includes(k)) { if (k !== 'node' || v.startsWith('c:')) keep.set(k, k === 'view' && v === 'history' ? 'changes' : v); }
      else out.set(k, v);
    }
    if (keep.toString() !== query.toString()) history.replaceState(null, '', '#' + path + ([...keep].length ? '?' + keep.toString() : ''));
    for (const [k, v] of Object.entries(navState || {})) if (v != null && v !== '' && v !== false) out.set(k, v === true ? '1' : String(v));
    navState = null;
    for (const [k, v] of keep) out.set(k, v);
    return { path, query: out };
  }

  // 사이드바 = 시나리오별 묶음 [10/15 확정]. 묶음 제목이 없는 첫 줄은 두 시나리오 공통
  const NAV = [
    [null, [['/', '대시보드', '▦']]],
    ['설치 검사', [['/installs', '설치 검사', '▣'], ['/scans', '공급망 검사', '⌕']]],
    ['런타임 감시', [['/events', '이벤트', '≣'], ['/topology', '토폴로지', '⌘']]],
    ['설정 · 기록', [['/policies', '정책', '§'], ['/audit', '감사 로그', '◷'], ['/settings', '설정', '⚙']]], // 설정 화면 [10/20 결정 2]
  ];
  let current = null; // { unmount, update }

  function shell() {
    const nav = h('nav', { class: 'side-nav', 'aria-label': '메뉴' }, NAV.map(([group, links]) => [
      group ? h('div', { class: 'nav-group-title' }, group) : null,
      links.map(([to, label, icon]) => h('a', { href: '#' + to, class: 'nav-link', 'data-to': to, title: label }, h('span', { class: 'nav-icon', 'aria-hidden': true }, icon), h('span', { class: 'nav-label' }, label),
        to === '/' ? h('span', { class: 'nav-badge num', 'data-nav-badge': '', hidden: true }) : null))]));
    const foot = h('div', { class: 'side-foot' });
    // 10/20 E: 통합 검색(shell-plus.js 가 채움) · 접기 버튼. 10/20 C: 종 = 알림 센터(shell-plus.js) · 10/20 A: 라이선스 칩 · 계정 메뉴(auth.js)
    const search = h('div', { class: 'side-search', 'data-part': 'search' });
    const collapse = h('button', { type: 'button', class: 'side-collapse', 'data-action': 'collapse', 'aria-label': '사이드바 접기', title: '사이드바 접기 · 펼치기' }, h('span', { 'aria-hidden': true }, '«'));
    const aside = h('aside', { class: 'sidebar' }, h('a', { href: '#/', class: 'brand' }, h('span', { class: 'brand-icon', 'aria-hidden': true }, '🛡'), h('span', { class: 'nav-label' }, 'SupplyGuard')), search, nav, foot, collapse);
    const ws = h('span', { class: 'ws' });
    const eps = h('span', { class: 'eps' });
    const bell = h('span', { class: 'bell-wrap', 'data-part': 'bell-wrap' });
    const acct = UI.auth ? UI.auth.headerEl() : h('span');
    const menuBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-xs menu-btn', 'data-action': 'menu', 'aria-label': '메뉴 열기', 'aria-expanded': 'false', 'aria-controls': 'sidebar' }, '☰'); // 768 미만: 사이드바 서랍 [10/30]
    aside.id = 'sidebar';
    const head = h('div', { class: 'page-head' }, menuBtn, h('h1', { class: 'page-title' }), h('div', { class: 'page-actions' }));
    const header = h('header', { class: 'topbar' }, head, h('div', { class: 'topbar-right' }, h('span', { class: 'ws-status', role: 'status' }, ws, eps), bell, h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => $('#help').showModal(), title: '사용 안내 (?)' }, '? 안내'), h('button', { type: 'button', class: 'btn btn-primary btn-xs', onclick: () => $('#demo').classList.toggle('open') }, '데모 제어'), acct));
    const banner = h('div', { class: 'banner banner-danger', hidden: true, role: 'alert' });
    // 실시간 연결 끊김 · 끊긴 동안 채운 수 [10/20 D]
    const connBanner = h('div', { class: 'banner banner-danger', hidden: true, role: 'alert', 'data-banner': 'conn' }, h('b', null, '실시간 연결이 끊겼습니다'), ' — 다시 연결하는 중입니다(1초 → 10초 간격). 그동안의 이벤트는 다시 붙으면 채웁니다.');
    // 이벤트 첫 로드 실패 [10/21 React 맞춤 — StreamBanners.tsx] — 백엔드가 꺼져 있는데 「위반 없음」으로 보이지 않게. 이벤트 화면에서 목록이 비어 오류 칸이 보일 때는 띄우지 않는다(오류 표시 1곳)
    const loadText = h('span', { class: 'grow' });
    const loadBanner = h('div', { class: 'banner banner-danger banner-load', hidden: true, role: 'alert', 'data-banner': 'load' }, loadText,
      h('button', { type: 'button', class: 'btn btn-outline btn-xs', 'data-action': 'retry-load', onclick: () => loadEvents(true) }, '다시 시도'));
    let loadShown = null;
    let backfillShown = null;
    const backfillText = h('span', { class: 'grow' });
    const backfillBanner = h('div', { class: 'banner banner-info', hidden: true, role: 'status', 'data-banner': 'backfill' }, backfillText,
      h('button', { type: 'button', class: 'banner-x', 'aria-label': '닫기', onclick: () => { backfillBanner.hidden = true; state.backfill = null; } }, '×'));
    // 「도메인 판단 꺼짐」 경고 [10/20 도우미] — state.server.dnsResolve === 'off' 일 때. 한 번 닫으면 이 탭(세션) 동안 숨긴다
    const DNS_KEY = 'supplyguard.banner.dns';
    const dnsDismissed = () => { try { return sessionStorage.getItem(DNS_KEY) === '1'; } catch { return false; } };
    const dnsBanner = h('div', { class: 'banner banner-warn', hidden: true, role: 'alert', 'data-banner': 'dns' },
      h('span', { class: 'grow' }, h('b', null, '도메인 판단 꺼짐'), ' — trace_dns 가 뜨지 않아 도메인 기준 규칙(allowHosts · denyHosts · 차단 도메인)과 DNS 질의 규칙(kind: dns)이 통과 처리됩니다. IP · 포트 규칙만 동작합니다. ', h('a', { href: '#/policies', class: 'link' }, '정책 보기 →')),
      h('button', { type: 'button', class: 'banner-x', 'aria-label': '닫기', onclick: () => { try { sessionStorage.setItem(DNS_KEY, '1'); } catch { /* 저장 차단 */ } dnsBanner.hidden = true; } }, '×'));
    const page = h('main', { class: 'page', id: 'page' });
    const main = h('div', { class: 'main' }, header, banner, loadBanner, connBanner, backfillBanner, dnsBanner, page);
    const root = h('div', { class: 'shell' }, aside, main);
    function sync() {
      const { path } = route();
      for (const a of nav.querySelectorAll('.nav-link')) a.classList.toggle('active', a.dataset.to === path);
      const st = state.stats, enforce = state.info.enforceKill;
      banner.hidden = !state.liveError; banner.textContent = state.liveError;
      dnsBanner.hidden = !(state.server && state.server.dnsResolve === 'off') || dnsDismissed();
      const shownInList = path === '/events' && state.eventsError && !state.verdicts.length;
      loadBanner.hidden = !state.eventsError || !!shownInList;
      if (state.eventsError && state.eventsError !== loadShown) { loadShown = state.eventsError; replace(loadText, h('b', null, '이벤트를 불러오지 못했습니다'), ` — ${state.eventsError.message}. 지금 보이는 목록 · 숫자는 실제와 다를 수 있습니다.`); }
      connBanner.hidden = state.connected || !state.eventsReady || !!state.eventsError;
      if (state.backfill && state.backfill !== backfillShown) { backfillShown = state.backfill; backfillText.textContent = `실시간 연결이 다시 붙었습니다 — 끊긴 동안 ${fmt.num(state.backfill.n)}건을 채웠습니다.`; backfillBanner.hidden = false; const b = state.backfill; setTimeout(() => { if (state.backfill === b) { state.backfill = null; backfillBanner.hidden = true; } }, 10000); }
      if (!state.backfill) backfillBanner.hidden = true;
      acct.sync && acct.sync();
      replace(foot, 
        h('div', null, h('span', null, '수집'), h('span', null, state.source === 'live' ? (state.info.source === 'gadget' ? 'eBPF 가젯' : 'Mock 데모') + ' · 실제' : 'Mock 데모 · 시뮬')),
        h('div', null, h('span', null, '격리'), h('span', { class: enforce ? 'tone-danger-soft' : 'tone-warn-soft' }, enforce ? '자동 종료' : 'dry-run')),
        h('div', null, h('span', null, 'IG'), h('span', { class: 'num' }, state.info.gadgetVersion)));
      ws.className = `ws ${state.connected ? 'on' : 'off'}`; ws.textContent = state.connected ? '실시간 연결됨' : '재연결 중…';
      replace(eps, '초당 ', h('b', { class: 'num' }, fmt.num(Math.round((st ? st.eventsPerSec : 0) * 10) / 10)), ' evt');
      // 사이드바 대시보드 배지 = 판정 대기 건수 [10/15 3차 — React 모습]
      const nb = nav.querySelector('[data-nav-badge]'); const pending = state.source === 'live' ? 0 : state.cases.filter((c) => c.state === 'open').length;
      nb.hidden = !pending; nb.textContent = pending; nb.setAttribute('aria-label', `판정 대기 ${pending}건`);
    }
    root.sync = sync;
    return root;
  }

  function helpDialog() {
    const steps = [
      ['대시보드에서 판정 대기 확인', '지금 처리할 일이 있는지 본다. 판정 대기 = 격리 · 경고된 설치와 격리된 런타임 컨테이너.', '#/'],
      ['설치 검사에서 판정', '막힌 설치의 공격 체인과 정적 분석(OSV) 결과를 보고 「악성 확정」 또는 「오탐」.', '#/installs'],
      ['정책에서 제안 적용', '판정이 만든 제안을 미리보기(과거 위반이 어떻게 바뀌나)로 확인하고 적용하거나 버린다.', '#/policies'],
      ['이벤트로 지금 걸리는 것 보기', '실시간 위반만. 행을 누르면 토폴로지로 이어진다.', '#/events'],
      ['토폴로지에서 런타임 판정', '컨테이너가 무엇에 손댔는지 관계로 보고, 격리된 컨테이너를 판정한다.', '#/topology'],
      ['감사 로그로 되짚기', '과거 위반과 판정 결과, 판정 · 정책 변경 이력을 기간으로 찾는다.', '#/audit'],
    ];
    const d = h('dialog', { id: 'help', class: 'dialog' },
      h('form', { method: 'dialog', class: 'dialog-body' },
        h('h3', null, '사용 흐름'),
        h('ol', { class: 'steps' }, steps.map(([t, desc, go]) => h('li', null, h('div', null, h('b', null, t), h('p', null, desc)), h('a', { href: go, class: 'btn btn-ghost btn-xs', onclick: () => d.close() }, '이동')))),
        h('p', { class: 'muted' }, '데모 제어(상단 오른쪽)에서 공격 시나리오를 바로 실행하거나 격리 모드를 dry-run 으로 바꿔 볼 수 있습니다. 키보드 ? 로 이 안내를 엽니다.'),
        // 단축키 [10/20 E]
        h('div', { 'data-part': 'shortcuts' }, h('h4', null, '단축키'), h('dl', { class: 'shortcuts' },
          [['/', '사이드바 검색으로 이동(패키지 · 컨테이너 · 규칙 id · 도메인 · 검사)'], ['?', '이 안내 열기'], ['Esc', '대화상자 · 패널 · 검색 결과 닫기'], ['Enter', '목록에서 고른 행 열기 (Space 도 같음)'], ['↑ ↓', '검색 결과 사이 이동'], ['[', '사이드바 접기 · 펼치기']]
            .map(([k, t]) => [h('dt', null, h('kbd', null, k)), h('dd', null, t)]))),
        h('div', { class: 'dialog-foot' }, h('button', { class: 'btn btn-primary', value: 'close' }, '닫기'))));
    return d;
  }

  function demoDrawer() {
    const countdown = h('span', { class: 'num' });
    let srcSel = state.source;
    const apiInput = h('input', { class: 'ctl mono', value: state.apiBase, placeholder: 'http://127.0.0.1:8000', disabled: state.source !== 'live', 'aria-label': '백엔드 주소' });
    const body = h('div', { class: 'drawer-body' },
      h('h3', null, '데모 제어'),
      h('p', { class: 'muted' }, '실제 앱에는 없는 목업 전용 패널. 백엔드 mock 소스가 하는 일을 손으로 일으킨다.'),
      h('div', { class: 'card' },
        h('label', { class: 'row' }, h('span', null, '데이터 소스'), select([['sim', '내장 시뮬레이션'], ['live', '실제 백엔드']], state.source, (v) => { srcSel = v; apiInput.disabled = v !== 'live'; })),
        apiInput,
        h('div', { class: 'row' }, h('small', { class: 'muted' }, '실제: REST + /ws/events 로 붙는다. 백엔드는 ALLOWED_ORIGINS 에 이 페이지 출처를 넣어 띄운다'), h('button', { type: 'button', class: 'btn btn-primary btn-xs', onclick: () => setSource(srcSel, apiInput.value.trim()) }, '연결'))),
      h('label', { class: 'row' }, h('span', null, '격리 모드 ', h('small', { class: 'muted' }, 'ENFORCE_KILL')), switchEl(state.info.enforceKill, (on) => { state.info.enforceKill = on; emit(); toast(on ? '격리 모드: 자동 종료' : '격리 모드: dry-run (알림만)', { tone: on ? 'danger' : 'warn' }); })),
      h('div', { class: 'row' }, h('span', null, '설치 검사 실행'), h('span', { class: 'row-inline' },
        h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-demo': 'install-benign', title: 'sg-install pip requests', onclick: () => runInstallDemo('benign') }, '정상'),
        h('button', { type: 'button', class: 'btn btn-danger btn-xs', 'data-demo': 'install-malicious', title: 'sg-install pip ./reqeusts', onclick: () => runInstallDemo('malicious') }, '악성'),
        h('button', { type: 'button', class: 'btn btn-warn-soft btn-xs', 'data-demo': 'install-warn', title: 'sg-install npm tiny-git-dep', onclick: () => runInstallDemo('warn') }, '경고'),
        h('button', { type: 'button', class: 'btn btn-warn-soft btn-xs', 'data-demo': 'install-dns-exfil', title: 'SG_DEMO_SCENARIOS=dns-exfil sg-install pip ./reqeusts', onclick: () => runInstallDemo('dnsExfil') }, 'DNS 유출'))),
      h('p', { class: 'muted small' }, 'sg-install(CLI) 대역 — 정상 pip requests · 악성 pip ./reqeusts · 경고 npm tiny-git-dep(git:// 9418, 오탐 후보) · DNS 유출 pip ./reqeusts(dns-exfil 만 — sandbox-dns 시험 운영이라 격리 대상). 차단된 패키지는 컨테이너 없이 「설치 전 거부」.'),
      h('div', { class: 'row' }, h('span', null, '런타임 공격 ', h('small', { class: 'muted' }, '자동 ', countdown)), h('button', { type: 'button', class: 'btn btn-danger btn-xs', 'data-demo': 'attack', onclick: runAttackNow }, '지금 실행')),
      h('p', { class: 'muted small' }, '배포된 pkg-reqeusts 컨테이너에 시나리오 1→2→3 을 흘린다. 격리 중이면 먼저 재기동하고(차단 이미지면 기동 즉시 격리), 일시정지면 해제한다.'),
      h('div', { class: 'row' }, h('span', null, 'DNS 유출 질의'), h('button', { type: 'button', class: 'btn btn-warn-soft btn-xs', 'data-demo': 'attack-dns', onclick: runDnsExfilNow }, '지금 실행')),
      h('p', { class: 'muted small' }, 'pkg-reqeusts 가 48자 hex 라벨 A 질의 + TXT 질의를 보낸다 → runtime-dns-exfil 경고 2건(kind: dns). 도메인 판단이 꺼져 있으면(?dns=off) 질의가 보이지 않는다.'),
      h('div', { class: 'row' }, h('span', null, '실시간 연결'), h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => disconnect(3000) }, '3초 끊기')),
      h('label', { class: 'row' }, h('span', null, '정상 이벤트 속도'), select([['300', '느리게'], ['100', '보통'], ['40', '빠르게']], '100', (v) => { sim.interval = Number(v); if (state.connected) { stop(); start(); } })),
      h('label', { class: 'row' }, h('span', null, '자동 공격 주기'), select([['0', '끔 (데모 대본)'], ['10000', '10초'], ['20000', '20초'], ['60000', '60초']], String(sim.attackEvery), (v) => { sim.attackEvery = Number(v); sim.nextAttack = sim.attackEvery ? Date.now() + sim.attackEvery : Infinity; })),
      h('div', { class: 'row muted small' }, h('span', null, '격리된 컨테이너는 15초 뒤 새 ID 로 재기동한다 (재배포 흉내).')));
    const d = h('aside', { id: 'demo', class: 'drawer' }, h('button', { type: 'button', class: 'drawer-x', 'aria-label': '닫기', onclick: () => d.classList.remove('open') }, '×'), body);
    setInterval(() => { countdown.textContent = state.source === 'live' ? '(백엔드 주기)' : !sim.attackEvery ? '꺼짐' : Math.max(0, Math.ceil((sim.nextAttack - Date.now()) / 1000)) + '초 뒤'; }, 500);
    return d;
  }

  function mount() {
    const { path, query } = takeQuery(); // 링크용 값 + (한 번만) 넘겨받은 필터 [10/21b]
    const def = UI.screens[path] || null;
    if (!def) { location.replace('#/'); return; }
    if (current && current.unmount) current.unmount();
    const page = $('#page');
    page.replaceChildren();
    page.classList.remove('page-enter'); void page.offsetWidth; page.classList.add('page-enter');
    $('.page-title').textContent = def.title; headerActions();
    current = def.mount(page, query) || {};
    document.title = `${def.title} · SupplyGuard`;
    UI.shellEl.sync();
  }

  // 로그인(auth.js)을 마친 뒤에만 셸을 띄운다 [10/20 A]. 도우미 등 셸에 붙는 것은 UI.whenReady 로 기다린다
  const readyQueue = []; let ready = false;
  const whenReady = (fn) => { if (ready) fn(); else readyQueue.push(fn); };
  function boot() { if (UI.auth) UI.auth.gate(startApp); else startApp(); }
  function startApp() {
    const sh = shell();
    UI.shellEl = sh;
    document.body.append(sh, h('div', { id: 'toasts', class: 'toasts', 'aria-live': 'polite' }), helpDialog(), demoDrawer());
    listeners.add(() => { sh.sync(); if (current && current.update) current.update(); });
    window.addEventListener('hashchange', mount);
    document.addEventListener('click', onNavClick); // 상태를 넘기는 링크(data-nav) [10/21b]
    document.addEventListener('keydown', (e) => { if (e.key === '?' && !document.body.classList.contains('locked') && !/input|textarea|select/i.test(e.target.tagName) && !$('dialog[open]')) $('#help').showModal(); });
    mount();
    if (state.source === 'live') { state.verdicts = []; state.stats = null; state.unseen = 0; state.topology = new TopologyStore(); }
    loadEvents();
    ready = true; readyQueue.splice(0).forEach((fn) => fn());
  }

  // 화면 머리 오른쪽(화면 이름 옆)에 그 화면의 주 버튼 · 입력을 둔다. 화면이 바뀌면 비운다
  function headerActions(...nodes) { const el = $('.page-actions'); if (el) replace(el, nodes); }

  window.UI = { h, s, $, replace, fmt, cssVar, countUp, reducedMotion, KINDS, KIND_LONG, KIND_SHORT, levelOf, detailOf, LEVEL_LABEL, INSTALL_STATUS, DECISION_LABEL, LIST_LABEL, ACTOR, SANDBOX, state, emit, listeners, fresh, kindBadge, verdictBadge, statusBadge, decisionBadge, kpi, panel, sheet, empty, pauseToggle, SEV, switchEl, select, feed, barChart, perMinute, topologyGraph, toast, route, navigate, setQuery, go, to, headerActions, screens: {}, timelineBar, srv,
    KIND_ORDER, KIND_STEP, fakeVerdict, attackChain, chainFromVerdicts, decisionBar, previewView, osvQuery, sim, runAttack, runAttackNow, runDnsExfilNow, runInstallDemo, simEvent, api, setSource,
    // 10/20 2차 시안
    disconnect, whenReady, remount: () => mount(), loadEvents, actor, serverFromInfo, CASE_SOURCE, caseLink, topoLink,
    // 10/20 결정 반영
    RETRY_MS, simFail: failHit, simFailNext: (name, n) => failLeft.set(name, Math.max(1, Number(n) || 1)) }; // simFailNext: 회귀용 — 데이터를 받은 뒤 다음 n 번 실패 [10/21]
  document.addEventListener('DOMContentLoaded', boot);
})();
