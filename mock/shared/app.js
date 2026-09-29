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

  const KINDS = ['exec', 'open', 'connect'];
  const LEVEL_LABEL = { normal: '정상', alert: '경고', held: '격리 대상', killed: '격리됨' };
  const levelOf = (v) => (!v.matched ? 'normal' : v.action !== 'kill' ? 'alert' : v.enforced ? 'killed' : 'held');
  const detailOf = (e) => (e.kind === 'exec' ? e.args || e.comm : e.kind === 'open' ? e.path || '' : `${e.dstIp}:${e.dstPort}`);

  // ── 토폴로지 저장소 (frontend/src/lib/topology.ts) ──────
  const SEV = { normal: 0, alert: 1, held: 2, killed: 3 };
  const worse = (a, b) => (SEV[b] > SEV[a] ? b : a);
  class TopologyStore {
    constructor() { this.nodes = new Map(); this.edges = new Map(); }
    ingest(v) {
      const e = v.event; if (!e.containerName) return;
      const now = new Date(e.timestamp).getTime() || Date.now();
      const level = levelOf(v);
      const c = this.touch(`c:${e.containerName}`, 'container', e.containerName, e.containerName, level, now);
      const p = this.touch(`p:${e.containerName}:${e.comm}`, 'process', e.comm, e.containerName, level, now);
      this.link(c.id, p.id, 'exec', level, now);
      if (e.kind === 'open' && e.path) { const f = this.touch(`f:${e.containerName}:${e.path}`, 'file', e.path, e.containerName, level, now); this.link(p.id, f.id, 'open', level, now); }
      else if (e.kind === 'connect') { const d = detailOf(e); const dn = this.touch(`d:${e.containerName}:${d}`, 'dest', d, e.containerName, level, now); this.link(p.id, dn.id, 'connect', level, now); }
    }
    touch(id, type, label, container, level, now) {
      let n = this.nodes.get(id);
      if (!n) { n = { id, type, label, container, level, count: 0, lastSeen: now }; this.nodes.set(id, n); }
      n.count++; n.level = worse(n.level, level); n.lastSeen = Math.max(n.lastSeen, now); return n;
    }
    link(source, target, kind, level, now) {
      const id = `${source}->${target}`;
      let ed = this.edges.get(id);
      if (!ed) { ed = { id, source, target, kind, level, count: 0, lastSeen: now }; this.edges.set(id, ed); }
      ed.count++; ed.level = worse(ed.level, level); ed.lastSeen = Math.max(ed.lastSeen, now);
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
  const state = {
    connected: true, paused: false, verdicts: [], unseen: 0, token: '',
    rules: JSON.parse(JSON.stringify(M.rules)),
    info: { source: 'mock', gadgets: KINDS, enforceKill: true, authRequired: true, gadgetVersion: 'v0.56.1' },
    stats: null, audit: M.buildAudit(Date.now()), topology: new TopologyStore(),
  };
  const listeners = new Set();
  const emit = () => { for (const f of listeners) f(); };

  // ── 시뮬레이션: mock 이벤트 소스 + 파이프라인 + 통계 ──────
  const sim = {
    containers: M.containers.map((c) => Object.assign({ id: M.hexId(Math.random, 64), killedAt: 0 }, c)),
    queue: [], seq: 0, total: 0, violations: 0, killed: [], perContainer: new Map(),
    recent: [], // 최근 60초 이벤트 시각
    trend: [], // 5초 버킷 60개
    nextAttack: Date.now() + 5000, interval: 100, attackEvery: 20000, restartIn: 15000, rnd: Math.random,
  };
  const rnd = (n) => Math.floor(Math.random() * n);
  function mkEvent(c, tpl, at) {
    return Object.assign({ timestamp: new Date(at).toISOString(), containerId: c.id, containerName: c.name, imageName: c.image, pid: 1000 + rnd(30000) }, tpl);
  }
  function bucketOf(t) { return Math.floor(t / 5000) * 5000; }
  function record(v, at) {
    const level = levelOf(v);
    sim.total++; sim.recent.push(at);
    let b = sim.trend[sim.trend.length - 1];
    if (!b || b.ts !== bucketOf(at)) { b = { ts: bucketOf(at), t: new Date(bucketOf(at)).toISOString(), exec: 0, open: 0, connect: 0, violations: 0, w: 0 }; sim.trend.push(b); if (sim.trend.length > 60) sim.trend.shift(); }
    b[v.event.kind]++;
    if (v.matched) { sim.violations++; b.violations++; b.w += level === 'killed' ? 20 : level === 'held' ? 12 : 5; sim.perContainer.set(v.event.containerName, (sim.perContainer.get(v.event.containerName) || 0) + 1); }
  }
  // pipeline: 판정 → (kill 이면) 격리 → 큐
  function pipeline(c, e, at, opts) {
    const v = M.evaluate(state.rules, e);
    if (v.matched && v.action === 'kill') {
      if (!state.info.enforceKill || v.dryRun) v.dryRun = true;
      else if (c.killedAt) v.enforced = true; // 이미 격리 중 — 중복 kill 안 함
      else { v.enforced = true; c.killedAt = at; sim.killed.unshift({ id: c.id, name: c.name, at: new Date(at).toISOString() }); if (!opts || !opts.silent) UI.toast(`${c.name} 격리됨 — ${v.reason}`, { tone: 'danger', action: { label: '이벤트 보기', go: '#/events?verdict=kill' } }); }
    }
    record(v, at);
    state.topology.ingest(v);
    if (v.matched && !(opts && opts.silent)) state.unseen++;
    if (!state.paused || (opts && opts.silent)) sim.queue.push(Object.assign({ key: ++sim.seq }, v));
    return v;
  }
  function tick() {
    const now = Date.now();
    for (const c of sim.containers) {
      if (c.killedAt) {
        if (now - c.killedAt < sim.restartIn) continue;
        c.killedAt = 0; c.id = M.hexId(Math.random, 64);
        UI.toast(`${c.name} 새 컨테이너 ID 로 재기동됨 (데모: 재배포)`, { tone: 'info' });
      }
      if (rnd(3) === 0) pipeline(c, mkEvent(c, c.normal[rnd(c.normal.length)], now), now);
    }
    if (now >= sim.nextAttack) { runAttack(now); sim.nextAttack = now + sim.attackEvery; }
  }
  function runAttack(now, opts) {
    for (const c of sim.containers) if (c.attacker && !c.killedAt) for (const a of M.attack) pipeline(c, mkEvent(c, a, now), now, opts);
  }
  function flush() {
    if (sim.queue.length) { const batch = sim.queue.reverse(); sim.queue = []; state.verdicts = batch.concat(state.verdicts).slice(0, 500); }
  }
  function snapshot() {
    const now = Date.now();
    sim.recent = sim.recent.filter((t) => now - t < 60000);
    const cut = now - 5 * 60000;
    const trend = sim.trend.filter((b) => b.ts >= cut);
    const risk = Math.min(100, trend.reduce((a, b) => a + b.w, 0));
    return {
      timestamp: new Date(now).toISOString(), totalEvents: sim.total, eventsLastMinute: sim.recent.length,
      eventsPerSec: sim.recent.filter((t) => now - t < 5000).length / 5, totalViolations: sim.violations, riskScore: Math.round(risk),
      killed: sim.killed.slice(0, 20), killedCount: sim.killed.length,
      topContainers: [...sim.perContainer].map(([name, violations]) => ({ name, violations })).sort((a, b) => b.violations - a.violations).slice(0, 5),
      trend: trend.map(({ t, exec, open, connect, violations }) => ({ t, exec, open, connect, violations })),
      wsClients: 1, dropped: 0, enforceKill: state.info.enforceKill, source: 'mock',
    };
  }
  // 시작 시 최근 5분을 미리 채운다 (새로고침 직후 빈 화면 방지 — 실제 앱은 /api/events/recent)
  function seed() {
    const start = Date.now() - 300000;
    for (let t = start; t < Date.now() - 500; t += 100) {
      for (const c of sim.containers) if (rnd(3) === 0) pipeline(c, mkEvent(c, c.normal[rnd(c.normal.length)], t), t, { silent: true });
      if ((t - start) % 40000 === 20000) { runAttack(t, { silent: true }); }
      for (const c of sim.containers) if (c.killedAt && t - c.killedAt >= sim.restartIn) { c.killedAt = 0; c.id = M.hexId(Math.random, 64); }
    }
    flush(); state.unseen = 0; state.stats = snapshot();
  }

  // ── 실시간 연결 상태 (WS) 시뮬레이션 ─────────────────────
  let tickTimer, flushTimer, statsTimer;
  function start() {
    tickTimer = setInterval(tick, sim.interval);
    flushTimer = setInterval(() => { flush(); emit(); }, 250);
    statsTimer = setInterval(() => { state.stats = snapshot(); }, 1000);
  }
  function stop() { clearInterval(tickTimer); clearInterval(flushTimer); clearInterval(statsTimer); }
  function disconnect(ms) {
    if (!state.connected) return;
    state.connected = false; stop(); emit();
    UI.toast('실시간 연결이 끊겼습니다 — 재연결 중 (1s → 10s 백오프)', { tone: 'warn' });
    setTimeout(() => { state.connected = true; start(); emit(); UI.toast('실시간 연결 복구', { tone: 'ok' }); }, ms || 3000);
  }

  // ── 공통 컴포넌트 ────────────────────────────────────────
  const kindBadge = (kind) => h('span', { class: `badge badge-kind badge-kind-${kind}` }, kind);
  function verdictBadge(v) {
    const level = levelOf(v);
    const title = level === 'held' ? (v.enforceError ? `격리 실패: ${v.enforceError}` : 'dry-run — 알림만 보냄') : null;
    return h('span', { class: `badge badge-level badge-level-${level}`, title }, LEVEL_LABEL[level]);
  }
  function kpi({ label, value, hint, tone }) {
    return h('div', { class: 'kpi' }, h('div', { class: 'kpi-label' }, label), h('div', { class: `kpi-value num tone-${tone || 'default'}` }, value), hint ? h('div', { class: 'kpi-hint' }, hint) : null);
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
  function confirmButton({ label, confirmLabel, onConfirm, class: cls, disabled }) {
    let armed = false, timer;
    const b = h('button', { type: 'button', class: cls, disabled }, label);
    b.addEventListener('click', () => {
      if (armed) { armed = false; clearTimeout(timer); b.classList.remove('armed'); b.textContent = label; onConfirm(); return; }
      armed = true; b.classList.add('armed'); b.textContent = confirmLabel;
      timer = setTimeout(() => { armed = false; b.classList.remove('armed'); b.textContent = label; }, 4000);
    });
    return b;
  }
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
    const head = full ? h('div', { class: 'feed-head' }, h('span', { class: 'c-time' }, '시각'), h('span', { class: 'c-name' }, '컨테이너'), h('span', { class: 'c-img' }, '이미지'), h('span', { class: 'c-kind' }, 'Kind'), h('span', { class: 'c-detail' }, '상세 (args · path · dst)'), h('span', { class: 'c-rule' }, '규칙'), h('span', { class: 'c-verdict' }, '판정')) : null;
    const root = h('div', { class: `feed ${full ? 'feed-full' : ''}` }, head, scroller);
    let rows = [], selectedKey = null, emptyEl = null;
    function rowEl(v, i) {
      const level = levelOf(v);
      const li = h('li', { class: `feed-row ${onSelect ? 'clickable' : ''} ${v.key === selectedKey ? 'selected' : level === 'killed' || level === 'held' ? 'danger' : ''}`, style: `top:${i * ROW}px;height:${ROW}px` },
        h('span', { class: 'c-time num mono' }, fmt.time(v.event.timestamp)),
        h('span', { class: 'c-name', title: v.event.containerName }, v.event.containerName),
        full && showImage ? h('span', { class: 'c-img', title: v.event.imageName }, v.event.imageName) : null,
        h('span', { class: 'c-kind' }, kindBadge(v.event.kind)),
        h('span', { class: 'c-detail mono', title: detailOf(v.event) }, detailOf(v.event)),
        full ? h('span', { class: 'c-rule', title: v.reason }, v.ruleId || '—') : v.matched ? h('span', { class: 'c-rule-inline', title: v.reason }, v.ruleId) : null,
        h('span', { class: 'c-verdict' }, verdictBadge(v)));
      if (onSelect) li.addEventListener('click', () => onSelect(v));
      return li;
    }
    function draw() {
      if (!rows.length) { list.replaceChildren(); list.style.height = '0px'; if (!emptyEl) { emptyEl = empty(emptyText || '이벤트 수신 대기 중'); scroller.append(emptyEl); } return; }
      if (emptyEl) { emptyEl.remove(); emptyEl = null; }
      const height = scroller.clientHeight || 400, top = scroller.scrollTop;
      const start = Math.max(0, Math.floor(top / ROW) - OVER), end = Math.min(rows.length, Math.ceil((top + height) / ROW) + OVER);
      list.style.height = rows.length * ROW + 'px';
      const frag = document.createDocumentFragment();
      for (let i = start; i < end; i++) frag.append(rowEl(rows[i], i));
      replace(list, frag);
    }
    scroller.addEventListener('scroll', draw);
    new ResizeObserver(draw).observe(scroller);
    root.set = (r) => { rows = r; draw(); };
    root.select = (k) => { selectedKey = k; draw(); };
    root.setShowImage = (v) => { showImage = v; root.classList.toggle('no-img', !v); draw(); };
    return root;
  }

  // 라인 차트 (TrendChart.tsx) — exec·open·connect·위반 4계열, 최근 5분
  const SERIES = [['exec', 'exec', '#7c3aed'], ['open', 'open', '#0284c7'], ['connect', 'connect', '#0d9488'], ['violations', '위반', '#dc2626']];
  function lineChart() {
    const root = h('div', { class: 'chart' });
    let data = [];
    function draw() {
      root.replaceChildren();
      if (!data.length) { root.append(empty('추이 데이터 대기 중')); return; }
      const W = root.clientWidth || 480, H = root.clientHeight || 220;
      const m = { t: 12, r: 16, b: 40, l: 36 };
      const iw = W - m.l - m.r, ih = H - m.t - m.b;
      const max = Math.max(4, ...data.map((d) => Math.max(d.exec, d.open, d.connect, d.violations)));
      const x = (i) => m.l + (data.length === 1 ? iw / 2 : (i / (data.length - 1)) * iw);
      const y = (v) => m.t + ih - (v / max) * ih;
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart-svg' });
      const yTicks = 4;
      for (let i = 0; i <= yTicks; i++) {
        const v = Math.round((max / yTicks) * i), yy = y(v);
        svg.append(s('line', { x1: m.l, x2: W - m.r, y1: yy, y2: yy, stroke: '#f1f5f9' }));
        svg.append(s('text', { x: m.l - 6, y: yy + 4, 'text-anchor': 'end', class: 'tick' }, v));
      }
      svg.append(s('line', { x1: m.l, x2: W - m.r, y1: m.t + ih, y2: m.t + ih, stroke: '#e2e8f0' }));
      const step = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(iw / 64))));
      data.forEach((d, i) => { if (i % step === 0) svg.append(s('text', { x: x(i), y: m.t + ih + 16, 'text-anchor': 'middle', class: 'tick' }, fmt.time(d.t).slice(0, 5))); });
      for (const [key, , color] of SERIES) {
        const dAttr = data.map((d, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(d[key]).toFixed(1)}`).join(' ');
        svg.append(s('path', { d: dAttr, fill: 'none', stroke: color, 'stroke-width': key === 'violations' ? 2 : 1.5, 'stroke-linejoin': 'round' }));
      }
      const legend = s('g', { transform: `translate(${m.l},${H - 8})` });
      let lx = 0;
      for (const [, name, color] of SERIES) { legend.append(s('line', { x1: lx, x2: lx + 14, y1: -4, y2: -4, stroke: color, 'stroke-width': 2 }), s('text', { x: lx + 18, y: 0, class: 'legend' }, name)); lx += 18 + name.length * 8 + 16; }
      svg.append(legend);
      // hover: 가장 가까운 점의 값
      const tip = h('div', { class: 'chart-tip', hidden: true });
      svg.addEventListener('mousemove', (ev) => {
        const r = svg.getBoundingClientRect(); const px = ev.clientX - r.left;
        const i = Math.max(0, Math.min(data.length - 1, Math.round(((px - m.l) / iw) * (data.length - 1))));
        const d = data[i]; tip.hidden = false; tip.style.left = Math.min(W - 150, x(i) + 8) + 'px'; tip.style.top = '8px';
        replace(tip, h('b', null, fmt.time(d.t)), ...SERIES.map(([k, n, c]) => h('div', null, h('i', { style: `background:${c}` }), `${n} ${d[k]}`)));
      });
      svg.addEventListener('mouseleave', () => { tip.hidden = true; });
      root.append(svg, tip);
    }
    new ResizeObserver(draw).observe(root);
    root.set = (d) => { data = d || []; draw(); };
    return root;
  }

  // 토폴로지 그래프 (TopologyPage.tsx 의 3열 고정 레이아웃을 SVG 로)
  const NODE = { w: 230, h: 32, rowH: 52, colX: { container: 0, process: 280, file: 580, dest: 580 } };
  const NODE_STYLE = { normal: ['#ffffff', '#cbd5e1', '#334155'], alert: ['#fffbeb', '#f59e0b', '#78350f'], held: ['#fef2f2', '#f87171', '#991b1b'], killed: ['#dc2626', '#b91c1c', '#ffffff'] };
  const EDGE_COLOR = { normal: '#cbd5e1', alert: '#f59e0b', held: '#ef4444', killed: '#dc2626' };
  const ICON = { container: '▣', process: '⚙', file: '▤', dest: '◎' };
  function topologyGraph() {
    const root = h('div', { class: 'topo' });
    root.set = ({ nodes, edges }) => {
      root.replaceChildren();
      if (!nodes.length) { root.append(empty('표시할 활동 없음 — 이벤트가 들어오면 그래프가 그려집니다')); return; }
      const children = new Map(); for (const e of edges) children.set(e.source, [...(children.get(e.source) || []), e.target]);
      const byId = new Map(nodes.map((n) => [n.id, n])); const pos = new Map(); let row = 0;
      const containers = nodes.filter((n) => n.type === 'container').sort((a, b) => a.label.localeCompare(b.label));
      for (const c of containers) {
        const start = row;
        const procs = (children.get(c.id) || []).map((id) => byId.get(id)).filter(Boolean).sort((a, b) => a.label.localeCompare(b.label));
        for (const p of procs) {
          const pStart = row;
          const leaves = (children.get(p.id) || []).map((id) => byId.get(id)).filter(Boolean).sort((a, b) => (a.level === b.level ? a.label.localeCompare(b.label) : a.level === 'normal' ? 1 : -1));
          for (const l of leaves) pos.set(l.id, { x: NODE.colX[l.type], y: row++ * NODE.rowH });
          if (!leaves.length) row++;
          pos.set(p.id, { x: NODE.colX.process, y: ((pStart + row - 1) / 2) * NODE.rowH });
        }
        if (row === start) row++;
        pos.set(c.id, { x: NODE.colX.container, y: ((start + row - 1) / 2) * NODE.rowH });
        row++;
      }
      const W = 580 + NODE.w + 40, Hh = Math.max(1, row) * NODE.rowH + 20;
      const svg = s('svg', { viewBox: `-20 -10 ${W} ${Hh}`, class: 'topo-svg', preserveAspectRatio: 'xMidYMin meet' });
      const defs = s('defs');
      for (const [lv, c] of Object.entries(EDGE_COLOR)) defs.append(s('marker', { id: `arrow-${lv}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, s('path', { d: 'M0,0 L10,5 L0,10 z', fill: c })));
      svg.append(defs);
      for (const e of edges) {
        const a = pos.get(e.source), b = pos.get(e.target); if (!a || !b) continue;
        const x1 = a.x + NODE.w, y1 = a.y + NODE.h / 2, x2 = b.x, y2 = b.y + NODE.h / 2, c = (x1 + x2) / 2;
        svg.append(s('path', { d: `M${x1},${y1} C${c},${y1} ${c},${y2} ${x2},${y2}`, fill: 'none', stroke: EDGE_COLOR[e.level], 'stroke-width': e.level === 'normal' ? 1 : 2, 'marker-end': `url(#arrow-${e.level})`, class: e.level !== 'normal' ? 'edge-hot' : '' }));
        if (e.kind !== 'exec') svg.append(s('text', { x: c, y: (y1 + y2) / 2 - 4, 'text-anchor': 'middle', class: 'edge-label' }, e.kind));
      }
      for (const n of nodes) {
        const p = pos.get(n.id); if (!p) continue; const [bg, bd, fg] = NODE_STYLE[n.level];
        const g = s('g', { transform: `translate(${p.x},${p.y})` }, s('title', null, `${n.label} · ${n.count}회`));
        g.append(s('rect', { width: NODE.w, height: NODE.h, rx: 6, fill: bg, stroke: bd, 'stroke-dasharray': n.level === 'held' ? '4 3' : null }));
        g.append(s('text', { x: 10, y: 21, class: 'node-icon', fill: fg }, ICON[n.type]));
        const label = n.label.length > 28 ? '…' + n.label.slice(-27) : n.label;
        g.append(s('text', { x: 30, y: 21, fill: fg, class: n.type === 'file' || n.type === 'dest' ? 'node-mono' : 'node-label' }, label));
        svg.append(g);
      }
      root.append(svg);
    };
    return root;
  }

  // ── 토스트 ──────────────────────────────────────────────
  function toast(text, opts) {
    const region = $('#toasts'); if (!region) return;
    const o = opts || {};
    const el = h('div', { class: `toast toast-${o.tone || 'info'}` }, h('span', null, text), o.action ? h('a', { href: o.action.go, class: 'toast-action', onclick: () => el.remove() }, o.action.label) : null, h('button', { type: 'button', class: 'toast-x', 'aria-label': '닫기', onclick: () => el.remove() }, '×'));
    region.append(el);
    while (region.children.length > 4) region.firstChild.remove();
    setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 300); }, 6000);
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

  const NAV = [['/', '대시보드', '▦'], ['/events', '이벤트', '≣'], ['/topology', '토폴로지', '⌘'], ['/policies', '정책', '⚙'], ['/audit', '감사 로그', '◷']];
  const FLOW = [['/', '1 관찰'], ['/events', '2 판정'], ['/topology', '3 격리'], ['/policies', '4 정책'], ['/audit', '5 감사']];
  let current = null; // { unmount, update }

  function shell() {
    const nav = h('nav', { class: 'side-nav' }, NAV.map(([to, label, icon]) => h('a', { href: '#' + to, class: 'nav-link', 'data-to': to }, h('span', { class: 'nav-icon', 'aria-hidden': true }, icon), label)));
    const foot = h('div', { class: 'side-foot' });
    const aside = h('aside', { class: 'sidebar' }, h('a', { href: '#/', class: 'brand' }, h('span', { class: 'brand-icon', 'aria-hidden': true }, '🛡'), 'SupplyGuard'), nav, foot);
    const ws = h('span', { class: 'ws' });
    const eps = h('span', { class: 'eps' });
    const bell = h('a', { href: '#/events?verdict=violation', class: 'bell', 'aria-label': '새 위반', onclick: () => { state.unseen = 0; emit(); } }, h('span', { 'aria-hidden': true }, '🔔'), h('span', { class: 'bell-badge num', hidden: true }));
    const flow = h('div', { class: 'flow' }, FLOW.map(([to, label]) => h('a', { href: '#' + to, class: 'flow-step', 'data-to': to }, label)));
    const header = h('header', { class: 'topbar' }, flow, h('div', { class: 'topbar-right' }, h('span', { class: 'ws-status', role: 'status' }, ws, eps), bell, h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => $('#help').showModal(), title: '사용 안내 (?)' }, '? 안내'), h('button', { type: 'button', class: 'btn btn-primary btn-xs', onclick: () => $('#demo').classList.toggle('open') }, '데모 제어')));
    const page = h('main', { class: 'page', id: 'page' });
    const main = h('div', { class: 'main' }, header, page);
    const root = h('div', { class: 'shell' }, aside, main);
    function sync() {
      const { path } = route();
      for (const a of nav.children) a.classList.toggle('active', a.dataset.to === path);
      for (const a of flow.children) a.classList.toggle('active', a.dataset.to === path);
      const st = state.stats, enforce = state.info.enforceKill;
      replace(foot, 
        h('div', null, h('span', null, '수집'), h('span', null, 'Mock 데모')),
        h('div', null, h('span', null, '격리'), h('span', { class: enforce ? 'tone-danger-soft' : 'tone-warn-soft' }, enforce ? '자동 종료' : 'dry-run')),
        h('div', null, h('span', null, 'IG'), h('span', { class: 'num' }, state.info.gadgetVersion)));
      ws.className = `ws ${state.connected ? 'on' : 'off'}`; ws.textContent = state.connected ? '실시간 연결됨' : '재연결 중…';
      replace(eps, '초당 ', h('b', { class: 'num' }, fmt.num(Math.round((st ? st.eventsPerSec : 0) * 10) / 10)), ' evt');
      const badge = bell.lastChild; badge.hidden = state.unseen === 0; badge.textContent = state.unseen > 99 ? '99+' : state.unseen;
      bell.setAttribute('aria-label', `새 위반 ${state.unseen}건`);
    }
    root.sync = sync;
    return root;
  }

  function helpDialog() {
    const steps = [
      ['대시보드에서 관찰', 'KPI 4개와 실시간 피드로 지금 무슨 일이 일어나는지 본다. 위험 점수는 최근 5분 위반의 가중합.', '#/'],
      ['이벤트에서 판정 확인', '행을 누르면 원본 JSON 과 어느 정책에 걸렸는지 보인다. 상단 종 아이콘은 새 위반으로 바로 간다.', '#/events?verdict=violation'],
      ['토폴로지에서 격리 확인', '컨테이너 → 프로세스 → 파일/목적지 관계. 붉은 노드가 격리를 유발한 행위.', '#/topology'],
      ['정책 조정', '폼 또는 YAML 로 편집 후 "저장 후 적용". dry-run 을 켜면 kill 정책도 알림만 보낸다(오탐 보호).', '#/policies'],
      ['감사 로그로 되짚기', '저장된 위반 판정을 기간·규칙·컨테이너로 조회한다.', '#/audit'],
    ];
    const d = h('dialog', { id: 'help', class: 'dialog' },
      h('form', { method: 'dialog', class: 'dialog-body' },
        h('h3', null, '사용 흐름 (5단계)'),
        h('ol', { class: 'steps' }, steps.map(([t, desc, go]) => h('li', null, h('div', null, h('b', null, t), h('p', null, desc)), h('a', { href: go, class: 'btn btn-ghost btn-xs', onclick: () => d.close() }, '이동')))),
        h('p', { class: 'muted' }, '데모 제어(상단 오른쪽)에서 공격 시나리오를 바로 실행하거나 격리 모드를 dry-run 으로 바꿔 볼 수 있습니다. 키보드 ? 로 이 안내를 엽니다.'),
        h('div', { class: 'dialog-foot' }, h('button', { class: 'btn btn-primary', value: 'close' }, '닫기'))));
    return d;
  }

  function demoDrawer() {
    const countdown = h('span', { class: 'num' });
    const body = h('div', { class: 'drawer-body' },
      h('h3', null, '데모 제어'),
      h('p', { class: 'muted' }, '실제 앱에는 없는 목업 전용 패널. 백엔드 mock 소스가 하는 일을 손으로 일으킨다.'),
      h('label', { class: 'row' }, h('span', null, '격리 모드 ', h('small', { class: 'muted' }, 'ENFORCE_KILL')), switchEl(state.info.enforceKill, (on) => { state.info.enforceKill = on; emit(); toast(on ? '격리 모드: 자동 종료' : '격리 모드: dry-run (알림만)', { tone: on ? 'danger' : 'warn' }); })),
      h('div', { class: 'row' }, h('span', null, '다음 공격 시나리오까지 ', countdown), h('button', { type: 'button', class: 'btn btn-danger btn-xs', onclick: () => { runAttack(Date.now()); sim.nextAttack = Date.now() + sim.attackEvery; } }, '지금 실행')),
      h('div', { class: 'row' }, h('span', null, '실시간 연결'), h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => disconnect(3000) }, '3초 끊기')),
      h('label', { class: 'row' }, h('span', null, '정상 이벤트 속도'), select([['300', '느리게'], ['100', '보통'], ['40', '빠르게']], '100', (v) => { sim.interval = Number(v); if (state.connected) { stop(); start(); } })),
      h('label', { class: 'row' }, h('span', null, '공격 반복 주기'), select([['10000', '10초'], ['20000', '20초'], ['60000', '60초']], '20000', (v) => { sim.attackEvery = Number(v); })),
      h('div', { class: 'row muted small' }, h('span', null, '격리된 컨테이너는 15초 뒤 새 ID 로 재기동한다 (재배포 흉내).')));
    const d = h('aside', { id: 'demo', class: 'drawer' }, h('button', { type: 'button', class: 'drawer-x', 'aria-label': '닫기', onclick: () => d.classList.remove('open') }, '×'), body);
    setInterval(() => { countdown.textContent = Math.max(0, Math.ceil((sim.nextAttack - Date.now()) / 1000)) + '초'; }, 500);
    return d;
  }

  function mount() {
    const { path, query } = route();
    const def = UI.screens[path] || null;
    if (!def) { location.replace('#/'); return; }
    if (current && current.unmount) current.unmount();
    const page = $('#page');
    page.replaceChildren();
    page.classList.remove('page-enter'); void page.offsetWidth; page.classList.add('page-enter');
    current = def.mount(page, query) || {};
    document.title = `${def.title} · SupplyGuard`;
    UI.shellEl.sync();
  }

  function boot() {
    seed();
    const sh = shell();
    UI.shellEl = sh;
    document.body.append(sh, h('div', { id: 'toasts', class: 'toasts', 'aria-live': 'polite' }), helpDialog(), demoDrawer());
    listeners.add(() => { sh.sync(); if (current && current.update) current.update(); });
    window.addEventListener('hashchange', mount);
    document.addEventListener('keydown', (e) => { if (e.key === '?' && !/input|textarea|select/i.test(e.target.tagName)) $('#help').showModal(); });
    mount();
    start();
  }

  window.UI = { h, s, $, replace, fmt, KINDS, levelOf, detailOf, LEVEL_LABEL, state, emit, listeners, kindBadge, verdictBadge, kpi, panel, empty, pauseToggle, confirmButton, switchEl, select, feed, lineChart, topologyGraph, toast, route, navigate, setQuery, screens: {}, sim, runAttack };
  document.addEventListener('DOMContentLoaded', boot);
})();
