// SupplyGuard 목업 — 화면 5개 (frontend/src/features/* 와 1:1). UI.screens[path] = { title, mount(page, query) → { update, unmount } }
(function () {
  'use strict';
  const U = window.UI, M = window.MOCK;
  const { h, replace, fmt, kindBadge, verdictBadge, kpi, panel, empty, levelOf, detailOf, KINDS, state } = U;
  const LEVEL_TONE = (level) => (level === 'killed' ? 'danger' : level === 'held' ? 'danger' : level === 'alert' ? 'warn' : 'default');

  // ── 대시보드 ─────────────────────────────────────────────
  U.screens['/'] = {
    title: '대시보드',
    mount(page) {
      const kpis = h('div', { class: 'kpi-grid' });
      const feedEl = U.feed({ full: false });
      const chart = U.lineChart();
      const top = h('ul', { class: 'top-list' });
      const pause = U.pauseToggle();
      page.append(h('div', { class: 'dash' }, kpis,
        h('div', { class: 'dash-grid' },
          panel({ title: '실시간 이벤트 피드', actions: [h('a', { href: '#/events', class: 'link small' }, '전체 보기'), pause], body: feedEl }),
          h('div', { class: 'dash-side' },
            panel({ title: '시스템콜 추이 (최근 5분)', body: h('div', { class: 'chart-wrap' }, chart) }),
            panel({ title: '위반 Top 컨테이너', body: top })))));
      function update() {
        const st = state.stats || {}; const risk = st.riskScore || 0; const last = (st.killed || [])[0];
        replace(kpis, 
          kpi({ label: '총 이벤트 (1분)', value: fmt.num(st.eventsLastMinute || 0), hint: `누적 ${fmt.num(st.totalEvents || 0)}` }),
          kpi({ label: '위반 건수', value: fmt.num(st.totalViolations || 0), tone: st.totalViolations ? 'warn' : 'default', hint: '서버 기동 이후 누적' }),
          kpi({ label: '격리된 컨테이너', value: fmt.num(st.killedCount || 0), tone: st.killedCount ? 'danger' : 'default', hint: last ? `최근 ${last.name} · ${fmt.time(last.at)}` : st.enforceKill === false ? 'dry-run — 종료하지 않고 알림만' : '격리 기록 없음' }),
          kpi({ label: '위험 점수', value: [risk, h('span', { class: 'kpi-unit' }, ' / 100')], tone: risk >= 60 ? 'danger' : risk >= 20 ? 'warn' : 'default', hint: '최근 5분 위반 가중합 (격리 20 · 격리 대상 12 · 경고 5)' }));
        feedEl.set(state.verdicts);
        chart.set(st.trend);
        pause.sync();
        const rows = st.topContainers || []; const max = Math.max(1, ...rows.map((c) => c.violations));
        replace(top, rows.length ? rows.map((c) => h('li', null, h('a', { href: `#/topology?container=${encodeURIComponent(c.name)}`, class: 'top-row', title: '토폴로지에서 보기' }, h('span', { class: 'top-name' }, c.name), h('span', { class: 'bar' }, h('span', { class: 'bar-fill', style: `width:${(c.violations / max) * 100}%` })), h('span', { class: 'num top-n' }, fmt.num(c.violations))))) : empty('위반 없음'));
      }
      update();
      return { update };
    },
  };

  // ── 이벤트 ───────────────────────────────────────────────
  const VERDICT_OPTS = [['all', '전체'], ['normal', '정상'], ['violation', '위반 전체'], ['alert', '경고'], ['kill', '격리 (대상 포함)']];
  U.screens['/events'] = {
    title: '이벤트',
    mount(page, query) {
      const f = { kind: query.get('kind') || '', verdict: query.get('verdict') || 'all', container: query.get('container') || '', period: query.get('period') || 'live' };
      let selected = null;
      const count = h('span', { class: 'num muted' });
      const detail = h('div', { class: 'detail-slot' });
      const feedEl = U.feed({ full: true, onSelect: (v) => { selected = v; feedEl.select(v.key); feedEl.setShowImage(false); showDetail(); }, empty: '조건에 맞는 이벤트 없음' });
      const pause = U.pauseToggle();
      const note = h('div', { class: 'note', hidden: true }, '기간 조회는 감사 로그에 저장된 위반 판정만 보여 줍니다.');
      const periodBtns = h('div', { class: 'seg', role: 'group', 'aria-label': '기간' });
      const setF = (k, v) => { f[k] = v; U.setQuery({ [k]: v === 'all' || v === 'live' ? '' : v }); update(); };
      const filters = h('div', { class: 'filters' },
        h('label', null, 'Kind ', U.select([['', '전체'], ...KINDS.map((k) => [k, k])], f.kind, (v) => setF('kind', v))),
        h('label', null, '판정 ', U.select(VERDICT_OPTS, f.verdict, (v) => setF('verdict', v))),
        h('input', { class: 'ctl w-44', placeholder: '컨테이너 검색', value: f.container, oninput: (e) => setF('container', e.target.value) }),
        periodBtns);
      const body = h('div', { class: 'col' }, filters, note, h('div', { class: 'grow' }, feedEl));
      const main = panel({ title: ['이벤트 · 판정 스트림 ', count], actions: pause, body, class: 'grow' });
      page.append(h('div', { class: 'split' }, main, detail));
      let history = [], histKey = '';
      function loadHistory() {
        const key = `${f.period}|${f.kind}|${f.container}|${f.verdict}`; if (key === histKey) return; histKey = key;
        const since = new Date(Date.now() - (f.period === '1h' ? 3600e3 : 86400e3)).toISOString();
        U.api.audit({ since, kind: f.kind, container: f.container, limit: 500, action: f.verdict === 'alert' || f.verdict === 'kill' ? f.verdict : '' })
          .then((rows) => { if (histKey !== key) return; history = rows.map((r) => Object.assign({ key: -r.id }, r)); note.textContent = '기간 조회는 감사 로그에 저장된 위반 판정만 보여 줍니다.'; update(); })
          .catch((e) => { note.textContent = `조회 실패: ${e.message}`; });
      }
      function rowsNow() {
        if (f.period !== 'live') loadHistory();
        const src = f.period === 'live' ? state.verdicts : history;
        const q = f.container.toLowerCase();
        return src.filter((v) => {
          if (f.kind && v.event.kind !== f.kind) return false;
          if (q && !v.event.containerName.toLowerCase().includes(q)) return false;
          const l = levelOf(v);
          switch (f.verdict) { case 'normal': return l === 'normal'; case 'violation': return l !== 'normal'; case 'alert': return l === 'alert'; case 'kill': return l === 'killed' || l === 'held'; }
          return true;
        });
      }
      function showDetail() {
        detail.replaceChildren();
        if (!selected) { feedEl.setShowImage(true); return; }
        const v = selected; const rule = v.ruleId ? state.rules.find((r) => r.id === v.ruleId) : null;
        const json = Object.assign({}, v); delete json.key;
        detail.append(panel({ title: '이벤트 상세', class: 'detail', actions: h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-label': '닫기', onclick: () => { selected = null; feedEl.select(null); showDetail(); } }, '✕'), body: h('div', { class: 'detail-body' },
          h('dl', { class: 'dl' }, h('dt', null, '판정'), h('dd', null, verdictBadge(v)), h('dt', null, '시각'), h('dd', { class: 'num' }, fmt.dateTime(v.event.timestamp)), h('dt', null, '컨테이너'), h('dd', null, v.event.containerName), h('dt', null, '사유'), h('dd', null, v.reason || '—'), v.enforceError ? [h('dt', null, '격리 오류'), h('dd', { class: 'tone-danger' }, v.enforceError)] : null),
          v.ruleId ? h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('b', null, '관련 정책'), h('a', { href: `#/policies?id=${encodeURIComponent(v.ruleId)}`, class: 'link small' }, '정책 편집')), h('div', { class: 'mono small' }, v.ruleId), rule ? h('p', { class: 'muted small' }, rule.description) : h('p', { class: 'muted small' }, '현재 정책 목록에 없음 (삭제·변경됨)')) : null,
          h('div', null, h('b', null, '원본 JSON'), h('pre', { class: 'json' }, JSON.stringify(json, null, 2)))) }));
      }
      function update() {
        const rows = rowsNow();
        count.textContent = `${fmt.num(rows.length)}건`;
        feedEl.set(rows);
        note.hidden = f.period === 'live';
        if (f.period === 'live') histKey = ''; pause.hidden = f.period !== 'live'; pause.sync();
        replace(periodBtns, ['live', '1h', '24h'].map((p) => h('button', { type: 'button', class: `seg-btn ${f.period === p ? 'on' : ''}`, onclick: () => setF('period', p) }, p === 'live' ? '실시간' : p)));
      }
      update();
      return { update };
    },
  };

  // ── 토폴로지 ─────────────────────────────────────────────
  // 왼쪽 그래프 + 오른쪽 "공격 체인" 패널. 체인은 데모 시나리오 순서(1 exec → 2 open → 3 connect)로 위반 경로를 나열하고,
  // 항목을 누르면 그래프에서 해당 노드와 연결선만 강조된다. 노드를 누르면 상세(횟수·걸린 규칙·사유)가 뜬다.
  const WINDOWS = [1, 5, 15];
  const KIND_ORDER = { exec: 1, open: 2, connect: 3 };
  const KIND_STEP = { exec: '1 실행', open: '2 파일', connect: '3 통신' };
  const fakeVerdict = (level) => ({ matched: level !== 'normal', action: level === 'alert' ? 'alert' : 'kill', enforced: level === 'killed' });
  U.screens['/topology'] = {
    title: '토폴로지',
    mount(page, query) {
      let container = query.get('container') || '', windowMin = 5, last = 0, selected = null, snap = { nodes: [], edges: [] };
      const graph = U.topologyGraph({ onSelect: (n) => { selected = selected && selected.id === n.id ? null : n; graph.select(selected ? selected.id : null); renderSide(); } });
      const meta = h('span', { class: 'num muted' });
      const sel = h('span');
      const range = h('input', { type: 'range', min: 0, max: WINDOWS.length - 1, value: WINDOWS.indexOf(windowMin), class: 'range', oninput: (e) => { windowMin = WINDOWS[Number(e.target.value)]; draw(); } });
      const winLabel = h('span', { class: 'num w-10' });
      const legend = h('div', { class: 'legend-row' }, Object.entries(U.LEVEL_LABEL).map(([l, label]) => h('span', null, h('i', { class: `sw sw-${l}` }), label)), h('span', { class: 'muted' }, h('i', { class: 'sw', style: 'border-color:#e2e8f0;background:linear-gradient(90deg,#cbd5e1 50%,transparent 50%)' }), '선 굵기 = 위반'));
      const side = h('div', { class: 'topo-side' });
      page.append(h('div', { class: 'topo-layout' },
        panel({ title: ['보안 토폴로지 ', meta], class: 'grow', actions: h('div', { class: 'row-actions' }, sel, h('label', { class: 'row-inline' }, '최근 ', range, winLabel)), body: h('div', { class: 'col' }, legend, h('div', { class: 'topo-wrap grow' }, graph)) }),
        side));
      // 공격 체인: 컨테이너별로 위반을 일으킨 노드를 시나리오 순서로 — 1 실행(프로세스의 exec 위반) → 2 파일(open) → 3 통신(connect)
      function chains() {
        const out = [];
        const step = (kind, n) => ({ kind, node: n, level: n.byKind[kind], rules: [...n.rules.entries()].filter(([id]) => n.ruleKinds.get(id) === kind).sort((a, b) => b[1] - a[1]).map(([id]) => id), at: n.lastViolation || n.lastSeen });
        for (const c of snap.nodes.filter((n) => n.type === 'container').sort((a, b) => U.SEV[b.level] - U.SEV[a.level])) {
          const steps = [];
          for (const n of snap.nodes) {
            if (n.container !== c.label) continue;
            if (n.type === 'process' && n.byKind.exec) steps.push(step('exec', n));
            if (n.type === 'file' && n.byKind.open) steps.push(step('open', n));
            if (n.type === 'dest' && n.byKind.connect) steps.push(step('connect', n));
          }
          if (!steps.length) continue;
          steps.sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || U.SEV[b.level] - U.SEV[a.level] || a.at - b.at);
          out.push({ container: c, steps });
        }
        return out;
      }
      function nodeDetail(n) {
        const TYPE = { container: '컨테이너', process: '프로세스', file: '파일', dest: '외부 목적지' };
        return h('section', { class: 'side-card' },
          h('div', { class: 'card-head' }, h('b', null, '선택한 노드'), h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => { selected = null; graph.select(null); renderSide(); } }, '✕')),
          h('dl', { class: 'dl tight' },
            h('dt', null, '종류'), h('dd', null, TYPE[n.type]),
            h('dt', null, '이름'), h('dd', { class: n.type === 'file' || n.type === 'dest' ? 'mono' : '' }, n.label),
            h('dt', null, '컨테이너'), h('dd', null, n.container),
            h('dt', null, '판정'), h('dd', null, verdictBadge(fakeVerdict(n.level))),
            h('dt', null, '횟수'), h('dd', { class: 'num' }, `${fmt.num(n.count)}회 · 위반 ${fmt.num(n.violations)}회`),
            h('dt', null, '마지막'), h('dd', { class: 'num' }, fmt.time(new Date(n.lastSeen).toISOString()))),
          n.rules.size ? h('div', null, h('div', { class: 'small strong' }, '걸린 규칙'), h('ul', { class: 'rule-chips' }, [...n.rules.entries()].sort((a, b) => b[1] - a[1]).map(([id, cnt]) => h('li', null, h('a', { href: `#/policies?id=${encodeURIComponent(id)}`, class: 'chip mono' }, `${id} ×${cnt}`))))) : null,
          n.reason ? h('p', { class: 'small muted' }, n.reason) : null,
          h('div', { class: 'row-actions' }, h('a', { href: `#/events?container=${encodeURIComponent(n.container)}${n.level !== 'normal' ? '&verdict=violation' : ''}`, class: 'btn btn-ghost btn-xs' }, '이벤트에서 보기 →')));
      }
      function renderSide() {
        const list = chains();
        replace(side,
          selected ? nodeDetail(selected) : null,
          h('section', { class: 'side-card grow' },
            h('div', { class: 'card-head' }, h('b', null, '공격 체인'), h('span', { class: 'small muted num' }, `최근 ${windowMin}분 · ${list.length}개 컨테이너`)),
            list.length ? list.map(({ container: c, steps }) => h('div', { class: 'chain' },
              h('button', { type: 'button', class: `chain-head ${selected && selected.id === c.id ? 'on' : ''}`, onclick: () => { selected = c; graph.select(c.id); renderSide(); } }, h('span', { class: 'strong' }, c.label), verdictBadge(fakeVerdict(c.level))),
              h('ol', { class: 'chain-steps' }, steps.map((st) => h('li', null, h('button', { type: 'button', class: `chain-step ${selected && selected.id === st.node.id ? 'on' : ''}`, onclick: () => { selected = st.node; graph.select(st.node.id); renderSide(); } },
                h('span', { class: `step-no step-${st.kind}` }, KIND_STEP[st.kind]),
                h('span', { class: 'step-label mono', title: st.node.label }, st.node.label),
                h('span', { class: 'step-rule small muted', title: st.rules.join(', ') }, st.rules[0] || ''),
                verdictBadge(fakeVerdict(st.level)))))))) :
              h('div', { class: 'empty' }, state.source === 'sim' ? '이 창에 위반 없음 — 데모 제어 → 지금 실행' : '이 창에 위반 없음')));
      }
      function draw() {
        snap = state.topology.snapshot(windowMin * 60000, container || undefined);
        const risky = snap.nodes.filter((n) => n.level !== 'normal').length;
        meta.textContent = `노드 ${snap.nodes.length} · 위험 ${risky}`;
        winLabel.textContent = `${windowMin}분`;
        replace(sel, U.select([['', '모든 컨테이너'], ...state.topology.containers().map((c) => [c, c])], container, (v) => { container = v; U.setQuery({ container: v }); selected = null; graph.select(null); draw(); }));
        if (selected && !snap.nodes.some((n) => n.id === selected.id)) { selected = null; graph.select(null); }
        graph.set(snap);
        renderSide();
      }
      draw();
      return { update() { if (Date.now() - last > 1000) { last = Date.now(); draw(); } } }; // 스트림은 250ms, 그래프는 1초
    },
  };

  // ── 정책 ─────────────────────────────────────────────────
  const LIST_FIELDS = ['containers', 'denyComms', 'denyArgs', 'denyPaths', 'allowPaths', 'allowPorts', 'allowCidrs', 'denyPorts', 'denyCidrs'];
  const PORT_FIELDS = ['allowPorts', 'denyPorts'];
  const FIELDS_BY_KIND = {
    exec: [['denyComms', '금지 프로세스', 'comm 또는 argv[0] 이름 (예: curl, wget, nc)'], ['denyArgs', '금지 인자 패턴', '인자 문자열에 포함되면 위반 (예: | sh)']],
    open: [['denyPaths', '금지 경로', '접두사 일치, * ? [ ] 가 있으면 glob (예: /home/*/.ssh/*)'], ['allowPaths', '예외 경로', '금지 경로보다 먼저 평가되는 허용 목록']],
    connect: [['allowPorts', '허용 포트', '허용 포트 또는 허용 대역이면 통과, 그 밖은 위반'], ['allowCidrs', '허용 대역', 'CIDR 또는 IP (예: 10.0.0.0/8)'], ['denyPorts', '금지 포트', '허용 목록과 무관하게 항상 위반'], ['denyCidrs', '금지 대역', '허용 목록과 무관하게 항상 위반']],
  };
  // 최소 YAML — 규칙 스키마(스칼라·문자열/숫자 목록)만 다룬다
  const yq = (v) => (typeof v === 'number' || typeof v === 'boolean' ? String(v) : /^[A-Za-z0-9_./*?\[\]:-]+$/.test(v) && !/^[-?:]/.test(v) && !/:$/.test(v) ? v : JSON.stringify(v));
  function ruleToYaml(r, indent) {
    const pad = ' '.repeat(indent || 0); const lines = [];
    for (const k of ['id', 'description', 'kind', 'action', 'dryRun', 'disabled']) if (r[k] !== undefined && r[k] !== '' && r[k] !== false) lines.push(`${pad}${k}: ${yq(r[k])}`);
    for (const k of LIST_FIELDS) if (r[k] && r[k].length) { lines.push(`${pad}${k}:`); for (const x of r[k]) lines.push(`${pad}  - ${yq(x)}`); }
    return lines.join('\n');
  }
  const rulesToYaml = (rs) => '# SupplyGuard 정책 — PUT /api/policies 로 전체 교체\nrules:\n' + rs.map((r) => ruleToYaml(r, 4).replace(/^ {4}/, '  - ')).join('\n\n') + '\n';
  function parseScalar(v) {
    v = v.trim();
    if (v === '') return '';
    if (/^\[.*\]$/.test(v)) return v.slice(1, -1).split(',').map((x) => parseScalar(x)).filter((x) => x !== '');
    if (/^".*"$/.test(v)) return JSON.parse(v);
    if (/^'.*'$/.test(v)) return v.slice(1, -1);
    if (v === 'true') return true; if (v === 'false') return false;
    if (/^-?\d+$/.test(v)) return Number(v);
    return v;
  }
  function parseYaml(text) {
    const lines = text.split('\n').map((l) => l.replace(/\s+#.*$/, '')).filter((l) => l.trim() && !l.trim().startsWith('#')).map((l) => ({ indent: l.match(/^ */)[0].length, text: l.trim() }));
    let i = 0;
    function block(indent) {
      if (i >= lines.length) return null;
      if (lines[i].text.startsWith('- ')) { const arr = []; while (i < lines.length && lines[i].indent === indent && lines[i].text.startsWith('- ')) { const t = lines[i].text.slice(2); if (/^[A-Za-z_][\w]*:( |$)/.test(t)) { lines[i] = { indent: indent + 2, text: t }; arr.push(block(indent + 2)); } else { i++; arr.push(parseScalar(t)); } } return arr; }
      const obj = {};
      while (i < lines.length && lines[i].indent === indent && !lines[i].text.startsWith('- ')) {
        const m = lines[i].text.match(/^([A-Za-z_][\w]*):\s*(.*)$/); if (!m) throw new Error(`YAML 해석 불가: "${lines[i].text}"`);
        i++;
        if (m[2] !== '') obj[m[1]] = parseScalar(m[2]);
        else if (i < lines.length && lines[i].indent > indent) obj[m[1]] = block(lines[i].indent);
        else if (i < lines.length && lines[i].indent === indent && lines[i].text.startsWith('- ')) obj[m[1]] = block(indent);
        else obj[m[1]] = null;
      }
      return obj;
    }
    const out = block(lines.length ? lines[0].indent : 0);
    if (i < lines.length) throw new Error(`YAML 들여쓰기 오류 (${i + 1}번째 항목 근처)`);
    return out;
  }
  function validateRule(r, existing) {
    if (!r || typeof r !== 'object') throw new Error('YAML 최상위는 규칙 객체여야 함');
    if (!/^[a-z0-9][a-z0-9-]*$/.test(r.id || '')) throw new Error('id 는 소문자·숫자·하이픈');
    if (!KINDS.includes(r.kind)) throw new Error('kind 는 exec | open | connect');
    if (!['alert', 'kill'].includes(r.action)) throw new Error('action 은 alert | kill');
    for (const f of PORT_FIELDS) if (r[f] && r[f].some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) throw new Error(`${f}: 1~65535 정수만`);
    return r;
  }
  const canWrite = () => !state.info.authRequired || state.token !== '';
  const errText = (e) => (e && e.message) || String(e);

  U.screens['/policies'] = {
    title: '정책',
    mount(page, query) {
      let selected = query.get('id') || '';
      const list = h('ul', { class: 'rule-list' });
      const editor = h('div', { class: 'grow' });
      const editorTitle = h('span');
      const tokenRow = h('label', { class: 'token-row', hidden: !state.info.authRequired }, '🔑 ', h('input', { type: 'password', autocomplete: 'off', class: 'ctl grow', placeholder: '관리자 토큰 (변경 시 필요 · 목업은 아무 값)', value: state.token, oninput: (e) => { state.token = e.target.value; renderEditor(); } }));
      const select = (id) => { selected = id; U.setQuery({ id }); renderList(); renderEditor(); };
      page.append(h('div', { class: 'split' },
        panel({ title: h('span', { id: 'rules-title' }), class: 'w-80', actions: [h('button', { type: 'button', class: 'btn btn-ghost btn-xs', title: '전체 정책을 YAML 로 보기·일괄 적용', onclick: () => select('__yaml__') }, '{} YAML'), h('button', { type: 'button', class: 'btn btn-primary btn-xs', onclick: () => select('__new__') }, '+ 새 정책')], body: h('div', { class: 'col' }, h('div', { class: 'grow scroll' }, list), tokenRow) }),
        panel({ title: editorTitle, class: 'grow', body: editor })));
      function renderList() {
        tokenRow.hidden = !state.info.authRequired;
        page.querySelector('#rules-title').textContent = `정책 ${state.rules.length}`;
        replace(list, state.rules.length ? state.rules.map((r) => h('li', null, h('button', { type: 'button', class: `rule-row ${r.id === selected ? 'selected' : ''}`, onclick: () => select(r.id) },
          h('span', { class: `dot ${r.disabled ? 'off' : 'on'}`, title: r.disabled ? '비활성' : '활성' }),
          h('span', { class: `rule-id ${r.disabled ? 'muted' : ''}` }, r.id),
          h('span', { class: `badge ${r.action === 'kill' && !r.dryRun ? 'badge-kill' : 'badge-alert'}` }, r.action, r.dryRun ? ' · dry' : ''),
          kindBadge(r.kind)))) : empty('정책 없음'));
      }
      function renderEditor() {
        editor.replaceChildren();
        const cur = state.rules.find((r) => r.id === selected);
        if (selected === '__yaml__') { editorTitle.textContent = '전체 정책 YAML'; editor.append(bulkYaml()); return; }
        if (selected === '__new__' || cur) { editorTitle.textContent = selected === '__new__' ? '새 정책' : `정책 편집 · ${cur.id}`; editor.append(ruleEditor(cur || { id: '', kind: 'open', action: 'alert' }, selected === '__new__')); return; }
        editorTitle.textContent = '정책 편집'; editor.append(empty('왼쪽에서 정책을 고르거나 새 정책을 만드세요'));
      }
      function bulkYaml() {
        const ta = h('textarea', { class: 'ctl mono yaml grow', spellcheck: 'false', 'aria-label': '전체 정책 YAML', disabled: true }, '불러오는 중…');
        U.api.exportYaml().then((text) => { ta.value = text === null ? rulesToYaml(state.rules) : text; ta.disabled = false; apply.disabled = !canWrite(); }).catch((e) => { msg.className = 'grow small tone-danger'; msg.textContent = errText(e); });
        const msg = h('span', { class: 'grow small' });
        const apply = U.confirmButton({ label: '전체 교체 후 적용 ▶', confirmLabel: '기존 정책을 모두 교체 — 확정', class: 'btn btn-primary', disabled: true, onConfirm: () => {
          const done = (rs) => { renderList(); msg.className = 'grow small tone-ok'; msg.textContent = `${rs.length}개 정책을 엔진에 적용함`; U.toast(`정책 ${rs.length}개 전체 교체 후 적용`, { tone: 'ok' }); };
          const fail = (e) => { msg.className = 'grow small tone-danger'; msg.textContent = errText(e); };
          if (state.source === 'live') { U.api.applyYaml(ta.value).then(done).catch(fail); return; }
          try { const doc = parseYaml(ta.value); if (!doc || !Array.isArray(doc.rules)) throw new Error('400 · 최상위 rules: 목록이 필요함'); const rs = doc.rules.map((r) => validateRule(r)); const ids = new Set(); for (const r of rs) { if (ids.has(r.id)) throw new Error(`400 · 중복 id: ${r.id}`); ids.add(r.id); } state.rules = rs; done(rs); }
          catch (e) { fail(e); }
        } });
        return h('div', { class: 'col' }, h('div', { class: 'grow pad' }, ta), h('div', { class: 'foot' }, msg, apply));
      }
      function ruleEditor(rule, isNew) {
        let mode = 'form', draft = toDraft(rule), yamlText = '', error = '', saved = false;
        const root = h('div', { class: 'col' });
        function toDraft(r) { const d = { id: r.id, description: r.description || '', kind: r.kind, action: r.action, dryRun: !!r.dryRun, disabled: !!r.disabled, lists: {} }; for (const f of LIST_FIELDS) d.lists[f] = (r[f] || []).join('\n'); return d; }
        function toRule(d) {
          const r = { id: d.id.trim(), kind: d.kind, action: d.action };
          if (d.description.trim()) r.description = d.description.trim(); if (d.dryRun) r.dryRun = true; if (d.disabled) r.disabled = true;
          for (const f of ['containers', ...FIELDS_BY_KIND[d.kind].map((x) => x[0])]) {
            const items = d.lists[f].split(/[\n,]/).map((x) => x.trim()).filter(Boolean); if (!items.length) continue;
            if (PORT_FIELDS.includes(f)) { const ports = items.map(Number); const bad = items.find((_, i) => !Number.isInteger(ports[i]) || ports[i] < 1 || ports[i] > 65535); if (bad) throw new Error(`포트 값 오류: ${bad}`); r[f] = ports; } else r[f] = items;
          }
          return r;
        }
        const current = () => { if (mode === 'form') return validateRule(toRule(draft)); const p = parseYaml(yamlText); if (!isNew && p && p.id !== rule.id) throw new Error('기존 정책의 id는 바꿀 수 없음'); return validateRule(p); };
        function render() {
          const effective = draft.action === 'kill' && draft.dryRun ? 'kill → 알림만 (dry-run)' : draft.action;
          const field = (label, hint, ctl) => h('label', { class: 'field' }, h('span', null, h('b', null, label), hint ? h('small', { class: 'muted' }, ' ' + hint) : null), ctl);
          const upd = (patch) => { Object.assign(draft, patch); saved = false; render(); };
          const body = mode === 'yaml'
            ? h('textarea', { class: 'ctl mono yaml grow', spellcheck: 'false', 'aria-label': '정책 YAML', value: yamlText, oninput: (e) => { yamlText = e.target.value; saved = false; } }, yamlText)
            : h('div', { class: 'form' },
              field('id', '소문자·숫자·하이픈', h('input', { class: 'ctl', value: draft.id, disabled: !isNew, oninput: (e) => { draft.id = e.target.value; saved = false; } })),
              field('설명', null, h('input', { class: 'ctl', value: draft.description, oninput: (e) => { draft.description = e.target.value; saved = false; } })),
              h('div', { class: 'two' }, field('kind', null, U.select(KINDS.map((k) => [k, k]), draft.kind, (v) => upd({ kind: v }), { class: 'ctl' })), field('action', null, U.select([['alert', 'alert — 알림'], ['kill', 'kill — 컨테이너 강제 종료']], draft.action, (v) => upd({ action: v }), { class: 'ctl' }))),
              FIELDS_BY_KIND[draft.kind].map(([f, label, hint]) => field(label, hint, h('textarea', { class: 'ctl mono list', placeholder: '한 줄에 하나', value: draft.lists[f], oninput: (e) => { draft.lists[f] = e.target.value; saved = false; } }, draft.lists[f]))),
              field('적용 컨테이너', '이름 또는 이미지 glob, 비우면 전체 (예: pkg-*)', h('textarea', { class: 'ctl mono list short', placeholder: '전체', value: draft.lists.containers, oninput: (e) => { draft.lists.containers = e.target.value; saved = false; } }, draft.lists.containers)),
              h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: draft.disabled, onchange: (e) => { draft.disabled = e.target.checked; saved = false; } }), ' 비활성화 (평가하지 않음)'));
          const seg = h('div', { class: 'seg', role: 'group' }, ['form', 'yaml'].map((m) => h('button', { type: 'button', class: `seg-btn dark ${mode === m ? 'on' : ''}`, onclick: () => switchMode(m) }, m === 'form' ? '폼' : 'YAML')));
          const saveBtn = h('button', { type: 'button', class: 'btn btn-primary', disabled: !canWrite(), title: canWrite() ? null : '관리자 토큰을 입력하세요', onclick: save }, '저장 후 적용 ▶');
          replace(root, 
            h('div', { class: 'editor-head' }, seg, h('span', { class: 'small muted' }, '적용 결과: ', h('b', { class: draft.action === 'kill' && !draft.dryRun ? 'tone-danger' : 'tone-warn' }, effective))),
            h('div', { class: 'grow scroll pad' }, body),
            h('div', { class: 'foot' },
              mode === 'form' ? h('label', { class: 'row-inline', title: 'kill 정책을 알림만 보내도록 강제 (오탐 시 컨테이너 보호)' }, U.switchEl(draft.dryRun, (on) => upd({ dryRun: on })), ' dry-run') : null,
              error ? h('span', { class: 'grow small tone-danger', title: error }, error) : saved ? h('span', { class: 'grow small tone-ok' }, '저장 후 엔진에 적용됨') : h('span', { class: 'grow' }),
              !isNew ? U.confirmButton({ label: '🗑 삭제', confirmLabel: '눌러서 삭제 확정', class: 'btn btn-danger-ghost', disabled: !canWrite(), onConfirm: () => { U.api.deleteRule(rule.id).then(() => U.api.listRules()).then(() => { U.toast(`정책 ${rule.id} 삭제됨`, { tone: 'warn' }); select(''); }).catch((e) => { error = errText(e); render(); }); } }) : null,
              saveBtn));
        }
        function switchMode(next) {
          if (next === mode) return; error = '';
          try { if (next === 'yaml') yamlText = ruleToYaml(toRule(draft)); else { const p = parseYaml(yamlText); validateRule(p); if (!isNew && p.id !== rule.id) throw new Error('기존 정책의 id는 바꿀 수 없음 — 새 정책으로 만드세요'); draft = toDraft(p); } mode = next; }
          catch (e) { error = e.message; }
          render();
        }
        function save() {
          error = '';
          let r;
          try { r = current(); if (isNew && state.source === 'sim' && state.rules.some((x) => x.id === r.id)) throw new Error(`409 · 이미 있는 id: ${r.id}`); }
          catch (e) { error = e.message; render(); return; }
          U.api.saveRule(r).then((savedRule) => U.api.listRules().then(() => savedRule || r)).then((sr) => { draft = toDraft(sr); saved = true; renderList(); U.toast(`정책 ${sr.id} 저장 후 엔진 리로드`, { tone: 'ok' }); if (isNew) select(sr.id); else render(); })
            .catch((e) => { error = errText(e); render(); });
        }
        render();
        return root;
      }
      const load = () => U.api.listRules().then(() => { renderList(); renderEditor(); }).catch((e) => { replace(list, h('p', { class: 'pad tone-danger small' }, `불러오기 실패: ${errText(e)}`)); });
      renderList(); renderEditor(); load();
      return { update() { tokenRow.hidden = !state.info.authRequired; } }; // 실제 모드에서 /api/info 가 늦게 와도 반영
    },
  };

  // ── 감사 로그 ────────────────────────────────────────────
  U.screens['/audit'] = {
    title: '감사 로그',
    mount(page) {
      const PAGE = 100;
      const f = { kind: '', action: '', rule: '', container: '', since: '', until: '' };
      let rows = [], hasMore = false, loading = false, timer, seq = 0;
      const tbody = h('tbody');
      const more = h('div', { class: 'more', hidden: true }, h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => fetchPage(rows.length ? rows[rows.length - 1].id : undefined) }, '더 보기'));
      const table = h('table', { class: 'table' }, h('thead', null, h('tr', null, ['#', '시각', '컨테이너', 'Kind', '상세', '규칙', '판정', '사유'].map((t) => h('th', null, t)))), tbody);
      const emptyEl = empty('조건에 맞는 기록 없음');
      const errEl = h('p', { class: 'pad tone-danger small', hidden: true });
      const wrap = h('div', { class: 'grow scroll' }, errEl, table, emptyEl, more);
      const toIso = (v) => (v ? new Date(v).toISOString() : '');
      function fetchPage(before) {
        const my = ++seq; loading = true; refresh.classList.add('spin');
        U.api.audit({ kind: f.kind, action: f.action, rule: f.rule, container: f.container, since: toIso(f.since), until: toIso(f.until), limit: PAGE, before })
          .then((pageRows) => { if (my !== seq) return; rows = before ? rows.concat(pageRows) : pageRows; hasMore = pageRows.length === PAGE; errEl.hidden = true; draw(); })
          .catch((e) => { if (my !== seq) return; errEl.hidden = false; errEl.textContent = `조회 실패: ${e.message}`; })
          .finally(() => { loading = false; refresh.classList.remove('spin'); });
      }
      const setF = (k) => (v) => { f[k] = v; clearTimeout(timer); timer = setTimeout(() => fetchPage(), 300); }; // 필터 변경 300ms 뒤 첫 페이지부터
      const refresh = h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => fetchPage() }, '⟳ 새로고침');
      page.append(panel({ title: '감사 로그 · 위반 판정 이력', class: 'grow', actions: refresh, body: h('div', { class: 'col' },
        h('div', { class: 'filters' },
          U.select([['', 'Kind 전체'], ...KINDS.map((k) => [k, k])], '', setF('kind')),
          U.select([['', '대응 전체'], ['alert', 'alert'], ['kill', 'kill']], '', setF('action')),
          h('input', { class: 'ctl w-40', placeholder: '규칙 id', oninput: (e) => setF('rule')(e.target.value) }),
          h('input', { class: 'ctl w-40', placeholder: '컨테이너', oninput: (e) => setF('container')(e.target.value) }),
          h('label', null, '기간 ', h('input', { type: 'datetime-local', class: 'ctl', 'aria-label': '시작', onchange: (e) => setF('since')(e.target.value) }), ' ~ ', h('input', { type: 'datetime-local', class: 'ctl', 'aria-label': '끝', onchange: (e) => setF('until')(e.target.value) }))),
        wrap) }));
      function draw() {
        emptyEl.hidden = rows.length > 0 || loading; table.hidden = rows.length === 0; more.hidden = !hasMore;
        replace(tbody, rows.map((a) => h('tr', null,
          h('td', { class: 'num muted right' }, a.id),
          h('td', { class: 'num mono nowrap' }, fmt.dateTime(a.event.timestamp)),
          h('td', null, h('div', { class: 'strong' }, a.event.containerName), h('div', { class: 'mono muted small', title: a.event.imageName }, `${fmt.shortId(a.event.containerId)} · ${a.event.imageName}`)),
          h('td', null, kindBadge(a.event.kind)),
          h('td', { class: 'mono small trunc', title: detailOf(a.event) }, detailOf(a.event)),
          h('td', { class: 'mono small nowrap' }, a.ruleId),
          h('td', null, verdictBadge(a)),
          h('td', { class: 'small' }, a.reason, a.enforceError ? h('div', { class: 'tone-danger' }, `격리 오류: ${a.enforceError}`) : null))));
      }
      fetchPage();
      return {};
    },
  };
})();
