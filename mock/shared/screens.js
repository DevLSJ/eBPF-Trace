// SupplyGuard 목업 — 화면 7개(대시보드 · 설치 검사 · 공급망 검사 · 이벤트 · 토폴로지 · 정책 · 감사 로그; 설정은 settings.js · 보고서는 report.js). UI.screens[path] = { title, mount(page, query) → { update, unmount } }
// 탭 하나 = 질문 하나 [10/15 목표]: 대시보드(지금 처리할 일?) · 설치 검사(악성인가?) · 이벤트(지금 무엇이 걸리나?) · 토폴로지(어디까지 손댔나?) · 정책(적용하면 무엇이 달라지나?) · 감사 로그(어떻게 닫혔나?)
(function () {
  'use strict';
  const U = window.UI, M = window.MOCK;
  const { h, replace, fmt, kindBadge, verdictBadge, panel, empty, levelOf, detailOf, KINDS, state } = U;
  const LEVEL_TONE = (level) => (level === 'killed' ? 'danger' : level === 'held' ? 'danger' : level === 'alert' ? 'warn' : 'default');

  const pkgLabel = (s) => s.packages.join(' ');
  const durText = (s) => { if (s.refusedBy) return '—'; const end = s.finishedAt || s.containerExitedAt; if (!end) return '—'; const sec = Math.max(0, Math.round((Date.parse(end) - Date.parse(s.startedAt)) / 1000)); return sec < 60 ? `${sec}초` : `${Math.floor(sec / 60)}분 ${sec % 60}초`; };
  const DAY = 86400e3;
  // 건 → 사람이 읽는 대상 이름: label(설치 = 입력 그대로 「pip ./reqeusts」, 런타임 = 컨테이너). 정규화 키(pip:reqeusts)는 차단 목록 · 제안 변경 내용에만 [10/15 3차]
  const caseTarget = (c, installs) => { if (c.label) return c.label; if (c.source === 'scan') return c.package; if (c.source !== 'install') return c.container; const s = (installs || []).find((x) => x.id === c.installId); return s ? `${s.manager} ${pkgLabel(s)}` : c.package; };
  const caseLink = (c) => U.caseLink(c); // 출처별 링크 · 표기는 app.js 한 곳(U.caseLink · U.CASE_SOURCE) [10/20 J]
  const sourceChip = (src) => h('span', { class: `src-chip src-${src}` }, U.CASE_SOURCE[src] || src);
  // 데이터가 바뀔 때만 다시 그린다 — 열린 시트의 스크롤 · 포커스를 지킨다
  const sigOf = (x) => JSON.stringify(x);
  // 목록 공통 [10/20 D · 10/21b]: 필터 칩의 ✕ · 「모두 해제」는 남은 필터를 상태로 넘겨 화면을 다시 그린다 — 입력 칸까지 같아진다(필터는 주소에 없다)
  const clearFilter = (cur, keys) => U.go(location.hash, Object.fromEntries(Object.entries(cur).filter(([k]) => !keys.includes(k))));
  // 이 행동에서 정책 시작 [10/16]: 막는 새 정책 · 걸린 정책에 예외
  function policyStarts(v) {
    const blk = U.policyEasy.blockLink(v.event), alw = v.ruleId ? U.policyEasy.allowLink(v.ruleId, v.event) : null;
    return blk || alw ? h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('b', null, '이 행동으로 정책 만들기')),
      h('div', { class: 'row-actions' },
        blk ? h('a', { ...U.to(blk), class: 'btn btn-ghost btn-xs', 'data-action': 'block-this' }, '이 행동 막기 →') : null,
        alw ? h('a', { ...U.to(alw), class: 'btn btn-ghost btn-xs', 'data-action': 'allow-this' }, `이 행동 허용(${v.ruleId} 에 예외) →`) : null)) : null;
  }

  // ── 대시보드 — 「지금 처리할 일이 있나?」 + 「지금까지 무엇을 수집 · 탐지했나?」 [10/15 목표 · 10/16 종합] ──
  // 위: 판정 대기(설치 · 런타임 함께, 걸린 규칙 한 줄). 아래: eBPF 수집 종합 — 저장된 기록(GET /api/summary?range=) 기반이라 재시작해도 그대로.
  // 최근 위반 피드 · 최근 설치 검사 목록은 이벤트 · 설치 검사 탭에만 있다
  const RANGES = [['1h', '1시간'], ['24h', '24시간'], ['7d', '7일']];
  const KIND_KO = { exec: '실행', open: '파일', connect: '통신', dns: '조회' }; // 짧은 라벨 [10/30 — dns 는 「조회」, 긴 이름 「도메인 조회」]
  // 쌓은 막대: keys = [[키, 이름, 클래스]] — 칸마다 <g data-bucket>, 조각마다 rect[data-kind]
  function stackedBars({ name, keys, label }) {
    const root = h('div', { class: 'chart stacked', 'data-chart': name });
    const legend = h('div', { class: 'chart-legend' }, keys.map(([, ko, cls]) => h('span', null, h('i', { class: `sw ${cls}` }), ko)));
    const box = h('div', { class: 'chart-box' });
    root.append(legend, box);
    let data = [], step = 3600;
    const tick = (t) => (step >= 21600 ? `${new Date(t).getMonth() + 1}/${new Date(t).getDate()}` : fmt.time(t).slice(0, 5));
    function draw() {
      box.replaceChildren();
      const W = box.clientWidth || 480, H = box.clientHeight || 140, m = { t: 8, r: 6, b: 20, l: 40 };
      const iw = W - m.l - m.r, ih = H - m.t - m.b;
      const tot = (d) => keys.reduce((n, [k]) => n + (d[k] || 0), 0);
      const max = Math.max(4, ...data.map(tot));
      const y = (v) => m.t + ih - (v / max) * ih;
      const slot = iw / Math.max(1, data.length), bw = Math.max(2, slot * 0.7);
      const svg = U.s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img', 'aria-label': label });
      for (const v of [0, max]) svg.append(U.s('line', { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: v ? 'grid' : 'axis' }), U.s('text', { x: m.l - 6, y: y(v) + 4, 'text-anchor': 'end', class: 'tick' }, fmt.num(v)));
      const every = Math.ceil(data.length / 6);
      data.forEach((d, i) => {
        const x = m.l + i * slot + (slot - bw) / 2;
        const g = U.s('g', { 'data-bucket': d.t }, U.s('title', null, `${tick(d.t)} · ${keys.map(([k, ko]) => `${ko} ${fmt.num(d[k] || 0)}`).join(' · ')}`));
        let acc = 0;
        for (const [k, , cls] of keys) { const v = d[k] || 0; if (!v) continue; const y1 = y(acc + v), y0 = y(acc); g.append(U.s('rect', { x, y: y1, width: bw, height: Math.max(1, y0 - y1), class: `seg ${cls}`, 'data-kind': k })); acc += v; }
        if (!acc) g.append(U.s('rect', { x, y: m.t + ih - 1, width: bw, height: 1, class: 'seg zero' }));
        svg.append(g);
        if (i % every === 0) svg.append(U.s('text', { x: x + bw / 2, y: H - 5, 'text-anchor': 'middle', class: 'tick' }, tick(d.t)));
      });
      box.append(svg);
    }
    new ResizeObserver(draw).observe(box);
    root.set = (d, st) => { data = d || []; step = st || 3600; draw(); };
    return root;
  }
  U.screens['/'] = {
    title: '대시보드',
    mount(page, query) {
      const count = h('b', { class: 'num', 'data-pending-count': '' }, '0');
      const list = h('div', { class: 'grid-scroll' });
      const drafts = h('div', { class: 'pending-foot', hidden: true });
      let range = RANGES.some(([r]) => r === query.get('range')) ? query.get('range') : '24h';
      const chips = h('div', { class: 'chips', role: 'group', 'aria-label': '기간' });
      const eps = h('span', { class: 'small muted num' });
      const kpis = h('div', { class: 'ov-kpis' });
      const cCollected = stackedBars({ name: 'collected', label: '수집량 추이', keys: [['exec', '실행', 'k-exec'], ['open', '파일', 'k-open'], ['connect', '통신', 'k-connect'], ['dns', '조회', 'k-dns']] }); // 조회(dns) #fb923c [10/30]
      const cViol = stackedBars({ name: 'violations', label: '위반 추이', keys: [['killed', '격리', 'k-killed'], ['alert', '경고', 'k-alert']] });
      const topRules = h('div', { 'data-top': 'rules' }), topCtrs = h('div', { 'data-top': 'containers' }), results = h('div', { 'data-results': '' });
      const card = (title, body, cls) => h('section', { class: `ov-card ${cls || ''}` }, h('h3', null, title), body);
      // 상태 신호등(머리 한 줄) [10/30 계약 §5] · 시연 카드(맨 위, 관리자 + /api/info.demo) [10/30 계약 §4] — shared/demo.js
      const signals = U.signals ? U.signals() : null;
      const demo = U.demoPanel ? U.demoPanel() : null;
      page.append(h('div', { class: 'dash' }, signals, demo,
        h('section', { class: 'panel pending-panel', 'data-section': 'pending' },
          h('header', { class: 'panel-head' }, h('h2', null, '판정 대기 ', count), h('span', { class: 'small muted' }, '격리 · 경고된 설치와 격리된 런타임 컨테이너')),
          h('div', { class: 'panel-body' }, list), drafts),
        h('section', { class: 'panel overview', 'data-section': 'overview' },
          h('header', { class: 'panel-head' }, h('h2', null, 'eBPF 수집 종합'), h('span', { class: 'row-inline small muted' }, h('i', { class: 'live-dot', 'aria-hidden': true }), '감시 중 ', eps), h('span', { class: 'push-right' }), chips),
          h('div', { class: 'ov-body' }, kpis,
            h('div', { class: 'ov-charts' }, card('수집량 추이 — 종류별', cCollected), card('위반 추이', cViol)),
            h('div', { class: 'ov-bottom' }, card('많이 걸린 정책', topRules), card('위반이 많은 컨테이너 · 패키지', topCtrs), card('설치 검사 · 판정', results))))));
      const drawChips = () => replace(chips, RANGES.map(([r, ko]) => h('button', { type: 'button', class: `chip-btn ${range === r ? 'on' : ''}`, 'data-range': r, 'aria-pressed': String(range === r), onclick: () => { range = r; drawChips(); sig = ''; load(); } }, ko)));
      drawChips();
      let sig = '', ovSig = '';
      function load() {
        const st = state.stats || {};
        eps.textContent = `· 초당 ${fmt.num(Math.round((st.eventsPerSec || 0) * 10) / 10)} evt`;
        Promise.all([U.api.cases().catch((e) => e), U.api.installs().catch((e) => e), U.api.proposals({ state: 'draft' }).catch(() => []), U.api.summary(range).catch((e) => e)]).then(([cases, installs, props, sum]) => {
          const next = sigOf([cases instanceof Error ? cases.message : cases, installs instanceof Error ? installs.message : installs.map((s) => [s.id, s.status]), props.length]);
          if (next !== sig) { sig = next; draw(cases, installs, props); }
          const ns = sigOf(sum instanceof Error ? sum.message : [sum.collected, sum.violations, sum.topRules, sum.installs, sum.decisions, sum.blocklist, sum.series.length, sum.isolation]);
          if (ns !== ovSig) { ovSig = ns; drawOverview(sum); }
        });
      }
      function draw(cases, installs, props) {
        const casesErr = cases instanceof Error ? cases : null, insErr = installs instanceof Error ? installs : null;
        const open = casesErr ? [] : cases.filter((c) => c.state === 'open');
        count.textContent = casesErr ? '—' : fmt.num(open.length);
        replace(list, casesErr ? empty(casesErr.unsupported ? casesErr.message : `불러오기 실패: ${casesErr.message}`)
          : !open.length ? h('div', { class: 'empty col-center all-clear' }, h('b', null, '✓ 처리할 일 없음'), h('span', { class: 'small muted' }, '새 격리 · 경고가 생기면 여기에 판정 대기로 올라옵니다'))
          : h('ul', { class: 'pending-list' }, open.map((c) => h('li', { class: 'pending-row' }, h('a', { ...U.to(caseLink(c)), class: 'needs-action', 'data-case': c.id, 'data-source': c.source, 'aria-label': `${caseTarget(c, insErr ? [] : installs)} 판정하기` },
            sourceChip(c.source),
            h('span', { class: 'pend-what' }, h('span', { class: 'mono trunc-cell strong', title: caseTarget(c, insErr ? [] : installs) }, caseTarget(c, insErr ? [] : installs)),
              h('span', { class: 'small muted trunc-cell', 'data-rules': '' }, c.ruleIds.join(' · '))),
            U.verdictBadge(U.fakeVerdict(c.level)), h('span', { class: 'num muted small' }, `위반 ${c.violations}`), h('span', { class: 'num muted small' }, fmt.time(c.openedAt)), h('span', { class: 'chev', 'aria-hidden': true }, '›')),
            rowMenu(c)))));
        drafts.hidden = !props.length;
        replace(drafts, props.length ? h('a', { href: '#/policies', class: 'link small' }, `판정했지만 아직 적용하지 않은 제안 ${props.length}건 → 정책에서 미리보기 · 적용`) : null);
      }
      // 행 메뉴 「보고서」 [10/30 계약 §5 — 진입 3곳 중 하나] — ⋯ 버튼 → 작은 메뉴(건 보고서 #/report?case=)
      function rowMenu(c) {
        const menu = h('div', { class: 'menu row-menu', role: 'menu', hidden: true }, h('a', { href: `#/report?case=${encodeURIComponent(c.id)}`, role: 'menuitem', class: 'menu-item', 'data-menu': 'report' }, '▤ 보고서'));
        const btn = h('button', { type: 'button', class: 'btn btn-ghost btn-xs row-menu-btn', 'data-action': 'row-menu', 'aria-haspopup': 'menu', 'aria-expanded': 'false', 'aria-label': `${c.id} 메뉴`, onclick: (e) => { e.stopPropagation(); const open = menu.hidden; for (const m of document.querySelectorAll('.row-menu')) m.hidden = true; menu.hidden = !open; btn.setAttribute('aria-expanded', String(open)); if (open) menu.querySelector('a').focus(); } }, '⋯');
        document.addEventListener('click', (e) => { if (!menu.hidden && !menu.contains(e.target) && e.target !== btn) { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); } });
        menu.addEventListener('keydown', (e) => { if (e.key === 'Escape') { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); btn.focus(); } });
        return h('span', { class: 'menu-anchor' }, btn, menu);
      }
      function drawOverview(s) {
        if (s instanceof Error) { replace(kpis, empty(s.unsupported ? '백엔드 미지원 — 종합 API(GET /api/summary)가 아직 백엔드에 없습니다' : `불러오기 실패: ${s.message}`)); return; }
        const k = s.collected.byKind;
        const iso = s.isolation || { count: 0 }; // 격리 지연 [10/30 계약 §3] — count 0 이면 「—」
        const prev = Object.fromEntries([...kpis.querySelectorAll('[data-kpi] [data-value][data-countup]')].map((e) => [e.closest('[data-kpi]').dataset.kpi, Number(e.dataset.countup)]));
        const tile = (key, label, value, sub, link, tone) => { const b = h('b', { class: `num tone-${tone || 'default'}`, 'data-value': '' }, fmt.num(value)); if (key in prev) { b.dataset.countup = String(prev[key]); U.countUp(b, value); } else b.dataset.countup = String(value); // 숫자 변화 카운트업 600ms [10/30 모션]
          return h('a', { ...U.to(link), class: 'ov-kpi', 'data-kpi': key }, h('span', { class: 'small muted' }, label), b, h('span', { class: 'small muted' }, sub)); };
        replace(kpis,
          tile('collected', '수집한 이벤트', s.collected.total, `실행 ${fmt.num(k.exec)} · 파일 ${fmt.num(k.open)} · 통신 ${fmt.num(k.connect)} · 조회 ${fmt.num(k.dns || 0)}`, { href: '#/events', state: { normal: true } }),
          tile('violations', '위반', s.violations.total, `격리 ${fmt.num(s.violations.killed + s.violations.held)} · 경고 ${fmt.num(s.violations.alert)}`, '#/audit', s.violations.total ? 'danger' : 'default'),
          tile('isolated', '격리한 컨테이너', s.isolatedContainers, '설치 검사 포함', { href: '#/audit', state: { action: 'kill' } }, s.isolatedContainers ? 'danger' : 'default'),
          tile('installs', '설치 검사', s.installs.total, `통과 ${s.installs.passed} · 격리 ${s.installs.isolated} · 거부 ${s.installs.refused}`, { href: '#/installs', state: { status: 'all' } }),
          tile('decided', '판정 완료', s.decisions.malicious + s.decisions.falsePositive, `악성 ${s.decisions.malicious} · 오탐 ${s.decisions.falsePositive} · 대기 ${s.decisions.pending}`, '#/audit?view=changes'),
          h('a', { ...U.to({ href: '#/audit', state: { action: 'kill' } }), class: 'ov-kpi', 'data-kpi': 'isolation', 'data-count': iso.count }, h('span', { class: 'small muted' }, '격리 지연 중앙값'),
            h('b', { class: `num tone-${iso.count ? 'danger' : 'default'}`, 'data-value': '' }, iso.count ? `${fmt.num(iso.medianMs)} ms` : '—'),
            h('span', { class: 'small muted' }, iso.count ? `p95 ${fmt.num(iso.p95Ms)} ms · 최대 ${fmt.num(iso.maxMs)} ms · 격리 ${fmt.num(iso.count)}건` : '이 기간에 격리 없음 (탐지→kill)')));
        cCollected.set(s.series, s.bucketSec);
        cViol.set(s.series, s.bucketSec);
        const topList = (rows, key, href) => (rows.length ? h('ol', { class: 'top-list' }, rows.slice(0, 5).map((r) => { const max = rows[0].count;
          return h('li', { 'data-row': r[key], 'data-count': r.count }, h('a', { ...U.to(href(r[key])), class: 'trunc-cell mono', title: r[key] }, r[key]),
            h('span', { class: 'top-bar' }, h('i', { class: `lv-${r.level}`, style: `width:${Math.max(4, (r.count / max) * 100)}%` })), h('b', { class: 'num' }, fmt.num(r.count))); }))
          : h('p', { class: 'small muted' }, '이 기간에 위반 없음'));
        replace(topRules, topList(s.topRules, 'ruleId', (id) => `#/policies?id=${encodeURIComponent(id)}`));
        replace(topCtrs, topList(s.topContainers, 'container', (c) => ({ href: '#/audit', state: { container: c } })));
        const I = s.installs, D = s.decisions, B = s.blocklist;
        const row = (label, parts) => h('div', { class: 'res-row' }, h('span', { class: 'small muted' }, label), h('span', { class: 'res-parts' }, parts.map(([ko, n, cls]) => h('span', { class: `res-chip ${cls || ''}` }, ko, ' ', h('b', { class: 'num' }, n)))));
        replace(results,
          row('설치 검사', [['통과', I.passed, 'ok'], ['격리', I.isolated, 'danger'], ['경고', I.warned, 'warn'], ['설치 전 거부', I.refused, 'dark'], ['실패 · 미확인', I.failed]]),
          row('판정', [['악성', D.malicious, 'danger'], ['오탐', D.falsePositive, 'info'], ['대기', D.pending, 'warn']]),
          h('div', { class: 'res-row' }, h('span', { class: 'small muted' }, '차단 목록'), h('a', { href: '#/policies?id=__blocklist__', class: 'res-parts link' }, h('b', { class: 'num', 'data-blocklist-total': '' }, fmt.num(B.packages + B.images + B.hosts)), ` (패키지 ${B.packages} · 이미지 ${B.images} · 도메인 ${B.hosts})`)));
      }
      load();
      return { update: load };
    },
  };

  // ── 설치 검사 — 「이 패키지는 무엇을 하려 했고, 악성인가?」 [10/15 목표] ──
  // 기본 필터 「판정 대기」(진행 중 세션도 함께 — 결과가 나오는 순간을 놓치지 않게). 상세 시트 = 판정 버튼 · 공격 체인 · 정적 분석 비교 · 활동 요약
  const STATUS_CHIPS = [['pending', '판정 대기'], ['all', '전체'], ['isolated', '격리'], ['warned', '경고'], ['refused', '설치 전 거부'], ['passed', '통과'], ['failed', '설치 실패'], ['unknown', '결과 미확인'], ['running', '진행 중']];
  const MANAGERS = [['', '전체'], ['pip', 'pip'], ['npm', 'npm'], ['cargo', 'cargo']];
  const KIND_NAME = { exec: '실행', open: '파일', connect: '통신', dns: '조회' }; // 활동 요약 타일 [10/30 dns 「조회」]
  const CMD_EXAMPLE = 'sg-install pip <패키지>';
  function copyCommand(text) {
    const done = () => U.toast(`명령을 복사했습니다 — ${text}`, { tone: 'ok', key: 'copy', replace: true });
    try { navigator.clipboard.writeText(text).then(done, done); } catch { done(); }
  }
  // 정적 분석 비교 — 같은 패키지를 OSV(알려진 취약점 DB)에 물어본 결과와 커널 관찰 결과를 나란히 (M1)
  function osvCompare(s) {
    const q = U.osvQuery(s.manager, s.packages[0] || '');
    const val = h('div', { class: 'cmp-val muted' }, '조회 중…');
    const sub = h('div', { class: 'small muted' }, `${q.ecosystem} · ${q.name} · 버전 무관 · 출처 osv.dev`);
    const verdictLine = h('p', { class: 'small cmp-note', hidden: true });
    const nViol = s.violations.reduce((n, v) => n + (v.count || 1), 0);
    const box = h('section', { class: 'sheet-section', 'data-part': 'osv' }, h('h3', null, '정적 분석 비교'),
      h('div', { class: 'cmp' },
        h('div', { class: 'cmp-cell' }, h('div', { class: 'small strong' }, '정적 분석 (OSV)'), val, sub),
        h('div', { class: 'cmp-cell' }, h('div', { class: 'small strong' }, '커널 관찰 (SupplyGuard)'), h('div', { class: 'cmp-val' }, U.statusBadge(s.status), h('span', { class: `num ${nViol ? 'tone-danger' : 'muted'}` }, ` 위반 ${nViol}건`)), h('div', { class: 'small muted' }, '설치 중 실제로 한 행동'))),
      verdictLine);
    U.api.osv(q).then((r) => {
      if (r.error) { replace(val, h('span', { class: 'tone-warn' }, '조회 실패')); sub.textContent = `${q.ecosystem} · ${q.name} · ${r.error} — 커널 관찰 결과는 그대로입니다`; return; }
      replace(val, h('span', { class: r.vulns ? 'tone-warn' : 'tone-ok', 'data-osv-count': '' }, `알려진 취약점 ${fmt.num(r.vulns)}건`));
      if (!r.vulns && nViol) { verdictLine.hidden = false; verdictLine.textContent = '정적 분석으로는 깨끗하지만, 설치 중 행동을 커널에서 보고 잡았습니다.'; }
    });
    return box;
  }
  U.screens['/installs'] = {
    title: '설치 검사',
    mount(page, query) {
      const f = { status: query.get('status') || 'pending', manager: query.get('manager') || '' };
      if (!STATUS_CHIPS.some(([v]) => v === f.status)) f.status = 'pending';
      let selId = query.get('id') || '', rows = null, cases = new Map(), error = null; // rows === null: 첫 로드 중(스켈레톤)
      U.headerActions(h('button', { type: 'button', class: 'btn btn-ghost btn-xs', title: '감시 컨테이너에서 설치하는 CLI 명령', onclick: () => copyCommand(CMD_EXAMPLE) }, '⧉ 명령 복사'));
      const statusChips = h('div', { class: 'chips', 'data-filter': 'status', role: 'group', 'aria-label': '결과' });
      const mgrChips = h('div', { class: 'chips', 'data-filter': 'manager', role: 'group', 'aria-label': '매니저' });
      const tbody = h('tbody');
      const table = h('table', { class: 'table', 'data-table': 'installs' }, h('thead', null, h('tr', null, ['시작', '매니저', '패키지', '결과', '판정', '위반', '걸린 시간'].map((t) => h('th', null, t)))), tbody);
      const emptySlot = h('div', { class: 'empty-slot' }, U.skeleton(6));
      table.hidden = true;
      const count = h('span', { class: 'num muted' });
      const sheetSlot = h('div', { class: 'sheet-slot' });
      const applied = h('div');
      page.append(h('div', { class: 'split' },
        panel({ title: ['설치 세션 ', count], class: 'grow', body: h('div', { class: 'col' }, h('div', { class: 'filters' }, h('div', { class: 'chip-group' }, '보기', statusChips), h('div', { class: 'chip-group' }, '매니저', mgrChips)), applied, h('div', { class: 'grid-scroll' }, table, emptySlot)) }),
        sheetSlot));
      const STATUS_KO = Object.fromEntries(STATUS_CHIPS);
      const setF = (k, v) => { f[k] = v; draw(); }; // 필터는 화면 상태만 [10/21b]
      const select = (id) => { selId = id; U.setQuery({ id }); draw(); };
      const caseOf = (s) => (s.caseId ? cases.get(s.caseId) : null);
      const isPending = (s) => { const c = caseOf(s); return !!c && c.state === 'open'; };
      let sig = '';
      // quiet: 자동 재시도(30초마다, 스켈레톤 없이) [10/20 결정 4] — 오류 뒤에도 이 호출만은 통과시킨다
      let inflight = 0; // 부르는 중이면 스트림 갱신(update)이 또 부르지 않는다 — 겹친 호출이 서로의 결과를 덮지 않게
      const load = (quiet) => { inflight++; return Promise.all([U.api.installs(), U.api.cases({ source: 'install' })]).then(([r, cs]) => {
        const next = sigOf([r.map((s) => [s.id, s.status, s.caseId, s.violations.length, s.activity.kinds]), cs.map((c) => [c.id, c.state, c.decision])]);
        if (error && !quiet) return; // 오류 뒤에는 「다시 시도」 · 자동 재시도만 다시 부른다
        if (quiet) { error = null; sig = ''; }
        if (rows && next === sig) return; sig = next; rows = r; cases = new Map(cs.map((c) => [c.id, c])); draw();
      }).catch((e) => { if (rows !== null && !error) return; if (error && !quiet) return; rows = []; error = e; draw(); }).finally(() => { inflight--; }); }; // 데이터가 있으면 다시 부르기 실패는 목록 유지 · 표시 없음 [10/21 React 맞춤]
      const retry = () => load(true); // 「다시 시도」 = 조용한 다시 부르기(오류 칸 유지 · 버튼만 돌림) [10/21]
      const matches = (s, st) => (st === 'all' ? true : st === 'pending' ? isPending(s) || s.status === 'running' : s.status === st);
      function chips(el, defs, key) {
        const all = rows || [];
        replace(el, defs.map(([v, label]) => {
          const n = key === 'status' ? (v === 'pending' ? all.filter(isPending).length : all.filter((s) => matches(s, v)).length) : v ? all.filter((s) => s.manager === v).length : all.length;
          if (key === 'status' && !['pending', 'all'].includes(v) && !n && f.status !== v) return null; // 0건인 결과 칩은 숨긴다
          return h('button', { type: 'button', class: `chip-btn ${f[key] === v ? 'on' : ''}`, 'data-value': v, 'aria-pressed': String(f[key] === v), title: v === 'pending' ? '판정 대기 + 진행 중' : null, onclick: () => setF(key, v) }, label, h('span', { class: 'n num' }, n));
        }));
      }
      function installSheet(s) {
        const c = caseOf(s);
        const a = s.activity;
        const hostLevel = (l) => (l === 'normal' ? h('span', { class: 'badge badge-level-normal' }, '허용') : verdictBadge(U.fakeVerdict(l)));
        const refused = s.status === 'refused';
        // 순서: 결과 → 정적 분석 비교 → 공격 체인 → 활동 요약. 판정 칸은 아래 고정 [10/15 3차 — React 모습]
        return U.sheet({ kind: 'install', title: `${s.manager} ${pkgLabel(s)}`, onClose: () => select(''), foot: c ? U.decisionBar(c, { question: '이 패키지는 악성인가?' }) : null, body: [
          h('section', { class: 'sheet-section', 'data-part': 'result' }, h('h3', null, '결과'), h('dl', { class: 'dl tight' },
            h('dt', null, '설치 결과'), h('dd', null, U.statusBadge(s.status)),
            h('dt', null, '명령'), h('dd', { class: 'mono' }, `sg-install ${s.manager} ${pkgLabel(s)}`),
            h('dt', null, '시작'), h('dd', { class: 'num' }, fmt.dateTime(s.startedAt)),
            h('dt', null, '걸린 시간'), h('dd', { class: 'num' }, durText(s), s.exitCode != null ? h('span', { class: 'muted' }, ` · 종료 코드 ${s.exitCode}`) : null),
            h('dt', null, '컨테이너'), h('dd', { class: 'mono', title: s.containerId || '' }, s.container || '— (띄우지 않음)'),
            h('dt', null, '이미지'), h('dd', { class: 'mono' }, s.image || '—')),
            s.isolation && s.isolation.timeline ? U.timelineBar(s.isolation.timeline) : null, // 격리 타임라인 [10/30 계약 §3]
            s.status === 'isolated' || s.status === 'warned' ? h('div', { class: 'row-actions' },
              s.status === 'isolated' && s.container ? evidenceLink(s.container, s.containerId) : null, // 증거 보기 [10/20 결정 6]
              h('a', { href: `#/report?install=${encodeURIComponent(s.id)}`, class: 'btn btn-ghost btn-xs', 'data-action': 'report', title: '건 보고서 1장 — 인쇄 · Markdown 복사' }, '▤ 보고서 →')) : null), // 보고서 [10/30 계약 §5]
          refused ? null : osvCompare(s),
          refused ? h('p', { class: 'note-box refused' }, '차단 목록에 있는 패키지(', h('b', { class: 'mono' }, s.refusedBy.value), ')라서 감시 컨테이너를 띄우지 않고 설치 전에 거부했습니다. ', h('a', { href: '#/policies?id=__blocklist__', class: 'link' }, '차단 목록 →')) : null,
          s.status === 'unknown' ? h('p', { class: 'note-box' }, 'CLI가 끝 보고를 보내지 않았습니다(중단 등). 컨테이너가 끝난 뒤 10분이 지나 결과 미확인으로 둡니다.') : null,
          refused ? null : h('section', { class: 'sheet-section' }, h('h3', null, '공격 체인'),
            s.violations.length ? U.attackChain(U.chainFromVerdicts(s.violations)) : h('p', { class: 'small muted' }, '위반 없음 — 설치 중 정책에 걸린 행위가 없습니다.')),
          refused ? null : h('section', { class: 'sheet-section' }, h('h3', null, '활동 요약'),
            h('div', { class: 'kinds', 'data-activity': 'kinds' }, KINDS.map((k) => h('div', { 'data-kind': k }, h('b', { class: 'num' }, fmt.num(a.kinds[k] || 0)), h('span', { class: 'small muted' }, KIND_NAME[k])))),
            h('h4', null, `접속한 곳 ${a.hosts.length}`),
            h('ul', { class: 'act-list', 'data-activity': 'hosts' }, a.hosts.length ? a.hosts.map((x) => h('li', null, h('span', { class: 'mono', title: `${x.ip}:${x.port}` }, `${x.host || x.ip}:${x.port}`), h('span', { class: 'num muted' }, `×${x.count}`), hostLevel(x.level))) : h('li', { class: 'muted' }, '없음')),
            h('h4', null, `실행한 프로그램 ${a.programs.length}`),
            h('ul', { class: 'act-list', 'data-activity': 'programs' }, a.programs.length ? a.programs.map((x) => h('li', null, h('span', { class: 'mono', title: x.args }, x.args), h('span', { class: 'num muted' }, `×${x.count}`), x.level !== 'normal' ? hostLevel(x.level) : null)) : h('li', { class: 'muted' }, '없음'))),
          h('div', { class: 'row-actions' },
            s.container ? h('a', { ...U.to('#/events', { container: s.container, normal: true }), class: 'btn btn-ghost btn-xs' }, '이벤트에서 보기 →') : null,
            s.violations.length ? h('a', { ...U.to('#/audit', { container: s.container }), class: 'btn btn-ghost btn-xs' }, '감사 로그 →') : null)] });
      }
      function draw() {
        if (rows === null) return;
        chips(statusChips, STATUS_CHIPS, 'status'); chips(mgrChips, MANAGERS, 'manager');
        const list = rows.filter((s) => matches(s, f.status) && (!f.manager || s.manager === f.manager));
        count.textContent = `${fmt.num(list.length)}건`;
        table.hidden = !list.length;
        replace(applied, U.filterChips([f.status !== 'pending' ? { key: 'status', label: `보기: ${STATUS_KO[f.status]}`, clear: () => clearFilter(f, ['status']) } : null,
          f.manager ? { key: 'manager', label: `매니저: ${f.manager}`, clear: () => clearFilter(f, ['manager']) } : null], () => clearFilter(f, ['status', 'manager'])));
        replace(emptySlot,
          error ? U.errorState(error, retry, { what: '설치 세션' })
          : !rows.length ? U.emptyState({ icon: '▣', title: '아직 설치 검사가 없습니다', hint: '패키지를 PC 에 바로 깔지 말고 감시 컨테이너에서 설치해 보세요.', actions: [h('code', { class: 'cmd' }, CMD_EXAMPLE), h('button', { type: 'button', class: 'btn btn-primary btn-xs', onclick: () => copyCommand(CMD_EXAMPLE) }, '⧉ 명령 복사')] })
          : !list.length ? (f.status === 'pending' ? U.emptyState({ icon: '✓', title: '판정할 설치 없음', actions: h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => setF('status', 'all') }, `전체 세션 ${rows.length}건 보기`) })
            : U.emptyState({ icon: '⌕', title: '조건에 맞는 세션 없음', actions: h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => clearFilter(f, ['status', 'manager']) }, '필터 모두 해제') })) : null);
        replace(tbody, list.map((s) => { const c = caseOf(s); return U.rowKeys(h('tr', { 'data-id': s.id, class: `clickable ${isPending(s) ? 'needs-action' : ''} ${s.id === selId ? 'selected' : ''}`, onclick: () => select(s.id) },
          h('td', { class: 'num mono nowrap' }, fmt.dateTime(s.startedAt)),
          h('td', null, h('span', { class: 'mgr', 'data-manager': s.manager }, s.manager)),
          h('td', { class: 'mono trunc', title: pkgLabel(s) }, pkgLabel(s)),
          h('td', null, U.statusBadge(s.status)),
          h('td', null, c ? U.decisionBadge(c.decision) : h('span', { class: 'muted', 'data-decision': 'none' }, '—')),
          h('td', { class: `num ${s.violationCount ? 'tone-danger' : 'muted'}`, 'data-col': 'violations' }, s.violationCount), // 위반 수 = violationCount(같은 위반 묶음의 count 합)
          h('td', { class: 'num muted nowrap' }, durText(s))), () => select(s.id)); }));
        const cur = rows.find((s) => s.id === selId);
        replace(sheetSlot, cur ? installSheet(cur) : null);
      }
      load();
      return { update: () => { if (!error && !inflight) load(); } }; // 오류면 「다시 시도」 · 자동 재시도를 기다린다 [10/20 D · 결정 4] // sim 은 메모리 조회라 싸다 — 바뀐 게 없으면 load 가 그리지 않는다
    },
  };

  // 「증거 보기」 링크 [10/20 결정 6] — 그 컨테이너의 가장 최근 격리 감사 행을 찾아 감사 상세의 증거 탭으로 보낸다(GET /api/audit?container&action=kill).
  //   격리 행이 없으면(dry-run · 격리 대상만) 링크를 그리지 않는다. cache: 다시 그릴 때마다 조회하지 않게(토폴로지는 1초마다 다시 그린다)
  const evHref = new Map();
  function evidenceLink(container, cacheKey) {
    const a = h('a', { class: 'btn btn-ghost btn-xs', 'data-action': 'evidence', title: '격리 직전에 모은 로그 · 파일 변경 · 프로세스 (감사 로그 › 증거 탭)', hidden: true }, '▤ 증거 보기 →');
    const show = (link) => { if (link) { Object.assign(a, { href: link.href, hidden: false }); a.dataset.nav = JSON.stringify(link.state); } else a.remove(); };
    const key = `${container}|${cacheKey || ''}`;
    if (evHref.has(key)) { show(evHref.get(key)); return a; }
    U.api.audit({ container, action: 'kill', limit: 100 }).then((rows) => {
      const r = rows.find((x) => x.event.containerName === container && levelOf(x) === 'killed');
      const link = r ? { href: `#/audit?id=${r.id}&tab=evidence`, state: { container } } : null;
      evHref.set(key, link); show(link);
    }).catch(() => a.remove());
    return a;
  }

  // ── 공급망 검사 — 「설치하기 전에, 이 패키지 · 저장소 · 파일에 위험한 코드나 알려진 취약점이 있나?」 [10/16] ──
  // 실제 오픈소스로 정적 검사: GuardDog(악성 코드 패턴 — 파일:줄) · OSV-Scanner(의존성의 알려진 취약점). 코드를 실행하지 않는다.
  // 결과에서 「설치 검사로 실제 설치해 보기」(eBPF 동적 검사)와 「차단 목록에 올리기」(판정 → 제안)로 잇는다
  const SCAN_VERDICT = { malicious: ['악성 의심', 'danger'], vulnerable: ['취약점 있음', 'warn'], caution: ['주의', 'warn'], clean: ['위협 없음', 'ok'] }; // caution: 11/03 판정 3단계 — 점수는 높은데 런타임 휴리스틱 규칙만
  const RISK_LABEL = { high_risk: '높음', medium_risk: '보통', low_risk: '낮음', no_risks_detected: '없음' };
  const MAX_UPLOAD = 50 * 1024 * 1024;
  const sevTone = (s) => (Number(s) >= 9 ? 'danger' : Number(s) >= 7 ? 'high' : Number(s) >= 4 ? 'warn' : 'low');
  U.screens['/scans'] = {
    title: '공급망 검사',
    mount(page, query) {
      let selId = query.get('id') || '', rows = null, error = null, input = 'package', file = null, detail = null, focusLoc = '';
      let vf = SCAN_VERDICT[query.get('verdict')] ? query.get('verdict') : ''; // 결과 필터 [10/20 D]
      let picked = new Set(); // 패키지 골라 차단 [10/20 G] — 고른 행 키(매니저:이름@버전) [10/21 React 맞춤]
      let blk = null; // 차단 목록(GET /api/blocklist) — 「차단됨」 판단. live 도 같은 경로로
      const formErr = h('p', { class: 'form-error', 'data-form-error': '', hidden: true });
      const fields = h('div', { class: 'scan-fields' });
      const seg = h('div', { class: 'seg', role: 'group', 'aria-label': '입력' });
      const mgr = h('select', { class: 'ctl', 'data-field': 'manager', 'aria-label': '매니저' }, h('option', { value: 'pip' }, 'pip'), h('option', { value: 'npm' }, 'npm'));
      const name = h('input', { class: 'ctl mono', 'data-field': 'name', placeholder: '예: requests', 'aria-label': '패키지 이름' });
      const version = h('input', { class: 'ctl mono', 'data-field': 'version', placeholder: '버전(선택)', 'aria-label': '버전' });
      const url = h('input', { class: 'ctl mono', 'data-field': 'url', placeholder: 'https://github.com/소유자/저장소', 'aria-label': '저장소 주소' });
      const fileIn = h('input', { type: 'file', class: 'ctl', 'aria-label': '파일', accept: '.tar.gz,.tgz,.whl,.zip,.py,.js,.txt,.json' });
      const fileInfo = h('span', { class: 'small muted' }, '패키지 압축(.tar.gz · .whl · .tgz · .zip) · 소스(.py · .js) · 의존성(requirements.txt · package-lock.json), 50MB 까지');
      const showErr = (m) => { formErr.hidden = !m; formErr.textContent = m || ''; };
      fileIn.addEventListener('change', () => { file = fileIn.files[0] || null; showErr(file && file.size > MAX_UPLOAD ? `「${file.name}」 — 파일은 50MB 까지 올릴 수 있습니다(${(file.size / 1048576).toFixed(0)}MB)` : ''); });
      function drawForm() {
        replace(seg, [['package', '패키지 이름'], ['repo', '저장소 주소'], ['file', '파일 올리기']].map(([k, ko]) => h('button', { type: 'button', class: `seg-btn dark ${input === k ? 'on' : ''}`, 'data-input': k, 'aria-pressed': String(input === k), onclick: () => { input = k; showErr(''); drawForm(); } }, ko)));
        replace(fields, input === 'package' ? [mgr, name, version] : input === 'repo' ? [url] : [fileIn, fileInfo]);
      }
      const start = () => {
        showErr('');
        let body;
        if (input === 'package') body = { kind: 'package', manager: mgr.value, name: name.value, version: version.value };
        else if (input === 'repo') body = { kind: 'repo', url: url.value };
        else { if (!file) { showErr('파일을 고르세요'); return; } if (file.size > MAX_UPLOAD) { showErr(`「${file.name}」 — 파일은 50MB 까지 올릴 수 있습니다`); return; } body = { kind: 'file', fileName: file.name, size: file.size, file }; } // file: live 는 multipart 로 보낸다
        U.api.startScan(body).then((r) => { selId = ''; U.setQuery({ id: '' }); load(); U.toast(`검사를 시작했습니다 — ${r.id}`, { tone: 'info', key: 'scan', replace: true }); })
          .catch((e) => showErr(e.message.replace(/^\d+ · /, '')));
      };
      // 조회자는 검사를 시작하지 않는다(POST /api/scans 는 관리자) — 입력 칸 대신 안내 한 줄 [10/20 A]
      const form = U.can() ? h('section', { class: 'panel scan-form', 'data-part': 'scan-form' },
        h('header', { class: 'panel-head' }, h('h2', null, '검사할 대상'), h('span', { class: 'small muted' }, '설치하기 전에 정적 검사 — 코드를 실행하지 않습니다')),
        h('div', { class: 'scan-form-body' }, seg, fields, h('button', { type: 'button', class: 'btn btn-primary', 'aria-label': '검사 시작', onclick: start }, '검사 시작'), formErr))
        : h('section', { class: 'panel scan-form', 'data-part': 'scan-form-viewer' }, h('p', { class: 'small muted pad-sm' }, '검사 시작은 관리자가 합니다 — 아래 검사 기록과 결과는 볼 수 있습니다.'));
      const tbody = h('tbody');
      const table = h('table', { class: 'table', 'data-table': 'scans', hidden: true }, h('thead', null, h('tr', null, ['시작', '대상', '결과', '위험 점수', '위협', '취약점'].map((t) => h('th', null, t)))), tbody);
      const emptySlot = h('div', { class: 'empty-slot' }, U.skeleton(5));
      const sheetSlot = h('div', { class: 'sheet-slot' });
      const vChips = h('div', { class: 'chips', role: 'group', 'aria-label': '결과' });
      const applied = h('div');
      page.append(h('div', { class: 'split' }, h('div', { class: 'col grow scans-left' }, form,
        panel({ title: '검사 기록', class: 'grow', actions: vChips, body: h('div', { class: 'col' }, applied, h('div', { class: 'grid-scroll' }, table, emptySlot)) })), sheetSlot));
      const setVf = (v) => { vf = v; draw(); }; // 필터는 화면 상태만 [10/21b]
      drawForm();
      const select = (id) => { selId = id; focusLoc = ''; picked = new Set(); U.setQuery({ id }); load(); };
      let sig = '';
      let inflight = 0;
      function load(quiet) {
        inflight++;
        U.api.scans().then((r) => {
          if (error && !quiet) return; // 오류 뒤에는 「다시 시도」 · 자동 재시도(quiet)만 다시 부른다 [10/20 결정 4]
          if (quiet) { error = null; sig = ''; }
          rows = r;
          const next = sigOf([r.map((x) => [x.id, x.status]), selId]);
          if (next === sig && (!selId || detail)) return; sig = next;
          if (selId) Promise.all([U.api.scan(selId), U.api.blocklist().catch(() => null)]).then(([d, bl]) => { detail = d; blk = bl; draw(); }).catch(() => { detail = null; draw(); }); else { detail = null; draw(); }
        }).catch((e) => { if (rows !== null && !error) return; if (error && !quiet) return; error = e; rows = []; draw(); }).finally(() => { inflight--; }); // 데이터가 있으면 목록 유지 · 표시 없음 [10/21]
      }
      const retry = () => load(true);
      function draw() {
        if (rows === null) return;
        const list = rows.filter((x) => !vf || x.verdict === vf);
        replace(vChips, [['', '전체'], ...Object.entries(SCAN_VERDICT).map(([k, [ko]]) => [k, ko])].map(([k, ko]) => h('button', { type: 'button', class: `chip-btn ${vf === k ? 'on' : ''}`, 'data-verdict': k, 'aria-pressed': String(vf === k), onclick: () => setVf(k) }, ko)));
        replace(applied, U.filterChips([vf ? { key: 'verdict', label: `결과: ${SCAN_VERDICT[vf][0]}`, clear: () => clearFilter({ verdict: vf }, ['verdict']) } : null], () => clearFilter({ verdict: vf }, ['verdict'])));
        table.hidden = !list.length;
        replace(emptySlot, error ? U.errorState(error, retry, { what: '공급망 검사' })
          : !rows.length ? U.emptyState({ icon: '⌕', title: '아직 검사가 없습니다', hint: U.can() ? '위에서 패키지 이름 · 저장소 주소 · 파일로 시작하세요. 예: pip reqeusts (requests 의 오타 — 타이포스쿼팅 데모)' : '관리자가 검사를 시작하면 여기에 쌓입니다.' })
          : !list.length ? U.emptyState({ icon: '○', title: '조건에 맞는 검사 없음', actions: h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => clearFilter({ verdict: vf }, ['verdict']) }, '필터 해제') }) : null);
        replace(tbody, list.map((x) => { const [vk, tone] = SCAN_VERDICT[x.verdict] || ['검사 중', 'info'];
          return U.rowKeys(h('tr', { 'data-scan': x.id, 'data-status': x.status, class: `clickable ${x.id === selId ? 'selected' : ''} ${x.verdict === 'malicious' ? 'needs-action' : ''}`, onclick: () => select(x.id) },
            h('td', { class: 'num mono nowrap' }, fmt.dateTime(x.startedAt)),
            h('td', { class: 'mono trunc', title: x.target.label }, x.target.label),
            h('td', null, x.status === 'running' ? h('span', { class: 'badge badge-info' }, '검사 중…') : h('span', { class: `badge sv-${tone}` }, vk)),
            h('td', { class: 'num' }, x.risk ? `${x.risk.score.toFixed(1)}` : '—'),
            h('td', { class: `num ${x.threats ? 'tone-danger' : 'muted'}` }, x.status === 'done' ? x.threats : '—'),
            h('td', { class: `num ${x.vulnCount ? 'tone-warn' : 'muted'}` }, x.status === 'done' ? (x.vulnCount ? `${x.vulnCount} (최고 ${x.vulnMax})` : 0) : '—')), () => select(x.id)); }));
        replace(sheetSlot, selId && detail ? scanSheet(detail) : null);
      }
      function codeView(d) {
        const paths = Object.keys(d.files || {});
        if (!paths.length) return h('p', { class: 'small muted' }, d.status !== 'done' ? '검사 중…' : '위협이 나온 파일이 없어 코드를 보관하지 않았습니다(걸린 파일만 30일 보관).');
        let cur = focusLoc ? focusLoc.split(':')[0] : paths[0];
        if (!paths.includes(cur)) cur = paths[0];
        const lines = d.files[cur].split('\n');
        const at = (cat) => new Map(d.findings.filter((f) => f.file === cur && f.category === cat).map((f) => [f.line, f]));
        const thr = at('threat'), cap = at('capability');
        const focusLine = focusLoc && focusLoc.startsWith(cur + ':') ? Number(focusLoc.split(':')[1]) : 0;
        const mark = (text, f) => { if (!f || !f.match || !text.includes(f.match)) return text; const i = text.indexOf(f.match); return [text.slice(0, i), h('mark', null, f.match), text.slice(i + f.match.length)]; };
        const box = h('div', { class: 'code-view', role: 'region', 'aria-label': `${cur} 코드` }, h('pre', null, lines.map((ln, i) => { const n = i + 1, t = thr.get(n), c = cap.get(n);
          return h('div', { class: `code-line ${t ? 'hl-threat' : c ? 'hl-cap' : ''} ${n === focusLine ? 'focus' : ''}`, 'data-line': n, title: t ? `${t.rule} — ${t.message}` : c ? `${c.rule} — ${c.message}` : null },
            h('span', { class: 'ln' }, n), h('code', null, mark(ln || ' ', t || c))); })));
        if (focusLine) setTimeout(() => { const el = box.querySelector(`[data-line="${focusLine}"]`); if (el) el.scrollIntoView({ block: 'center' }); }, 0);
        return [paths.length > 1 ? h('div', { class: 'chips' }, paths.map((p) => h('button', { type: 'button', class: `chip-btn ${p === cur ? 'on' : ''}`, onclick: () => { focusLoc = `${p}:0`; draw(); } }, p))) : h('div', { class: 'small mono muted' }, cur), box];
      }
      // 패키지 골라 차단 [10/20 G · 10/21 React 맞춤 — features/scans/ScanPackages.tsx] — 잠금 파일마다 한 행인 패키지를 (매니저, 이름, 버전)으로 묶어 한 줄, 출처 파일을 나열.
      //   키 = 매니저:이름@버전(생태계 미지원은 생태계:이름@버전). 정렬 취약 수 → 이름 → 버전. 「차단됨」은 매니저:이름 소문자(blockKey — 차단은 버전과 무관)
      // 고르면 「선택한 N개 차단 목록에 올리기」 → 확인 대화상자 → POST /api/scans/{id}/block {packages:[{manager, name, version}]}(그 행의 버전) → 정책 제안
      function packagesView(d) {
        const groups = new Map();
        for (const p of d.packages || []) {
          const k = `${p.manager ? `${p.manager}:${p.name}` : `${p.ecosystem || '?'}:${p.name}`}@${p.version}`;
          const g = groups.get(k) || { key: k, blockKey: `${p.manager}:${String(p.name).toLowerCase()}`, manager: p.manager, name: p.name, version: p.version, ecosystem: p.ecosystem || '', sources: [], direct: false, vulns: 0 };
          if (p.source && !g.sources.includes(p.source)) g.sources.push(p.source); g.direct = g.direct || p.direct; g.vulns = Math.max(g.vulns, p.vulns || 0);
          groups.set(k, g);
        }
        const list = [...groups.values()].sort((a, b) => b.vulns - a.vulns || a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)));
        if (!list.length) return h('section', { class: 'sheet-section', 'data-part': 'packages' }, h('h3', null, '패키지 0'), h('p', { class: 'small muted' }, '잠금 · 의존성 파일을 찾지 못했습니다.'));
        const blocked = new Set(((blk || state.blocklist).packages || []).map((x) => String(x.value).toLowerCase()));
        const canPick = (g) => U.can() && !!g.manager && !blocked.has(g.blockKey);
        const sel = () => list.filter((g) => picked.has(g.key) && canPick(g)); // 선택 수는 고를 수 있는 것만
        const footSlot = h('div', { class: 'pkg-foot' });
        const drawFoot = () => replace(footSlot, !U.can() ? null : sel().length
          ? h('button', { type: 'button', class: 'btn btn-danger btn-xs', 'data-action': 'block-selected', onclick: blockPicked }, `⛔ 선택한 ${sel().length}개 차단 목록에 올리기`)
          : h('span', { class: 'small muted' }, '차단할 패키지를 고르세요 — 취약점이 많은 것부터 위에 있습니다'));
        function blockPicked() {
          const chosen = sel();
          // 같은 패키지(다른 버전)는 하나로 — 차단 목록 값은 매니저:이름이라 버전과 무관
          const effects = [`차단 제안 초안 — 패키지 ${chosen.length}개: ${[...new Set(chosen.map((g) => `${g.manager}:${g.name}`))].join(' · ')} (정책에서 미리보기 후 적용)`,
            '적용하면 다음 sg-install 부터 이 패키지는 설치 전 거부(컨테이너를 띄우지 않음) — 차단은 버전과 무관', `공급망 검사 건을 「악성」으로 판정한 기록이 남습니다 — 처리자 ${U.actor()}`];
          U.confirmDialog({ title: '고른 패키지 차단 목록에 올리기', target: `${d.target.label} · ${d.id}`, effects, okLabel: `${chosen.length}개 올리기`, undo: '정책에서 제안을 「버림」하면 차단 없이 끝납니다. 적용한 뒤에는 차단 목록에서 「해제」' })
            .then((r) => r && U.api.scanBlock(d.id, { packages: chosen.map((g) => ({ manager: g.manager, name: g.name, version: g.version })) }, r.reason)
              .then((x) => { picked = new Set(); U.navigate('/policies', { proposal: x.proposalId }); }))
            .catch((e) => U.toast(`차단 제안 실패: ${e.message}`, { tone: 'danger' }));
        }
        const allBox = U.can() ? h('input', { type: 'checkbox', 'aria-label': '모두 고르기', onchange: (e) => { for (const g of list) if (canPick(g)) { if (e.target.checked) picked.add(g.key); else picked.delete(g.key); } draw(); } }) : null;
        if (allBox) allBox.checked = list.filter(canPick).length > 0 && list.filter(canPick).every((g) => picked.has(g.key));
        const sec = h('section', { class: 'sheet-section', 'data-part': 'packages' },
          h('h3', null, `패키지 ${list.length}`, h('span', { class: 'small muted' }, ' — 잠금 · 의존성 파일에서 읽음, 같은 패키지 · 버전은 한 줄')),
          h('div', { class: 'preview-table' }, h('table', { class: 'table compact' }, h('thead', null, h('tr', null, [allBox ? h('th', null, allBox) : null, h('th', null, '패키지'), h('th', null, '버전'), h('th', null, '취약'), h('th', null, '의존'), h('th', null, '출처 파일')])),
            h('tbody', null, list.map((g) => h('tr', { 'data-pkg': g.key, 'data-sources': g.sources.length, class: picked.has(g.key) ? 'selected' : '' },
              U.can() ? h('td', null, canPick(g) ? h('input', { type: 'checkbox', 'data-pick': '', 'aria-label': `${g.key} 고르기`, checked: picked.has(g.key), onchange: (e) => { if (e.target.checked) picked.add(g.key); else picked.delete(g.key); draw(); } })
                : h('span', { class: 'small muted', title: g.manager ? '이미 차단 목록에 있음' : '차단 목록이 다루지 않는 생태계' }, g.manager ? '차단됨' : '—')) : null,
              h('td', { class: 'mono small' }, g.manager ? `${g.manager}:${g.name}` : h('span', { title: '차단 목록이 다루지 않는 생태계' }, `${g.ecosystem} ${g.name}`)),
              h('td', { class: 'mono small' }, g.version),
              h('td', { class: `num ${g.vulns ? 'tone-warn' : 'muted'}` }, g.vulns),
              h('td', { class: 'small' }, g.direct ? '직접' : '간접'),
              h('td', { class: 'small mono' }, h('ul', { class: 'src-list' }, g.sources.map((s) => h('li', null, s))))))))),
          footSlot);
        drawFoot();
        return sec;
      }
      // 판정 문구(11/02): 패키지 검사는 자기 버전(direct) 취약점과 OSV-Scanner 가 푼 의존성(간접) 취약점을 나눠 말한다
      U.scanVerdictText = (d, threatN) => {
        if (d.status !== 'done') return '검사 중입니다…';
        if (d.verdict === 'malicious') return `설치 단계에서 위험한 행동을 하는 코드가 ${d.installThreats || threatN}곳 있습니다. 설치하지 말고 차단 목록에 올리세요.`;
        if (d.verdict === 'caution') return `설치 단계의 위험한 행동은 없고, 실행 중 동작 규칙(동적 로딩 · 환경 변수 읽기 등)에 ${threatN}곳 걸렸습니다. 정상 라이브러리에도 흔한 패턴이니 코드 보기로 확인하세요.`;
        if (d.verdict === 'vulnerable') {
          const own = d.vulns.filter((v) => v.direct).reduce((n, v) => n + v.count, 0), dep = d.vulns.filter((v) => !v.direct).reduce((n, v) => n + v.count, 0);
          if (d.target.kind === 'package' && own) return `이 버전에 알려진 취약점이 ${own}건${dep ? ` · 의존성에 ${dep}건` : ''} 있습니다. 고쳐진 버전으로 올리세요.`;
          return `의존성에 알려진 취약점이 ${own + dep}건 있습니다. 고쳐진 버전으로 올리세요.`;
        }
        return '정적 검사에서 위험한 코드 · 알려진 취약점을 찾지 못했습니다. 설치 검사(eBPF)로 실제 행동도 확인할 수 있습니다.';
      };
      function scanSheet(d) {
        const [vk, tone] = SCAN_VERDICT[d.verdict] || ['검사 중', 'info'];
        const t = d.target, threats = d.findings.filter((f) => f.category === 'threat' && !f.test), caps = d.findings.filter((f) => f.category === 'capability' && !f.test), tests = d.findings.filter((f) => f.test);
        const vulnN = d.vulns.reduce((n, v) => n + v.count, 0);
        const cmd = t.kind === 'package' ? `sg-install ${t.manager} ${t.name}${t.version ? (t.manager === 'pip' ? '==' : '@') + t.version : ''}` : null;
        const finding = (f) => h('li', null, h('button', { type: 'button', class: `finding f-${f.test ? 'test' : f.category} ${focusLoc === `${f.file}:${f.line}` ? 'on' : ''}`, 'data-finding': '', 'data-category': f.category, 'data-test': f.test ? 'true' : null, 'data-loc': `${f.file}:${f.line}`, onclick: () => { focusLoc = `${f.file}:${f.line}`; draw(); } },
          h('span', { class: 'mono small' }, `${f.file}:${f.line}`), h('b', null, f.message), h('span', { class: 'mono small muted' }, f.rule, f.test ? h('span', { class: 'badge badge-test' }, '테스트 코드') : null)));
        return U.sheet({ kind: 'scan', title: t.label, onClose: () => select(''), body: [
          h('section', { class: `sheet-section scan-verdict sv-box-${tone}`, 'data-part': 'verdict' },
            h('div', { class: 'row-inline' }, h('span', { class: `badge sv-${tone}` }, vk), d.risk ? h('span', { class: 'small' }, '위험 점수 ', h('b', { class: 'num' }, d.risk.score.toFixed(1)), ` / 10 · ${RISK_LABEL[d.risk.label] || d.risk.label}`) : null),
            h('p', { class: 'small' }, U.scanVerdictText(d, threats.length)),
            h('div', { class: 'row-actions' },
              cmd ? h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-label': '설치 검사로 실제 설치해 보기', onclick: () => { try { navigator.clipboard.writeText(cmd).catch(() => {}); } catch { /* 복사 차단 */ } U.toast(`명령을 복사했습니다 — ${cmd} (감시 컨테이너에서 실제 설치 · eBPF 관찰)`, { tone: 'ok', key: 'copy', replace: true, action: { label: '설치 검사', go: '#/installs', state: { status: 'all' } } }); } }, '▶ 설치 검사로 실제 설치해 보기') : null,
              t.kind === 'package' && U.can() ? h('button', { type: 'button', class: `btn ${d.verdict === 'malicious' ? 'btn-danger' : 'btn-ghost'} btn-xs`, 'aria-label': '차단 목록에 올리기', onclick: () => U.api.scanBlock(d.id).then((r) => U.navigate('/policies', { proposal: r.proposalId })).catch((e) => U.toast(`차단 제안 실패: ${e.message}`, { tone: 'danger' })) }, '⛔ 차단 목록에 올리기') : null)),
          t.kind !== 'package' && d.status === 'done' ? packagesView(d) : null,
          h('section', { class: 'sheet-section', 'data-part': 'findings' }, h('h3', null, `위협 ${threats.length}`, h('span', { class: 'small muted' }, ' — GuardDog, 누르면 코드에서 그 줄')),
            threats.length ? h('ul', { class: 'findings' }, threats.map(finding)) : h('p', { class: 'small muted' }, '없음'),
            caps.length ? h('details', { class: 'caps' }, h('summary', { class: 'small' }, `기능(정보) ${caps.length} — 위협은 아니지만 코드가 할 수 있는 일`), h('ul', { class: 'findings' }, caps.map(finding))) : null,
            // 테스트 코드(11/02 결정): 위험 점수 · 판정 · 위협 수에 넣지 않고 따로 보여 준다
            tests.length ? h('details', { class: 'caps', 'data-part': 'tests' }, h('summary', { class: 'small' }, `테스트 코드 ${tests.length} — 위험 점수 · 판정에 넣지 않음`), h('ul', { class: 'findings' }, tests.map(finding))) : null),
          h('section', { class: 'sheet-section', 'data-part': 'code' }, h('h3', null, '코드 보기', h('span', { class: 'small muted' }, ' — 빨강 = 위협 줄, 노랑 = 기능')), codeView(d)),
          d.vulns.length ? h('section', { class: 'sheet-section', 'data-part': 'vulns' }, h('h3', null, `알려진 취약점 ${vulnN}`, h('span', { class: 'small muted' }, t.kind === 'package' ? ' — OSV-Scanner, 이 패키지 버전 · 의존성 포함' : ' — OSV-Scanner, 간접 의존성 포함')),
            h('table', { class: 'table compact' }, h('thead', null, h('tr', null, ['패키지', '버전', '의존', '건수', '최고 심각도', 'ID'].map((x) => h('th', null, x)))),
              h('tbody', null, [...d.vulns].sort((a, b) => Number(b.maxSeverity) - Number(a.maxSeverity)).map((v) => h('tr', { 'data-vpkg': v.package, 'data-count': v.count, 'data-max': v.maxSeverity, 'data-direct': String(v.direct) },
                h('td', { class: 'mono' }, v.package), h('td', { class: 'mono small' }, v.version), h('td', { class: 'small' }, v.direct ? '직접' : '간접'), h('td', { class: 'num' }, v.count),
                h('td', null, h('span', { class: `badge sev-${sevTone(v.maxSeverity)}` }, v.maxSeverity)),
                h('td', { class: 'small' }, v.ids.slice(0, 2).map((id) => h('a', { href: `https://osv.dev/vulnerability/${id}`, target: '_blank', rel: 'noopener', class: 'link mono' }, id, ' ')))))))) : null,
          h('p', { class: 'small muted' }, d.engines.map((e) => `${e.name} ${e.version}`).join(' · '), ' — 오픈소스 정적 분석(Apache-2.0)')] });
      }
      load();
      return { update: () => { if (!error && !inflight) load(); } }; // 오류면 「다시 시도」 · 자동 재시도를 기다린다 [10/20 D · 결정 4]
    },
  };

  // ── 이벤트 — 「지금 무엇이 걸리고 있나?」 [10/15 목표] ──
  // 실시간만(기간 조회는 감사 로그에만), 기본 위반만(「정상 포함」 토글). 행 상세 → 토폴로지에서 관계 보기
  const VERDICT_OPTS = [['violation', '위반 전체'], ['alert', '경고'], ['kill', '격리 (대상 포함)']];
  U.screens['/events'] = {
    title: '이벤트',
    mount(page, query) {
      const f = { kind: query.get('kind') || '', verdict: query.get('verdict') || 'violation', normal: query.get('normal') === '1', container: query.get('container') || '' };
      if (!VERDICT_OPTS.some(([v]) => v === f.verdict)) f.verdict = 'violation';
      let selected = null; const wantId = Number(query.get('id')) || null;
      const count = h('span', { class: 'num muted' });
      const detail = h('div', { class: 'sheet-slot' });
      const pick = (v) => { selected = v; U.setQuery({ id: v ? v.key : '' }); feedEl.select(v ? v.key : null); showDetail(); };
      const feedEl = U.feed({ full: true, onSelect: (v) => pick(v), empty: '조건에 맞는 이벤트 없음 — 데모 제어 → 런타임 공격 「지금 실행」' });
      const pause = U.pauseToggle();
      const setF = (k, v) => { f[k] = v; update(); }; // 필터는 화면 상태만 [10/21b]
      const filters = h('div', { class: 'filters' },
        h('label', null, '종류 ', U.select([['', '전체'], ...KINDS.map((k) => [k, k === 'dns' ? 'dns (도메인 조회)' : k])], f.kind, (v) => setF('kind', v))), // dns 는 긴 이름을 함께 [10/30]
        h('label', null, '탐지 결과 ', U.select(VERDICT_OPTS, f.verdict, (v) => setF('verdict', v))),
        h('label', { class: 'check', 'data-toggle': 'normal' }, h('input', { type: 'checkbox', checked: f.normal, onchange: (e) => setF('normal', e.target.checked) }), '정상 포함'),
        h('input', { class: 'ctl w-44', placeholder: '컨테이너 검색', 'aria-label': '컨테이너 검색', value: f.container, oninput: (e) => setF('container', e.target.value) }),
        h('a', { href: '#/audit', class: 'link small push-right', title: '지난 위반은 감사 로그에서 기간으로 찾는다' }, '지난 기록은 감사 로그 →'));
      // 첫 로드 · 오류 [10/20 D] — 이벤트는 스트림이라 「처음 받기 전」 스켈레톤, 처음 조회가 실패하면 오류 + 다시 시도
      const stateSlot = h('div', { class: 'feed-state' });
      const applied = h('div');
      const VERDICT_KO = Object.fromEntries(VERDICT_OPTS);
      const body = h('div', { class: 'col' }, filters, applied, stateSlot, h('div', { class: 'grow' }, feedEl));
      const main = panel({ title: [h('i', { class: 'live-dot', 'aria-hidden': true }), ' 실시간 이벤트 ', count], actions: pause, body, class: 'grow' });
      page.append(h('div', { class: 'split' }, main, detail));
      function rowsNow() {
        const q = f.container.toLowerCase();
        return state.verdicts.filter((v) => {
          if (f.kind && v.event.kind !== f.kind) return false;
          if (q && !v.event.containerName.toLowerCase().includes(q)) return false;
          const l = levelOf(v);
          if (l === 'normal') return f.normal;
          switch (f.verdict) { case 'alert': return l === 'alert'; case 'kill': return l === 'killed' || l === 'held'; }
          return true;
        });
      }
      function showDetail() {
        detail.replaceChildren();
        if (!selected) { feedEl.setShowImage(true); return; }
        feedEl.setShowImage(false);
        const v = selected; const rule = v.ruleId ? state.rules.find((r) => r.id === v.ruleId) : null;
        const json = Object.assign({}, v); delete json.key;
        const name = v.event.containerName; const lvl = levelOf(v);
        const dns = v.event.kind === 'connect' ? dnsRow(v.event) : null;
        const isInstall = name.startsWith(U.SANDBOX);
        // 이 컨테이너의 건 — 판정은 토폴로지(런타임) · 설치 검사(설치)에서 한다. 이벤트 탭은 「지금」만 답한다
        const rc = !isInstall && (lvl === 'killed' || lvl === 'held') ? state.cases.find((c) => c.source === 'runtime' && c.container === name && c.state !== 'closed') : null;
        const ins = isInstall ? state.installs.find((x) => x.container === name) : null;
        detail.append(U.sheet({ kind: 'event', title: '이벤트 상세', onClose: () => pick(null), body: [
          h('dl', { class: 'dl' }, h('dt', null, '탐지 결과'), h('dd', null, verdictBadge(v)), h('dt', null, '시각'), h('dd', { class: 'num' }, fmt.dateTime(v.event.timestamp)), h('dt', null, '컨테이너'), h('dd', null, name), h('dt', null, '이미지'), h('dd', { class: 'mono' }, v.event.imageName || '—'), h('dt', null, '사유'), h('dd', null, v.reason || '—'), v.enforceError ? [h('dt', null, '격리 오류'), h('dd', { class: 'tone-danger' }, v.enforceError)] : null, dns),
          rc ? h('div', { class: 'card case-hint' }, h('div', { class: 'card-head' }, h('b', null, `건 ${rc.id}`), U.decisionBadge(rc.decision)), h('p', { class: 'small muted' }, rc.state === 'open' ? '이 컨테이너는 판정 대기입니다. 토폴로지에서 관계를 보고 판정하세요.' : '판정됨 — 정책에서 제안 적용 대기')) : null,
          ins ? h('div', { class: 'card case-hint' }, h('div', { class: 'card-head' }, h('b', null, '설치 검사 세션'), h('a', { ...U.to(`#/installs?id=${ins.id}`, { status: 'all' }), class: 'link small' }, `${ins.manager} ${pkgLabel(ins)} →`)), h('p', { class: 'small muted' }, '설치 검사 컨테이너는 토폴로지에 그리지 않습니다. 판정은 설치 검사에서 합니다.')) : null,
          policyStarts(v),
          v.ruleId ? h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('b', null, '관련 정책'), h('a', { href: `#/policies?id=${encodeURIComponent(v.ruleId)}`, class: 'link small' }, '정책 편집')), h('div', { class: 'mono small' }, v.ruleId), rule ? h('p', { class: 'muted small' }, rule.description) : h('p', { class: 'muted small' }, '현재 정책 목록에 없음 (삭제·변경됨)')) : null,
          !isInstall ? h('div', { class: 'row-actions' }, h('a', { ...U.to(U.topoLink(name)), class: 'btn btn-primary btn-xs' }, '토폴로지에서 보기 →')) : null,
          h('div', null, h('b', null, '원본 JSON'), h('pre', { class: 'json' }, JSON.stringify(json, null, 2)))] }));
      }
      let chipSig = '', shownErr, shownReady;
      function update() {
        const rows = rowsNow();
        count.textContent = `${fmt.num(rows.length)}건`;
        // 상태 칸은 바뀔 때만 다시 그린다 — 250ms 마다 새로 그리면 오류 칸의 자동 재시도 시계가 계속 처음부터 잰다 [10/20 결정 4]
        if (state.eventsError !== shownErr || state.eventsReady !== shownReady) { shownErr = state.eventsError; shownReady = state.eventsReady;
          replace(stateSlot, state.eventsError ? U.errorState(state.eventsError, () => U.loadEvents(true), { what: '최근 이벤트' }) : !state.eventsReady ? U.skeleton(8) : null); }
        feedEl.hidden = !state.eventsReady;
        feedEl.set(state.eventsReady ? rows : []);
        const cs = sigOf(f);
        if (cs !== chipSig) { chipSig = cs; replace(applied, U.filterChips([f.kind ? { key: 'kind', label: `종류: ${f.kind}`, clear: () => clearFilter(f, ['kind']) } : null,
          f.verdict !== 'violation' ? { key: 'verdict', label: `탐지 결과: ${VERDICT_KO[f.verdict]}`, clear: () => clearFilter(f, ['verdict']) } : null,
          f.normal ? { key: 'normal', label: '정상 포함', clear: () => clearFilter(f, ['normal']) } : null,
          f.container ? { key: 'container', label: `컨테이너: ${f.container}`, clear: () => clearFilter(f, ['container']) } : null], () => clearFilter(f, ['kind', 'verdict', 'normal', 'container']))); }
        pause.sync();
      }
      update();
      if (wantId) { const v = state.verdicts.find((x) => x.key === wantId); if (v) pick(v); else U.setQuery({ id: '' }); }
      return { update };
    },
  };

  // 도메인 조회 [10/20 I] — connect 의 dnsTraced: true 인데 도메인이 없고 공인 IP 면 「도메인 조회 없는 IP 직접 연결」, false 면 판단 불가(trace_dns 꺼짐)
  function dnsRow(e) {
    const kind = e.dnsTraced === undefined ? 'unknown' : !e.dnsTraced ? 'off' : e.dstHost ? 'traced' : M.isPublic(e.dstIp || '') ? 'direct' : 'private';
    const text = { traced: [`trace_dns 로 확인 — ${e.dstHost}`, ''], direct: ['도메인 조회 없는 IP 직접 연결', 'tone-danger'], private: ['내부 주소 — 도메인 조회 없음(직접 연결로 보지 않음)', 'muted'], off: ['판단 불가 — trace_dns 가 꺼져 있었음(도메인 규칙 통과)', 'tone-warn'], unknown: ['기록 없음(옛 기록)', 'muted'] }[kind];
    return [h('dt', null, '도메인 조회'), h('dd', { 'data-dns': kind, class: text[1] }, kind === 'direct' ? h('span', { class: 'badge badge-kill' }, text[0]) : text[0], kind === 'direct' ? h('span', { class: 'small muted' }, ' — C2 · 유출에 흔함. 규칙의 directIp 로 막을 수 있습니다') : null)];
  }

  // ── 토폴로지 — 「이 컨테이너는 어디까지 손댔나?」 [10/15 목표] ──
  // 런타임 컨테이너만(sg-install-* 는 저장소에서 뺀다). 왼쪽 그래프 + 오른쪽 공격 체인(설치 검사 시트와 같은 부품 U.attackChain).
  // 노드 · 체인을 고르면 상세, 그 컨테이너에 건이 있으면 판정 버튼. 컨테이너 필터(상태)로 들어오면 그 컨테이너를 고른 상태로 연다.
  // 주소에는 컨테이너 노드만 ?node=c:<이름> 로 남는다 — 파일 · 도메인 · 프로세스 노드와 컨테이너 필터는 남기지 않는다 [10/21b]
  const WINDOWS = [1, 5, 15];
  U.screens['/topology'] = {
    title: '토폴로지',
    mount(page, query) {
      let container = query.get('container') || '', windowMin = 5, last = 0, selected = null, snap = { nodes: [], edges: [] };
      let wantNode = (query.get('node') || '').startsWith('c:') ? query.get('node') : container ? `c:${container}` : ''; // 고를 컨테이너 노드(그래프에 나타나면)
      const syncNode = () => U.setQuery({ node: selected && selected.type === 'container' ? selected.id : '' });
      const pickNode = (n) => { selected = n; syncNode(); graph.select(n ? n.id : null); renderSide(); };
      const graph = U.topologyGraph({ onSelect: (n) => pickNode(selected && selected.id === n.id ? null : n) });
      const meta = h('span', { class: 'num muted' });
      const sel = h('span');
      const range = h('input', { type: 'range', min: 0, max: WINDOWS.length - 1, value: WINDOWS.indexOf(windowMin), class: 'range', 'aria-label': '시간 창', oninput: (e) => { windowMin = WINDOWS[Number(e.target.value)]; draw(); } });
      const winLabel = h('span', { class: 'num w-10' });
      const legend = h('div', { class: 'legend-row' }, h('span', { class: 'muted' }, '탐지 결과'), Object.entries(U.LEVEL_LABEL).map(([l, label]) => h('span', null, h('i', { class: `sw sw-${l}` }), label)), h('span', { class: 'muted' }, h('i', { class: 'sw sw-edge' }), '선 굵기 = 위반'));
      const side = h('div', { class: 'topo-side' });
      page.append(h('div', { class: 'topo-layout' },
        panel({ title: ['런타임 토폴로지 ', meta], class: 'grow', actions: h('div', { class: 'row-actions' }, sel, h('label', { class: 'row-inline' }, '최근 ', range, winLabel)), body: h('div', { class: 'col' }, legend, h('div', { class: 'topo-wrap grow' }, graph)) }),
        side));
      // 공격 체인: 컨테이너별로 위반을 일으킨 노드를 시나리오 순서로 — 1 실행(프로세스의 exec 위반) → 2 파일(open) → 3 통신(connect)
      function chains() {
        const out = [];
        const step = (kind, n) => ({ id: n.id, node: n, kind, label: n.label, level: n.byKind[kind], rules: [...n.rules.entries()].filter(([id]) => n.ruleKinds.get(id) === kind).sort((a, b) => b[1] - a[1]).map(([id]) => id), at: n.lastViolation || n.lastSeen });
        for (const c of snap.nodes.filter((n) => n.type === 'container').sort((a, b) => U.SEV[b.level] - U.SEV[a.level])) {
          const steps = [];
          for (const n of snap.nodes) {
            if (n.container !== c.label) continue;
            if (n.type === 'process' && n.byKind.exec) steps.push(step('exec', n));
            if (n.type === 'file' && n.byKind.open) steps.push(step('open', n));
            if (n.type === 'dest' && n.byKind.connect) steps.push(step('connect', n));
            if (n.type === 'dest' && n.byKind.dns) steps.push(step('dns', n)); // DNS 질의 — 「3 통신」 단계, dns 먼저 [10/30]
          }
          if (steps.length) out.push({ container: c, steps });
        }
        return out;
      }
      function nodeDetail(n) {
        const TYPE = { container: '컨테이너', process: '프로세스', file: '파일', dest: '외부 목적지' };
        return h('section', { class: 'side-card' },
          h('div', { class: 'card-head' }, h('b', null, '선택한 노드'), h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-label': '선택 해제', onclick: () => pickNode(null) }, '✕')),
          h('dl', { class: 'dl tight' },
            h('dt', null, '종류'), h('dd', null, TYPE[n.type]),
            h('dt', null, '이름'), h('dd', { class: n.type === 'file' || n.type === 'dest' ? 'mono' : '' }, n.label),
            h('dt', null, '컨테이너'), h('dd', null, n.container),
            h('dt', null, '탐지 결과'), h('dd', null, verdictBadge(U.fakeVerdict(n.level))),
            h('dt', null, '횟수'), h('dd', { class: 'num' }, `${fmt.num(n.count)}회 · 위반 ${fmt.num(n.violations)}회`),
            h('dt', null, '마지막'), h('dd', { class: 'num' }, fmt.time(new Date(n.lastSeen).toISOString()))),
          n.rules.size ? h('div', null, h('div', { class: 'small strong' }, '걸린 규칙'), h('ul', { class: 'rule-chips' }, [...n.rules.entries()].sort((a, b) => b[1] - a[1]).map(([id, cnt]) => h('li', null, h('a', { href: `#/policies?id=${encodeURIComponent(id)}`, class: 'chip mono' }, `${id} ×${cnt}`))))) : null,
          n.reason ? h('p', { class: 'small muted' }, n.reason) : null,
          h('div', { class: 'row-actions' }, h('a', { ...U.to('#/events', { container: n.container, normal: n.level === 'normal' }), class: 'btn btn-ghost btn-xs' }, '이벤트에서 보기 →')));
      }
      // 고른 노드의 컨테이너에 런타임 건이 있으면 판정 카드 — 격리 컨테이너를 판정한다(설치 검사와 같은 판정 버튼)
      const caseFor = (name) => state.cases.find((x) => x.source === 'runtime' && x.container === name && x.state !== 'closed') || state.cases.find((x) => x.source === 'runtime' && x.container === name);
      function caseCard(c, withClose) {
        return h('section', { class: 'side-card case-card', 'data-case': c.id },
          h('div', { class: 'card-head' }, h('b', null, `${c.container} · 건 ${c.id}`), h('span', { class: 'row-inline' }, U.verdictBadge(U.fakeVerdict(c.level)), withClose ? h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-label': '선택 해제', onclick: () => pickNode(null) }, '✕') : null)),
          h('p', { class: 'small muted' }, `이미지 ${c.image} · 열림 ${fmt.time(c.openedAt)} · 위반 ${c.violations}건`),
          h('ul', { class: 'rule-chips' }, c.ruleIds.map((id) => h('li', null, h('a', { href: `#/policies?id=${encodeURIComponent(id)}`, class: 'chip mono' }, id)))),
          c.isolation && c.isolation.timeline ? U.timelineBar(c.isolation.timeline, { compact: true }) : null, // 격리 타임라인 [10/30 계약 §3]
          U.decisionBar(c, { question: '이 컨테이너(이미지)는 악성인가?', onDone: renderSide }),
          h('div', { class: 'row-actions' }, h('a', { ...U.to('#/events', { container: c.container }), class: 'btn btn-ghost btn-xs' }, '이벤트에서 보기 →'),
            c.level === 'killed' ? evidenceLink(c.container, `${c.id}:${c.violations}`) : null, // 증거 보기 [10/20 결정 6]
            h('a', { href: `#/report?case=${encodeURIComponent(c.id)}`, class: 'btn btn-ghost btn-xs', 'data-action': 'report', title: '건 보고서 1장 — 인쇄 · Markdown 복사' }, '▤ 보고서 →'))); // 보고서 [10/30 계약 §5]
      }
      function renderSide() {
        const list = chains();
        const c = selected ? caseFor(selected.container) : null;
        replace(side,
          // 건이 있는 컨테이너를 고르면 판정 카드만(노드 카드와 겹치는 정보를 빼서 공격 체인 자리를 남긴다). 그 밖의 노드는 노드 카드 + 건 카드
          selected && !(c && selected.type === 'container') ? nodeDetail(selected) : null,
          c ? caseCard(c, selected.type === 'container') : null,
          h('section', { class: 'side-card grow' },
            h('div', { class: 'card-head' }, h('b', null, '공격 체인'), h('span', { class: 'small muted num' }, `최근 ${windowMin}분 · ${list.length}개 컨테이너`)),
            list.length ? list.map(({ container: c, steps }) => h('div', { class: 'chain' },
              h('button', { type: 'button', class: `chain-head ${selected && selected.id === c.id ? 'on' : ''}`, onclick: () => pickNode(c) }, h('span', { class: 'strong' }, c.label), verdictBadge(U.fakeVerdict(c.level))),
              U.attackChain(steps, { maxChars: 14, selectedId: selected && selected.id, onPick: (st) => pickNode(st.node) }))) :
              h('div', { class: 'empty' }, state.source === 'sim' ? '이 창에 위반 없음 — 데모 제어 → 런타임 공격 「지금 실행」' : '이 창에 위반 없음')));
      }
      function draw() {
        snap = state.topology.snapshot(windowMin * 60000, container || undefined);
        const risky = snap.nodes.filter((n) => n.level !== 'normal').length;
        meta.textContent = `노드 ${snap.nodes.length} · 위험 ${risky}`;
        winLabel.textContent = `${windowMin}분`;
        replace(sel, U.select([['', '모든 컨테이너'], ...state.topology.containers().map((c) => [c, c])], container, (v) => { container = v; selected = null; syncNode(); graph.select(null); wantNode = v ? `c:${v}` : ''; draw(); }, { 'aria-label': '컨테이너' }));
        if (selected) { selected = snap.nodes.find((n) => n.id === selected.id) || null; if (!selected) syncNode(); }
        if (wantNode) { const c = snap.nodes.find((n) => n.id === wantNode); if (c) { selected = c; wantNode = ''; syncNode(); } }
        graph.select(selected ? selected.id : null);
        graph.set(snap);
        renderSide();
      }
      draw();
      let caseSig = '';
      return { update() {
        const cs = sigOf(state.cases.filter((c) => c.source === 'runtime').map((c) => [c.id, c.state, c.violations]));
        if (Date.now() - last > 1000 || cs !== caseSig) { last = Date.now(); caseSig = cs; draw(); } // 스트림은 250ms, 그래프는 1초(건이 바뀌면 바로)
      } };
    },
  };

  // ── 정책 ─────────────────────────────────────────────────
  const LIST_FIELDS = ['containers', 'denyComms', 'denyArgs', 'denyPaths', 'allowPaths', 'allowPorts', 'allowCidrs', 'allowHosts', 'denyPorts', 'denyCidrs', 'denyHosts', 'denyQtypes'];
  const PORT_FIELDS = ['allowPorts', 'denyPorts'];
  const NUM_FIELDS = ['maxLabelLength', 'maxNameLength']; // dns 전용 정수 필드 [10/30 계약 §1] — 라벨 1..63 · 이름 1..253
  const NUM_RANGE = { maxLabelLength: [1, 63], maxNameLength: [1, 253] };
  const CONNECT_ONLY = ['allowPorts', 'allowCidrs', 'denyPorts', 'denyCidrs', 'directIp']; // dns 에서는 거부
  const FIELDS_BY_KIND = {
    exec: [['denyComms', '금지 프로세스', 'comm 또는 argv[0] 이름 (예: curl, wget, nc)'], ['denyArgs', '금지 인자 패턴', '인자 문자열에 포함되면 위반 (예: | sh)']],
    open: [['denyPaths', '금지 경로', '접두사 일치, * ? [ ] 가 있으면 glob (예: /home/*/.ssh/*)'], ['allowPaths', '예외 경로', '금지 경로보다 먼저 평가되는 허용 목록']],
    connect: [['allowPorts', '허용 포트', '허용 포트·대역·도메인 중 하나면 통과, 그 밖은 위반'], ['allowCidrs', '허용 대역', 'CIDR 또는 IP (예: 10.0.0.0/8)'], ['allowHosts', '허용 도메인', 'DNS 응답으로 확인한 목적지 이름. pypi.org 는 *.pypi.org 도 포함'], ['denyPorts', '금지 포트', '허용 목록과 무관하게 항상 위반'], ['denyCidrs', '금지 대역', '허용 목록과 무관하게 항상 위반'], ['denyHosts', '금지 도메인', '허용 목록과 무관하게 항상 위반']],
    // DNS 질의 규칙(kind: dns) [10/30 계약 §1] — 고급 폼 라벨은 계약 그대로
    dns: [['allowHosts', '허용 도메인', '하나라도 넣으면 여기 없는 도메인 질의는 모두 위반 (점 없는 이름 · *.arpa · *.local · *.internal 은 제외)'], ['denyHosts', '금지 도메인', '허용 목록과 무관하게 항상 위반 (접미사 일치)'], ['denyQtypes', '금지 질의 유형', '대문자, 한 줄에 하나 (예: TXT, ALL)'], ['maxLabelLength', '라벨 길이 상한', '1~63 — 넘는 라벨은 유출 의심'], ['maxNameLength', '이름 길이 상한', '1~253 — 넘는 이름은 유출 의심']],
  };
  // 최소 YAML — 규칙 스키마(스칼라·문자열/숫자 목록)만 다룬다
  const yq = (v) => (typeof v === 'number' || typeof v === 'boolean' ? String(v) : /^[A-Za-z0-9_./*?\[\]:-]+$/.test(v) && !/^[-?:]/.test(v) && !/:$/.test(v) ? v : JSON.stringify(v));
  function ruleToYaml(r, indent) {
    const pad = ' '.repeat(indent || 0); const lines = [];
    for (const k of ['id', 'description', 'kind', 'action', 'directIp', ...NUM_FIELDS, 'dryRun', 'disabled']) if (r[k] !== undefined && r[k] !== '' && r[k] !== false) lines.push(`${pad}${k}: ${yq(r[k])}`);
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
    if (!KINDS.includes(r.kind)) throw new Error('kind 는 exec | open | connect | dns');
    if (!['alert', 'kill'].includes(r.action)) throw new Error('action 은 alert | kill');
    for (const f of PORT_FIELDS) if (r[f] && r[f].some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) throw new Error(`${f}: 1~65535 정수만`);
    if (r.directIp !== undefined && !['allow', 'alert', 'kill'].includes(r.directIp)) throw new Error('directIp 는 allow | alert | kill (또는 비움)');
    if (r.directIp && r.kind !== 'connect') throw new Error('directIp 는 connect 규칙에서만 씁니다');
    // dns 규칙 [10/30 계약 §1]: 조건 1개 이상 · 길이 상한 범위 · 질의 유형 대문자 · connect 전용 필드 거부(백엔드 Validate 와 같게)
    if (r.kind === 'dns') {
      for (const f of CONNECT_ONLY) if (r[f] !== undefined && r[f] !== '' && !(Array.isArray(r[f]) && !r[f].length)) throw new Error(`${f} 는 dns 규칙에서 쓸 수 없습니다 (connect 전용)`);
      for (const f of NUM_FIELDS) if (r[f] !== undefined && !(Number.isInteger(r[f]) && r[f] >= NUM_RANGE[f][0] && r[f] <= NUM_RANGE[f][1])) throw new Error(`${f}: ${NUM_RANGE[f][0]}~${NUM_RANGE[f][1]} 정수`);
      if (r.denyQtypes) { if (!Array.isArray(r.denyQtypes)) throw new Error('denyQtypes 는 목록'); r.denyQtypes = r.denyQtypes.map((q) => String(q).toUpperCase()); }
      if (!(r.allowHosts || []).length && !(r.denyHosts || []).length && !(r.denyQtypes || []).length && !r.maxLabelLength && !r.maxNameLength) throw new Error('dns 규칙에는 조건이 하나 이상 필요합니다 (허용 · 금지 도메인 · 금지 질의 유형 · 길이 상한)');
    } else if (NUM_FIELDS.some((f) => r[f] !== undefined) || r.denyQtypes) throw new Error('denyQtypes · maxLabelLength · maxNameLength 는 dns 규칙에서만 씁니다');
    return r;
  }
  const canWrite = () => U.can(); // 쓰기는 로그인 역할만 — 관리자 토큰 칸은 없앴다 [10/20 결정 1]
  const errText = (e) => (e && e.message) || String(e);

  const CHANGE_OP = { block: '차단', except: '예외' };
  const FIELD_LABEL = { allowPaths: '예외 경로', allowHosts: '허용 도메인', allowCidrs: '허용 대역' };
  const changeKey = (c) => (c.op === 'block' ? `block:${c.list}:${c.value}` : `except:${c.ruleId}:${c.field}:${c.value}`);
  const PROP_STATE = { draft: '초안', applied: '적용됨', discarded: '버림' };
  // 정책 — 「이 변경을 적용하면 무엇이 달라지나?」 [10/15 목표 · 3차 React 모습]
  // 왼쪽: 제안된 변경(맨 위) · 정책 목록. 오른쪽 위: 고른 것(제안 미리보기 · 정책 편집 · YAML). 오른쪽 아래: 차단 목록 · 변경 이력
  // URL: ?proposal=<id> | ?id=<정책 id> | ?id=__yaml__ | ?id=__new__ | ?id=__blocklist__(아래 차단 목록 칸으로 이동)
  U.screens['/policies'] = {
    title: '정책',
    mount(page, query) {
      // 서버 설정 · 계정은 「설정」 화면으로 옮겼다 [10/20 결정 2] — 옛 주소(알림 · 북마크)는 그리로 보낸다
      if (query.get('tab') === 'accounts') { location.replace('#/settings?tab=accounts'); return {}; }
      if (query.get('settings')) { location.replace('#/settings'); return {}; }
      let selected = query.get('id') || '', proposalId = query.get('proposal') || '';
      let focusBlocklist = selected === '__blocklist__'; if (focusBlocklist) selected = '';
      // 이벤트 · 감사 행에서 온 시작점(한 번만 쓴다): intent=block&kind&value → 새 정책 / intent=allow&value → 걸린 정책에 예외 [10/16]
      let intent = query.get('intent') ? { type: query.get('intent'), kind: query.get('kind'), value: query.get('value') || '' } : null;
      let tplRule = null; // 템플릿에서 고른 새 정책
      let drafts = [], allProps = [], propErr = null, blocklist = null, blErr = null, cases = [], changes = [];
      const isSystem = (id) => id === M.SYSTEM_RULE;
      const propList = h('div');
      const blBody = h('div', { class: 'grow scroll', 'data-view': 'blocklist' });
      const blCount = h('span', { class: 'num muted' });
      const chBody = h('div', { class: 'grow scroll' });
      const chCount = h('span', { class: 'num muted' });
      const list = h('ul', { class: 'rule-list' });
      const editor = h('div', { class: 'grow' });
      const editorTitle = h('span');
      // 화면 머리의 관리자 토큰 칸 · 서버 설정 버튼은 없앴다 [10/20 결정 1 · 2] — 쓰기는 로그인 역할, 서버 설정은 「설정」 화면
      const select = (id) => { if (id === '__blocklist__') { showBlocklist(); return; } tplRule = null; intent = null; pendingDefault = null; selected = id || (state.rules[0] || {}).id || ''; proposalId = ''; U.setQuery({ id: selected, proposal: '' }); renderNav(); renderEditor(); };
      const selectProposal = (id) => { proposalId = id; selected = ''; U.setQuery({ proposal: id, id: '' }); renderNav(); renderEditor(); };
      const draftCount = h('span', { class: 'num muted' });
      const rulesTitle = h('span');
      const blPanel = h('section', { class: 'panel', 'data-section': 'blocklist' }, h('header', { class: 'panel-head' }, h('h2', null, '차단 목록 ', blCount)), blBody);
      // 새 기본 규칙 안내 띠 [10/20 F] — GET /api/policies/defaults 의 missing · differs. 「이번엔 숨기기」는 이 브라우저(기본 규칙 내용이 바뀌면 다시 보인다)
      const defaultsSlot = h('div', { class: 'defaults-slot' });
      const HIDE_KEY = 'supplyguard.defaults.hidden';
      const hidden = () => { try { return JSON.parse(localStorage.getItem(HIDE_KEY) || '{}'); } catch { return {}; } };
      const hideSig = (r) => JSON.stringify(r);
      let defaults = null, defaultsOpen = false;
      // 바뀐 규칙: 지금 규칙을 덮어쓰지 않고, 기본에만 있는 값(목록 항목 · 비어 있는 옵션)만 더한 사본
      function mergeDefault(cur, def) {
        const r = JSON.parse(JSON.stringify(cur));
        for (const [k, v] of Object.entries(def)) {
          if (Array.isArray(v)) { const have = new Set(r[k] || []); const add = v.filter((x) => !have.has(x)); if (add.length) r[k] = [...(r[k] || []), ...add]; }
          else if (r[k] === undefined || r[k] === '') r[k] = v;
        }
        return r;
      }
      function diffText(cur, def) {
        const out = [];
        for (const k of new Set([...Object.keys(cur), ...Object.keys(def)])) {
          if (['description', 'disabled', 'dryRun'].includes(k)) continue;
          const a = cur[k], b = def[k];
          if (JSON.stringify(a) === JSON.stringify(b)) continue;
          if (Array.isArray(b)) { const add = b.filter((x) => !(a || []).includes(x)); if (add.length) out.push(`${k} +${add.join(', ')}`); }
          else if (a === undefined) out.push(`${k}: (없음) → ${b}`);
          else if (b !== undefined) out.push(`${k}: ${a} (지금 값 유지, 기본은 ${b})`);
        }
        return out.length ? out.join(' · ') : '지금 규칙에만 있는 값이 있습니다(그대로 둡니다)';
      }
      function drawDefaults() {
        const hid = hidden();
        const items = defaults ? [...defaults.missing.map((r) => ({ kind: 'missing', id: r.id, rule: r })), ...defaults.differs.map((d) => ({ kind: 'differs', id: d.id, rule: d.default, current: d.current }))].filter((x) => hid[x.id] !== hideSig(x.rule)) : [];
        const nM = items.filter((x) => x.kind === 'missing').length, nD = items.length - nM;
        if (!items.length) { replace(defaultsSlot); defaultsSlot.hidden = true; return; }
        defaultsSlot.hidden = false;
        const preview = (x) => { tplRule = null; intent = null; proposalId = ''; selected = x.kind === 'missing' ? '__default__' : x.id; pendingDefault = x; U.setQuery({ id: x.kind === 'missing' ? '' : x.id, proposal: '' }); renderNav(); renderEditor(); };
        replace(defaultsSlot, h('section', { class: 'defaults-banner', 'data-part': 'defaults-banner' },
          h('div', { class: 'row-inline' }, h('span', { class: 'defaults-icon', 'aria-hidden': true }, '★'),
            h('b', null, `기본 정책에 ${[nM ? `새 규칙 ${nM}개` : null, nD ? `바뀐 규칙 ${nD}개` : null].filter(Boolean).join(' · ')}가 있습니다`),
            h('span', { class: 'small muted' }, '— 업데이트로 생긴 규칙은 저절로 들어가지 않습니다. 사용자가 바꾼 규칙은 덮어쓰지 않습니다.'),
            h('button', { type: 'button', class: 'btn btn-ghost btn-xs push-right', 'data-action': 'defaults-toggle', 'aria-expanded': String(defaultsOpen), onclick: () => { defaultsOpen = !defaultsOpen; drawDefaults(); } }, defaultsOpen ? '접기 ▴' : '펼치기 ▾')),
          defaultsOpen ? h('ul', { class: 'defaults-list' }, items.map((x) => h('li', { 'data-default': x.id },
            h('span', { class: `badge ${x.kind === 'missing' ? 'badge-info' : 'badge-alert'}` }, x.kind === 'missing' ? '새 규칙' : '바뀐 규칙'),
            h('span', { class: 'defaults-what' }, h('span', { class: 'trunc-cell' }, x.rule.description || x.id), h('small', { class: 'mono muted trunc-cell' }, x.kind === 'missing' ? x.id : `${x.id} — ${diffText(x.current, x.rule)}`)),
            U.can() ? h('button', { type: 'button', class: 'btn btn-outline btn-xs', 'data-action': 'default-preview', onclick: () => preview(x) }, '미리보기 후 추가') : null,
            h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': 'default-hide', title: '이 브라우저에서 이번 기본 규칙은 숨깁니다', onclick: () => { const m = hidden(); m[x.id] = hideSig(x.rule); try { localStorage.setItem(HIDE_KEY, JSON.stringify(m)); } catch { /* 저장 차단 */ } drawDefaults(); } }, '이번엔 숨기기'))),
          h('li', { class: 'small muted' }, '목록에 없던 규칙은 그대로, 바뀐 규칙은 지금 규칙에 없는 값만 더해 「저장 전 확인」(최근 감사 로그 재평가)을 거쳐 저장합니다.')) : null));
      }
      const loadDefaults = () => U.api.policyDefaults().then((d) => { defaults = d; drawDefaults(); }).catch(() => { defaults = null; drawDefaults(); });
      let pendingDefault = null;
      page.append(defaultsSlot);
      const polEl = h('div', { class: 'pol' },
        h('div', { class: 'policy-nav pol-left' },
          h('section', { class: 'panel pol-props', 'data-section': 'proposals' }, h('header', { class: 'panel-head' }, h('h2', null, '제안된 변경 ', draftCount)), h('div', { class: 'scroll' }, propList)),
          h('section', { class: 'panel grow', 'data-section': 'rules' },
            h('header', { class: 'panel-head' }, h('h2', null, rulesTitle), U.can() ? h('div', { class: 'panel-actions' }, h('button', { type: 'button', class: 'btn btn-ghost btn-xs', title: '전체 정책을 YAML 로 보기·일괄 적용', onclick: () => select('__yaml__') }, '{} YAML'), h('button', { type: 'button', class: 'btn btn-primary btn-xs', onclick: () => select('__new__') }, '+ 새 정책')) : null),
            h('div', { class: 'grow scroll' }, list))),
        h('div', { class: 'pol-right' },
          panel({ title: editorTitle, class: 'grow', body: editor }),
          h('div', { class: 'pol-bottom' }, blPanel,
            h('section', { class: 'panel', 'data-section': 'changes' }, h('header', { class: 'panel-head' }, h('h2', null, '변경 이력 ', chCount), h('a', { href: '#/audit?view=changes', class: 'link small' }, '감사 로그 →')), chBody))));
      page.append(polEl);
      loadDefaults();
      // ?id=__blocklist__ · 「차단 목록에서 관리」: 아래 차단 목록 칸으로 이동해 잠깐 강조한다
      function showBlocklist() { blPanel.classList.remove('flash'); void blPanel.offsetWidth; blPanel.classList.add('flash'); blPanel.scrollIntoView({ block: 'nearest' }); }
      // 적용 범위 칩: 시스템 규칙은 「차단 목록에서 관리」, containers 가 sg-install-* 뿐이면 「설치 검사 전용」, 그 밖에 지정이 있으면 「일부 컨테이너」
      const scopeOf = (r) => (isSystem(r.id) ? '차단 목록에서 관리' : !r.containers || !r.containers.length ? null : r.containers.every((c) => c.startsWith('sg-install-')) ? '설치 검사 전용' : '일부 컨테이너');
      const caseLabel = (c) => (c ? caseTarget(c, state.installs) : '');
      const changeText = (ch) => (ch.op === 'block' ? `${U.LIST_LABEL[ch.list]} 차단 ${ch.value}` : `${ch.ruleId} ${FIELD_LABEL[ch.field] || ch.field} += ${ch.value}`);
      function renderNav() {
        draftCount.textContent = propErr ? '' : String(drafts.length);
        replace(propList, propErr ? h('p', { class: 'pad-sm small muted' }, propErr.unsupported ? propErr.message : `불러오기 실패: ${propErr.message}`)
          : !drafts.length ? h('p', { class: 'pad-sm small muted' }, '적용할 제안 없음 — 설치 검사 · 토폴로지에서 판정하면 여기에 생깁니다')
          : h('ul', { class: 'rule-list' }, drafts.map((p) => { const c = cases.find((x) => x.id === p.caseId); return h('li', null, h('button', { type: 'button', class: `rule-row prop-row ${p.id === proposalId ? 'selected' : ''}`, 'data-proposal': p.id, onclick: () => selectProposal(p.id) },
            h('span', { class: 'prop-line' }, U.decisionBadge(p.decision), h('span', { class: 'rule-id mono', title: caseLabel(c) }, caseLabel(c)), h('span', { class: 'small muted num push-right' }, fmt.time(p.createdAt))),
            h('span', { class: 'small muted trunc-cell prop-sum' }, p.changes.length ? p.changes.map(changeText).join(' · ') : '변경 없음 — 안내만'))); })));
        renderBottom();
        rulesTitle.textContent = `정책 ${state.rules.length}`;
        replace(list, state.rules.length ? state.rules.map((r) => h('li', null, h('button', { type: 'button', class: `rule-row ${r.id === selected ? 'selected' : ''}`, onclick: () => select(r.id) },
          h('span', { class: `dot ${r.disabled ? 'off' : 'on'}`, title: r.disabled ? '비활성' : '활성' }),
          // 쉬운 말 우선: 설명(없으면 이름) + 영문 이름은 작게, 대응 · 종류도 한국어 [10/16]
          h('span', { class: `rule-name ${r.disabled ? 'muted' : ''}`, title: r.description || r.id }, h('span', { class: 'trunc-cell' }, r.description || r.id), h('small', { class: 'mono muted trunc-cell' }, r.id)),
          scopeOf(r) ? h('span', { class: 'scope-chip', title: (r.containers || []).join(', ') }, scopeOf(r)) : null,
          h('span', { class: `badge ${r.action === 'kill' && !r.dryRun ? 'badge-kill' : 'badge-alert'}`, title: r.action }, r.action === 'kill' ? (r.dryRun ? '시험' : '격리') : '알림'),
          Object.assign(kindBadge(r.kind), { textContent: U.KIND_SHORT[r.kind] || r.kind })))) : empty('정책 없음')); // 짧은 라벨(dns 「조회」) [10/30]
      }
      function renderEditor() {
        editor.replaceChildren();
        if (proposalId) { const p = allProps.find((x) => x.id === proposalId); editorTitle.textContent = p ? `제안 · ${p.decision === 'malicious' ? '악성' : '오탐'} ${caseLabel(cases.find((x) => x.id === p.caseId)) || p.caseId}` : '제안'; editor.append(p ? proposalView(p) : empty(propErr ? propErr.message : '제안을 찾을 수 없음')); return; }
        const cur = state.rules.find((r) => r.id === selected);
        if (cur && isSystem(cur.id)) { editorTitle.textContent = `시스템 규칙 · ${cur.id}`; editor.append(systemRuleView(cur)); return; }
        // 조회자: 편집기 대신 읽기 전용(요약 · YAML) — 저장 · 삭제 버튼이 없다 [10/20 A]
        if (!U.can()) { editorTitle.textContent = cur ? `정책 · ${cur.id}` : '정책'; editor.append(cur ? readOnlyRule(cur) : empty('왼쪽에서 정책을 고르세요')); return; }
        if (selected === '__yaml__') { editorTitle.textContent = '전체 정책 YAML'; editor.append(bulkYaml()); return; }
        // 새 기본 규칙 「미리보기 후 추가」 [10/20 F] — 바로 「저장 전 확인」으로 연다
        if (pendingDefault && (selected === '__default__' || selected === pendingDefault.id)) {
          const x = pendingDefault;
          if (x.kind === 'missing') { editorTitle.textContent = `새 기본 규칙 · ${x.id}`; editor.append(ruleEditor(x.rule, true, { autoCheck: true })); return; }
          const c0 = state.rules.find((r) => r.id === x.id);
          if (c0) { editorTitle.textContent = `바뀐 기본 규칙 · ${x.id} — 빠진 값만 더함`; editor.append(ruleEditor(mergeDefault(c0, x.rule), false, { autoCheck: true })); return; }
        }
        if (selected === '__new__') {
          const it = intent; intent = null;
          if (it && it.type === 'block' && KINDS.includes(it.kind) && it.value) tplRule = U.policyEasy.ruleFromBlock(it.kind, it.value);
          if (!tplRule) { editorTitle.textContent = '새 정책 · 무엇을 하고 싶나요?'; editor.append(templatesView()); return; }
          editorTitle.textContent = `새 정책 · ${tplRule.description || tplRule.id}`; editor.append(ruleEditor(tplRule, true)); return;
        }
        if (cur) {
          const it = intent; intent = null;
          if (it && it.type === 'allow' && it.value) { const w = U.policyEasy.ruleWithAllow(cur, it.value); editorTitle.textContent = `정책 편집 · ${cur.id} — 예외 추가`; editor.append(ruleEditor(w.rule, false, { fresh: w.fresh, freshField: w.field })); return; }
          editorTitle.textContent = `정책 편집 · ${cur.id}`; editor.append(ruleEditor(cur, false)); return;
        }
        editorTitle.textContent = '정책 편집'; editor.append(empty('왼쪽에서 정책을 고르거나 새 정책을 만드세요'));
      }
      // 새 정책 — 목적별 템플릿에서 시작 [10/16]
      function templatesView() {
        return h('div', { class: 'grow scroll pad', 'data-view': 'templates' },
          h('p', { class: 'muted' }, '무엇을 막고 싶은지 고르면 값이 채워진 채로 시작합니다. 저장 전에 모두 고칠 수 있습니다.'),
          h('div', { class: 'tpl-grid' }, U.policyEasy.TEMPLATES.map((t) => h('button', { type: 'button', class: `tpl ${t.key === 'blank' ? 'tpl-blank' : ''}`, 'data-template': t.key === 'reverse-shell' ? 'reverse-shell' : t.key, onclick: () => { tplRule = U.policyEasy.fromTemplate(t.key); renderEditor(); } },
            h('span', { class: 'tpl-kind' }, U.policyEasy.KIND_TEXT[t.rule.kind][0]), h('b', null, t.title), h('small', { class: 'muted' }, t.desc)))));
      }
      // 조회자용 정책 보기 [10/20 A]
      function readOnlyRule(r) {
        const d = { id: r.id, description: r.description || '', kind: r.kind, action: r.action, dryRun: !!r.dryRun, disabled: !!r.disabled, lists: {}, nums: {} };
        for (const f of LIST_FIELDS) d.lists[f] = (r[f] || []).join('\n');
        for (const f of NUM_FIELDS) d.nums[f] = r[f] || '';
        return h('div', { class: 'grow scroll pad', 'data-readonly-rule': r.id }, h('div', { class: 'sheet-body flat' },
          h('p', { class: 'summary-bar' }, U.policyEasy.summarize(d)),
          h('p', { class: 'small muted' }, '조회자는 정책을 볼 수만 있습니다. 바꾸려면 관리자에게 요청하세요.'),
          h('pre', { class: 'json' }, ruleToYaml(r, 0))));
      }
      // 제안 상세 — 근거(판정) → 변경 내용 · 안내(notes) → 미리보기(열면 자동, U.previewView) → 적용 / 버림 [3차 React 모습]
      function proposalView(p) {
        const c = cases.find((x) => x.id === p.caseId);
        const prevSlot = h('div');
        let lastPv = null;
        const runPreview = () => { replace(prevSlot, U.previewView(p, null)); U.api.preview(p.id).then((r) => { lastPv = r; replace(prevSlot, U.previewView(p, r, (id) => state.audit.find((a) => a.id === id))); }).catch((e) => replace(prevSlot, U.previewView(p, { error: e.message }))); };
        runPreview();
        const msg = h('span', { class: 'grow small' });
        const act = (fn, done) => fn(p.id).then((r) => { done(r); return load(); }).catch((e) => { msg.className = 'grow small tone-danger'; msg.textContent = e.message; });
        // 적용 · 버림 = 확인 대화상자(대상 · 함께 일어나는 일 · 사유 · 되돌리기) [10/20 B — 두 번 누르기 대체]. 조회자는 미리보기만
        const target = `${caseLabel(c) || p.caseId} · 제안 ${p.id}`;
        const doApply = () => U.confirmDialog({ title: '제안 적용', target, tone: 'primary', okLabel: '적용',
          effects: (lastPv ? Promise.resolve(lastPv) : U.api.preview(p.id).catch(() => null)).then((pv) => U.api.impactApply(p, pv)),
          undo: p.decision === 'malicious' ? '정책 › 차단 목록에서 「해제」하면 다음 설치 · 기동부터 풀립니다' : '정책 편집에서 더한 예외 값을 지우고 저장하면 됩니다' })
          .then((r) => r && act((id) => U.api.apply(id, { reason: r.reason }), (x) => U.toast(`제안 적용 — ${caseLabel(c)} 건 종결 · ${x.change.summary}`, { tone: 'ok', key: 'proposal', replace: true, action: { label: '변경 이력', go: '#/audit?view=changes' } })));
        const doDiscard = () => U.confirmDialog({ title: '제안 버림', target, okLabel: '버림',
          effects: [`정책 · 차단 목록은 바뀌지 않습니다`, `건 ${p.caseId} 은 판정(${p.decision === 'malicious' ? '악성' : '오탐'})만 남기고 종결`, '판정 · 변경 이력에 「제안 버림」으로 남습니다'],
          undo: '버린 제안은 되살리지 않습니다 — 같은 대상이 다시 걸리면 새 건으로 판정합니다' })
          .then((r) => r && act((id) => U.api.discard(id, { reason: r.reason }), () => U.toast(`제안 ${p.id} 버림 — ${caseLabel(c)} 건 변경 없이 종결`, { tone: 'warn', key: 'proposal', replace: true })));
        const foot = p.state === 'draft'
          ? [h('button', { type: 'button', class: 'btn btn-outline', 'aria-label': '미리보기', title: '지금 정책 · 감사 로그로 다시 계산', onclick: runPreview }, '👁 미리보기'), msg,
            U.can() ? h('button', { type: 'button', class: 'btn btn-danger-ghost', 'aria-label': '버림', onclick: doDiscard }, '버림') : null,
            U.can() ? h('button', { type: 'button', class: 'btn btn-primary', 'aria-label': '적용', onclick: doApply }, '적용') : h('span', { class: 'small muted' }, '적용 · 버림은 관리자가 합니다')]
          : [h('span', { class: 'grow small', 'data-applied': p.state }, p.state === 'applied'
            ? [h('b', { class: 'tone-ok' }, '적용됨'), ` — ${p.appliedBy} · ${fmt.dateTime(p.appliedAt)} · 건 ${p.caseId} 종결 · `, h('a', { href: '#/audit?view=changes', class: 'link' }, '감사 로그 › 변경 이력 →')]
            : [h('b', null, '버림'), ` — 건 ${p.caseId} 변경 없이 종결`])];
        const caseLink = c ? U.caseLink(c, true) : null;
        return h('div', { class: 'col', 'data-view': 'proposal', 'data-proposal-id': p.id },
          h('div', { class: 'grow scroll pad' }, h('div', { class: 'sheet-body flat' },
            h('section', { class: 'sheet-section', 'data-part': 'basis' }, h('h3', null, '근거'),
              h('p', { class: 'small' }, c ? [`${U.CASE_SOURCE[c.source] || c.source} `, h('span', { class: 'mono' }, caseLabel(c)), ` · 위반 ${fmt.num(c.violations)}건 (${c.ruleIds.join(', ')}) · ${c.decidedBy || p.createdBy} 판정 ${fmt.dateTime(c.decidedAt || p.createdAt)}`, c.note ? ` · 메모 「${c.note}」` : '', ' · 건 ', h('a', { ...U.to(caseLink), class: 'link mono' }, p.caseId)]
                : `건 ${p.caseId} · ${p.createdBy} · ${fmt.dateTime(p.createdAt)}`)),
            h('section', { class: 'sheet-section' }, h('h3', null, `변경 내용 ${p.changes.length}`),
              p.changes.length ? h('ul', { class: 'change-list', 'data-changes': '' }, p.changes.map((ch) => h('li', { 'data-change': changeKey(ch) },
                h('span', { class: `badge ${ch.op === 'block' ? 'badge-kill' : 'badge-alert'}` }, CHANGE_OP[ch.op]), h('span', { class: 'mono small' }, changeText(ch)))))
                : h('p', { class: 'small muted' }, '자동으로 만들 변경이 없습니다 — 적용하면 건만 종결합니다.'),
              (p.notes || []).length ? h('ul', { class: 'note-box notes', 'data-notes': '', 'data-exec-note': '' }, p.notes.map((n) => h('li', null, n))) : null,
              p.changes.some((x) => x.op === 'block' && x.list === 'hosts') ? h('p', { class: 'small muted' }, `도메인 차단은 시스템 규칙 ${M.SYSTEM_RULE} 로 바로 집행됩니다(런타임 · 설치 모두).`) : null),
            prevSlot)),
          h('div', { class: 'foot' }, foot));
      }
      // 아래 칸: 차단 목록(패키지 · 이미지 · 도메인, 해제는 두 번 눌러 확정) · 변경 이력(최근 50)
      const BL_LISTS = [['packages', '패키지'], ['images', '이미지'], ['hosts', '도메인']];
      function renderBottom() {
        const total = blocklist ? BL_LISTS.reduce((n, [l]) => n + blocklist[l].length, 0) : 0;
        blCount.textContent = blocklist ? String(total) : '';
        replace(blBody, blErr ? h('p', { class: 'pad-sm small muted' }, blErr.unsupported ? blErr.message : `불러오기 실패: ${blErr.message}`)
          : !blocklist ? h('p', { class: 'pad-sm small muted' }, '불러오는 중…')
          : [!total ? h('p', { class: 'pad-sm small muted' }, '비어 있음 — 「악성 확정」 제안을 적용하면 여기에 들어갑니다') : null,
            BL_LISTS.map(([l, label]) => h('div', { 'data-list': l }, blocklist[l].map((x) => h('div', { class: 'bl-row', 'data-value': x.value, title: `${x.caseId || '—'} · ${x.by} · ${fmt.dateTime(x.at)}` },
              h('span', { class: 'small muted' }, label), h('span', { class: 'mono small trunc-cell' }, x.value),
              U.can() ? h('button', { type: 'button', class: 'btn btn-danger-ghost btn-xs', onclick: () => U.confirmDialog({ title: '차단 해제', target: `${label} ${x.value}`, okLabel: '해제', effects: U.api.impactUnblock(l, x.value),
                undo: '다시 막으려면 설치 검사 · 토폴로지에서 악성 판정하거나 공급망 검사에서 차단 목록에 올리세요' })
                .then((r) => r && U.api.unblock(l, x.value, { reason: r.reason }).then(() => { U.toast(`${label} ${x.value} 차단 해제`, { tone: 'warn', key: 'unblock', replace: true }); return load(); }))
                .catch((e) => U.toast(`해제 실패: ${e.message}`, { tone: 'danger' })) }, '해제') : null))))]);
        chCount.textContent = String(changes.length);
        replace(chBody, !changes.length ? h('p', { class: 'pad-sm small muted' }, '아직 없음')
          : h('ul', { class: 'ch-list' }, changes.slice(0, 50).map((x) => h('li', { 'data-change-id': x.id },
            h('div', { class: 'row-inline' }, h('span', { class: 'badge badge-level-normal' }, CHANGE_KIND[x.kind] || x.kind), h('span', { class: 'small muted num' }, fmt.dateTime(x.at)), h('span', { class: 'small muted push-right' }, x.by)),
            h('div', { class: 'small trunc-cell', title: x.summary }, x.summary)))));
      }
      function systemRuleView(r) {
        return h('div', { class: 'grow scroll pad', 'data-readonly': r.id }, h('div', { class: 'sheet-body flat' },
          h('p', { class: 'note-box' }, '시스템 규칙 — 직접 편집할 수 없습니다. 차단 목록의 도메인이 바뀌면 이 규칙의 denyHosts 가 함께 바뀝니다.'),
          h('dl', { class: 'dl' }, h('dt', null, 'id'), h('dd', { class: 'mono' }, r.id), h('dt', null, '설명'), h('dd', null, r.description), h('dt', null, '종류 · 대응'), h('dd', null, kindBadge(r.kind), ' ', h('span', { class: 'badge badge-kill' }, r.action)),
            h('dt', null, '금지 도메인'), h('dd', { class: 'mono' }, (r.denyHosts || []).length ? r.denyHosts.join(', ') : '없음')),
          h('div', { class: 'row-actions' }, h('button', { type: 'button', class: 'btn btn-primary btn-xs', onclick: () => select('__blocklist__') }, '차단 목록에서 관리 →'))));
      }
      function bulkYaml() {
        const ta = h('textarea', { class: 'ctl mono yaml grow', spellcheck: 'false', 'aria-label': '전체 정책 YAML', disabled: true }, '불러오는 중…');
        U.api.exportYaml().then((text) => { ta.value = text === null ? rulesToYaml(state.rules.filter((r) => !isSystem(r.id))) : text; ta.disabled = false; apply.disabled = !canWrite(); }).catch((e) => { msg.className = 'grow small tone-danger'; msg.textContent = errText(e); });
        const msg = h('span', { class: 'grow small' }, state.source === 'sim' ? `시스템 규칙 ${M.SYSTEM_RULE} 는 YAML 에 없고 교체해도 그대로 남습니다` : '');
        const apply = h('button', { type: 'button', class: 'btn btn-primary', disabled: true });
        apply.textContent = '전체 교체 후 적용 ▶';
        apply.addEventListener('click', () => U.confirmDialog({ title: '전체 정책 교체', target: 'YAML 의 정책 전체', okLabel: '교체 후 적용', reason: false,
          effects: [`지금 정책 ${state.rules.filter((r) => !isSystem(r.id)).length}개를 YAML 의 내용으로 모두 바꿉니다(시스템 규칙 ${M.SYSTEM_RULE} 은 그대로)`, 'YAML 에 없는 정책은 지워집니다', '엔진에 바로 적용 · 변경 이력에 남습니다'],
          undo: '바꾸기 전 YAML 을 복사해 두면 같은 화면에서 다시 교체할 수 있습니다' }).then((ok) => ok && runReplace()));
        const runReplace = () => {
          const done = (rs) => { renderNav(); msg.className = 'grow small tone-ok'; msg.textContent = `${rs.length}개 정책을 엔진에 적용함`; U.toast(`정책 ${rs.length}개 전체 교체 후 적용`, { tone: 'ok' }); };
          const fail = (e) => { msg.className = 'grow small tone-danger'; msg.textContent = errText(e); };
          if (state.source === 'live') { U.api.applyYaml(ta.value).then(done).catch(fail); return; }
          try { const doc = parseYaml(ta.value); if (!doc || !Array.isArray(doc.rules)) throw new Error('400 · 최상위 rules: 목록이 필요함'); const rs = doc.rules.map((r) => validateRule(r)); const ids = new Set(); for (const r of rs) { if (ids.has(r.id)) throw new Error(`400 · 중복 id: ${r.id}`); ids.add(r.id); } done(U.api.replaceRules(rs)); }
          catch (e) { fail(e); }
        };
        return h('div', { class: 'col' }, h('div', { class: 'grow pad' }, ta), h('div', { class: 'foot' }, msg, apply));
      }
      // 정책 편집 — 「쉬운 설정」(기본, U.policyEasy) · 「고급 · 폼」 · 「고급 · YAML」이 같은 draft 를 고친다.
      // 저장은 늘 「저장 전 확인」(한 줄 요약 + 최근 감사 로그 재평가 미리보기)을 거친다 [10/16 정책 개편]
      // opts.fresh: 이벤트 · 감사 행 「이 행동 허용」으로 새로 더한 예외 값(강조)
      function ruleEditor(rule, isNew, opts) {
        const o = opts || {};
        let mode = 'easy', draft = toDraft(rule), yamlText = '', error = '', saved = false, check = null;
        const root = h('div', { class: 'col', 'data-view': 'rule-editor' });
        const sumEl = h('div', { class: 'summary-bar', 'data-summary': '' });
        const ctx = { isNew, fresh: o.fresh ? new Set([`${o.freshField}:${o.fresh}`]) : null, onChange: () => { saved = false; error = ''; sumEl.textContent = U.policyEasy.summarize(draft); }, rerender: () => { saved = false; error = ''; render(); } };
        function toDraft(r) { const d = { id: r.id, description: r.description || '', kind: r.kind, action: r.action, directIp: r.directIp || '', dryRun: !!r.dryRun, disabled: !!r.disabled, lists: {}, nums: {} }; for (const f of LIST_FIELDS) d.lists[f] = (r[f] || []).join('\n'); for (const f of NUM_FIELDS) d.nums[f] = r[f] || ''; return d; }
        function toRule(d) {
          const r = { id: d.id.trim(), kind: d.kind, action: d.action };
          if (d.directIp && d.kind === 'connect') r.directIp = d.directIp; // 직접 IP 연결 처리 [10/20 F · I]
          if (d.description.trim()) r.description = d.description.trim(); if (d.dryRun) r.dryRun = true; if (d.disabled) r.disabled = true;
          for (const f of ['containers', ...FIELDS_BY_KIND[d.kind].map((x) => x[0]).filter((f) => !NUM_FIELDS.includes(f))]) {
            const items = (d.lists[f] || '').split(/[\n,]/).map((x) => x.trim()).filter(Boolean); if (!items.length) continue;
            if (PORT_FIELDS.includes(f)) { const ports = items.map(Number); const bad = items.find((_, i) => !Number.isInteger(ports[i]) || ports[i] < 1 || ports[i] > 65535); if (bad) throw new Error(`포트 값 오류: ${bad}`); r[f] = ports; }
            else if (f === 'denyQtypes') r[f] = items.map((x) => x.toUpperCase());
            else r[f] = items;
          }
          // dns 길이 상한(정수) [10/30] — 비우면 조건 없음
          if (d.kind === 'dns') for (const f of NUM_FIELDS) { const v = String((d.nums || {})[f] == null ? '' : d.nums[f]).trim(); if (!v) continue; const n = Number(v); if (!Number.isInteger(n)) throw new Error(`${f}: 정수로 써 주세요`); r[f] = n; }
          return r;
        }
        const current = () => { if (mode !== 'yaml') return validateRule(toRule(draft)); const p = parseYaml(yamlText); if (!isNew && p && p.id !== rule.id) throw new Error('기존 정책의 id는 바꿀 수 없음'); return validateRule(p); };
        const MODES = [['easy', '쉬운 설정'], ['form', '고급 · 폼'], ['yaml', '고급 · YAML']];
        function render() {
          if (check) { renderCheck(); return; }
          const effective = draft.action === 'kill' && draft.dryRun ? 'kill → 알림만 (dry-run)' : draft.action;
          const field = (label, hint, ctl) => h('label', { class: 'field' }, h('span', null, h('b', null, label), hint ? h('small', { class: 'muted' }, ' ' + hint) : null), ctl);
          const upd = (patch) => { Object.assign(draft, patch); saved = false; render(); };
          const body = mode === 'easy' ? U.policyEasy.render(draft, ctx)
            : mode === 'yaml'
              ? h('textarea', { class: 'ctl mono yaml grow', spellcheck: 'false', 'aria-label': '정책 YAML', value: yamlText, oninput: (e) => { yamlText = e.target.value; saved = false; } }, yamlText)
              : h('div', { class: 'form' },
                field('id', '소문자·숫자·하이픈', h('input', { class: 'ctl', value: draft.id, disabled: !isNew, oninput: (e) => { draft.id = e.target.value; saved = false; } })),
                field('설명', null, h('input', { class: 'ctl', value: draft.description, oninput: (e) => { draft.description = e.target.value; saved = false; } })),
                h('div', { class: 'two' }, field('kind', null, U.select(KINDS.map((k) => [k, k]), draft.kind, (v) => upd({ kind: v }), { class: 'ctl' })), field('action', null, U.select([['alert', 'alert — 알림'], ['kill', 'kill — 컨테이너 강제 종료']], draft.action, (v) => upd({ action: v }), { class: 'ctl' }))),
                FIELDS_BY_KIND[draft.kind].map(([f, label, hint]) => field(label, hint, NUM_FIELDS.includes(f)
                  ? h('input', { type: 'number', class: 'ctl num', 'data-field': f, min: NUM_RANGE[f][0], max: NUM_RANGE[f][1], placeholder: '비우면 조건 없음', value: draft.nums[f], oninput: (e) => { draft.nums[f] = e.target.value; saved = false; } })
                  : h('textarea', { class: 'ctl mono list', 'data-field': f, placeholder: '한 줄에 하나', value: draft.lists[f], oninput: (e) => { draft.lists[f] = e.target.value; saved = false; } }, draft.lists[f]))),
                draft.kind === 'connect' ? field('도메인 조회 없는 IP 직접 연결', 'directIp — trace_dns 가 켜져 있을 때만 판단, 비우면 옛 동작', U.select([['', '(비움)'], ['allow', 'allow — 통과'], ['alert', 'alert — 알림'], ['kill', 'kill — 격리']], draft.directIp || '', (v) => { draft.directIp = v; saved = false; }, { class: 'ctl', 'data-field': 'directIp' })) : null,
                field('적용 컨테이너', '이름 또는 이미지 glob, 비우면 전체 (예: pkg-*)', h('textarea', { class: 'ctl mono list short', 'data-field': 'containers', placeholder: '전체', value: draft.lists.containers, oninput: (e) => { draft.lists.containers = e.target.value; saved = false; } }, draft.lists.containers)),
                h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: draft.disabled, onchange: (e) => { draft.disabled = e.target.checked; saved = false; } }), ' 비활성화 (평가하지 않음)'));
          const seg = h('div', { class: 'seg', role: 'group', 'aria-label': '편집 방식' }, MODES.map(([m, label]) => h('button', { type: 'button', class: `seg-btn dark ${mode === m ? 'on' : ''}`, 'data-mode': m, 'aria-pressed': String(mode === m), onclick: () => switchMode(m) }, label)));
          if (mode === 'easy') sumEl.textContent = U.policyEasy.summarize(draft);
          replace(root,
            h('div', { class: 'editor-head' }, seg, mode === 'easy' ? (ctx.fresh ? h('span', { class: 'small tone-ok' }, `예외 ${o.fresh} 를 더했습니다 — 확인 후 저장하세요`) : null) : h('span', { class: 'small muted' }, '적용 결과: ', h('b', { class: draft.action === 'kill' && !draft.dryRun ? 'tone-danger' : 'tone-warn' }, effective))),
            h('div', { class: 'grow scroll pad' }, body),
            mode === 'easy' ? sumEl : null,
            h('div', { class: 'foot' },
              mode === 'form' ? h('label', { class: 'row-inline', title: 'kill 정책을 알림만 보내도록 강제 (오탐 시 컨테이너 보호)' }, U.switchEl(draft.dryRun, (on) => upd({ dryRun: on })), ' dry-run') : null,
              error ? h('span', { class: 'grow small tone-danger', title: error }, error) : saved ? h('span', { class: 'grow small tone-ok' }, '저장 후 엔진에 적용됨') : h('span', { class: 'grow' }),
              !isNew ? h('button', { type: 'button', class: 'btn btn-danger-ghost', disabled: !canWrite(), onclick: () => U.confirmDialog({ title: '정책 삭제', target: rule.id, okLabel: '삭제', reason: false,
                effects: [`엔진에서 ${rule.id} 를 빼 바로 적용합니다 — 이 정책에 걸리던 행동은 더 이상 알림 · 격리되지 않습니다`, '과거 감사 기록은 그대로 남습니다', '변경 이력에 「정책 편집」으로 남습니다'],
                undo: '「고급 · YAML」에서 지금 내용을 복사해 두면 새 정책으로 다시 만들 수 있습니다' })
                .then((ok) => ok && U.api.deleteRule(rule.id).then(() => U.api.listRules()).then(() => { U.toast(`정책 ${rule.id} 삭제됨`, { tone: 'warn' }); select(''); loadDefaults(); }).catch((e) => { error = errText(e); render(); })) }, '🗑 삭제') : null,
              h('button', { type: 'button', class: 'btn btn-primary', 'aria-label': '저장 전 확인', onclick: openCheck }, '저장 전 확인 →')));
        }
        function switchMode(next) {
          if (next === mode) return; error = '';
          try {
            if (next === 'yaml') yamlText = ruleToYaml(toRule(draft));
            else if (mode === 'yaml') { const p = parseYaml(yamlText); validateRule(p); if (!isNew && p.id !== rule.id) throw new Error('기존 정책의 id는 바꿀 수 없음 — 새 정책으로 만드세요'); draft = toDraft(p); }
            mode = next;
          } catch (e) { error = e.message; }
          render();
        }
        // 저장 전 확인 — 요약 + 지금 감사 로그를 이 정책으로 다시 평가한 결과. 저장은 여기서만
        function openCheck() {
          error = '';
          let r;
          try { r = current(); if (isNew && state.source === 'sim' && state.rules.some((x) => x.id === r.id)) throw new Error(`이미 있는 이름입니다: ${r.id} — ⑤ 에서 다른 이름을 쓰세요`); }
          catch (e) { error = e.message; render(); return; }
          check = { rule: r, preview: null };
          render();
          U.api.previewRule(r).then((pv) => { if (check && check.rule === r) { check.preview = pv; render(); } }).catch((e) => { if (check && check.rule === r) { check.preview = { error: e.message }; render(); } });
        }
        const LV = { normal: '통과', alert: '알림', held: '격리 대상', killed: '격리' };
        const LV_TO = { normal: '통과로', alert: '알림으로', held: '격리 대상으로', killed: '격리로' };
        function renderCheck() {
          const { rule: r, preview: pv } = check;
          const groups = pv && !pv.error ? Object.entries(pv.changed.reduce((m, x) => { const k = `${x.before}>${x.after}`; m[k] = (m[k] || 0) + 1; return m; }, {})) : [];
          replace(root, h('div', { class: 'grow scroll pad' }, h('section', { class: 'save-check', 'data-part': 'save-check' },
            h('h3', null, '저장 전 확인'),
            h('p', { class: 'summary-bar', 'data-summary': '' }, U.policyEasy.summarize(toDraft(r))),
            !pv ? h('p', { class: 'muted' }, '최근 감사 로그로 미리 계산하는 중…')
              : pv.error ? h('p', { class: 'small tone-warn' }, `미리보기를 계산하지 못했습니다 — ${pv.error}. 저장은 할 수 있습니다.`)
                : [h('p', { 'data-preview-count': '' }, `최근 감사 로그 ${fmt.num(pv.evaluated)}건을 이 정책으로 다시 평가 — 결과가 바뀌는 과거 위반 `, h('b', { class: 'num' }, `${pv.changed.length}건`)),
                  groups.length ? h('ul', { class: 'check-groups' }, groups.map(([k, n]) => { const [b, a] = k.split('>'); return h('li', null, `${LV[b]}에서 ${LV_TO[a]} 바뀜 `, h('b', { class: 'num' }, `${n}건`)); }))
                    : h('p', { class: 'small muted' }, '과거 기록 중 결과가 바뀌는 것은 없습니다. 저장한 뒤 들어오는 행동부터 적용됩니다.'),
                  pv.changed.length ? h('div', { class: 'preview-table' }, h('table', { class: 'table compact' }, h('thead', null, h('tr', null, ['#', '시각', '컨테이너', '지금 → 저장 후'].map((t) => h('th', null, t)))),
                    h('tbody', null, pv.changed.slice(0, 20).map((x) => { const a = state.audit.find((y) => y.id === x.auditId); return h('tr', null, h('td', { class: 'num muted' }, x.auditId), h('td', { class: 'num nowrap' }, a ? fmt.dateTime(a.event.timestamp) : '—'), h('td', { class: 'trunc-cell' }, x.container), h('td', { class: 'nowrap' }, `${LV[x.before]} → `, h('b', null, LV[x.after]))); })))) : null],
            h('div', { class: 'row-actions' },
              h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => { check = null; render(); } }, '← 고치기'),
              h('button', { type: 'button', class: 'btn btn-primary', 'aria-label': '저장 후 적용', disabled: !canWrite(), onclick: () => save(r) }, '저장 후 적용 ▶')))));
        }
        function save(r) {
          U.api.saveRule(r).then((savedRule) => U.api.listRules().then(() => savedRule || r)).then((sr) => { draft = toDraft(sr); saved = true; check = null; ctx.fresh = null; pendingDefault = null; renderNav(); loadDefaults(); U.toast(`정책 ${sr.id} 저장 — 엔진에 바로 적용`, { tone: 'ok' }); if (isNew) select(sr.id); else render(); })
            .catch((e) => { error = errText(e); check = null; render(); });
        }
        render();
        if (o.autoCheck) openCheck(); // 새 기본 규칙: 바로 저장 전 확인 [10/20 F]
        return root;
      }
      // 처음 열면: 적용할 제안이 있으면 맨 위 제안, 없으면 첫 정책 [10/15 확정 · 10/15 목표] — 빈 편집 영역을 보이지 않는다
      let first = true;
      function pickFirst() {
        if (!first) return; first = false;
        if (selected || proposalId) return;
        if (drafts.length) { proposalId = drafts[0].id; U.setQuery({ proposal: proposalId }); return; }
        if (state.rules.length) { selected = state.rules[0].id; U.setQuery({ id: selected }); }
      }
      let sig = '';
      function load() {
        return Promise.all([U.api.listRules().catch((e) => e), U.api.proposals({}).catch((e) => e), U.api.blocklist().catch((e) => e), U.api.cases({}).catch(() => []), U.api.changes({ limit: 50 }).catch((e) => e)]).then(([rs, ps, bl, cs, ch]) => {
          if (rs instanceof Error) replace(list, h('p', { class: 'pad tone-danger small' }, `불러오기 실패: ${errText(rs)}`));
          propErr = ps instanceof Error ? ps : null; allProps = propErr ? [] : ps; drafts = allProps.filter((p) => p.state === 'draft');
          changes = ch instanceof Error ? [] : ch;
          blErr = bl instanceof Error ? bl : null; blocklist = blErr ? null : bl; cases = cs;
          sig = sigOf([allProps.map((p) => [p.id, p.state]), blocklist, state.rules.length]);
          pickFirst(); renderNav(); renderEditor();
          if (focusBlocklist) { focusBlocklist = false; showBlocklist(); }
        });
      }
      renderNav(); load();
      return { update() {
        // 다른 화면 · 토스트에서 판정 · 적용이 일어나면 목록만 새로 그린다(편집 중인 폼은 건드리지 않는다)
        if (state.source === 'sim') { const next = sigOf([state.proposals.map((p) => [p.id, p.state]), state.blocklist, state.rules.length]); if (next !== sig) { sig = next; Promise.all([U.api.proposals({}), U.api.blocklist(), U.api.cases({}), U.api.changes({ limit: 50 })]).then(([ps, bl, cs, ch]) => { allProps = ps; drafts = ps.filter((p) => p.state === 'draft'); blocklist = bl; cases = cs; changes = ch; renderNav(); }); } }
      } };
    },
  };

  // ── 감사 로그 — 「언제 무엇이 걸렸고, 어떻게 닫혔나?」 [10/15 목표] ──
  // 위반 기록(판정 결과 열: 판정 대기 · 악성 · 오탐 · 건 없음) ↔ 판정 · 변경 이력(?view=changes). 기간 조회는 여기에만 있다.
  // 페이지는 고정 · 표만 스크롤, 사유 · 이미지 · 컨테이너 ID 는 행 상세 시트로 [10/15 확정]
  const CHANGE_KIND = { proposal_applied: '제안 적용', policy_edit: '정책 편집', policy_replace: '정책 전체 교체', blocklist_remove: '차단 해제', demo_run: '시연 실행' }; // demo_run [10/30 계약 §2 ⑦]
  U.screens['/audit'] = {
    title: '감사 로그',
    mount(page, query) {
      const PAGE = 100;
      // 필터(kind · action · rule · container · since · until)는 화면 상태만 — 주소에 남기지 않는다 [10/20 D · 10/21b]
      const f = { kind: query.get('kind') || '', action: query.get('action') || '', rule: query.get('rule') || '', container: query.get('container') || '', since: query.get('since') || '', until: query.get('until') || '' };
      let view = query.get('view') === 'changes' ? 'history' : 'violations'; // 주소 값은 React 와 같게 changes(옛 history 는 takeQuery 가 바꿔 준다) [10/21b]
      let rows = [], hasMore = false, loading = false, timer, seq = 0, selId = Number(query.get('id')) || null, cases = new Map(), casesErr = null;
      let loaded = false, lastErr = null, sheetTab = query.get('tab') === 'evidence' ? 'evidence' : 'detail';
      const tbody = h('tbody');
      const more = h('div', { class: 'more', hidden: true }, h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => fetchPage(rows.length ? rows[rows.length - 1].id : undefined) }, '더 보기'));
      const table = h('table', { class: 'table', 'data-table': 'audit' }, h('thead', null, h('tr', null, ['#', '시각', '컨테이너', '종류', '상세', '규칙', '탐지 결과', '판정'].map((t) => h('th', null, t)))), tbody);
      const stateSlot = h('div', { class: 'list-slot' }, U.skeleton(8));
      const applied = h('div');
      const noteSlot = h('div'); // 데이터가 있는데 다시 부르기만 실패 — 작은 오류 띠 [10/21 React 맞춤]
      const wrap = h('div', { class: 'grid-scroll' }, noteSlot, stateSlot, table, more);
      table.hidden = true;
      const histNote = h('div'), histBody = h('div');
      const hist = h('div', { class: 'grid-scroll', hidden: true }, histNote, histBody);
      let histLoaded = false; // 변경 이력을 한 번이라도 받았는지 — 받았으면 다시 부르기 실패는 띠, 못 받았으면 오류 칸 + 자동 재시도
      const sheetSlot = h('div', { class: 'sheet-slot' });
      const toIso = (v) => (v ? new Date(v).toISOString() : '');
      function fetchPage(before) {
        const my = ++seq; loading = true; refresh.classList.add('spin');
        Promise.all([U.api.audit({ kind: f.kind, action: f.action, rule: f.rule, container: f.container, since: toIso(f.since), until: toIso(f.until), limit: PAGE, before }), U.api.cases({}).catch((e) => e)])
          .then(([pageRows, cs]) => { if (my !== seq) return; casesErr = cs instanceof Error ? cs : null; cases = new Map((casesErr ? [] : cs).map((c) => [c.id, c])); rows = before ? rows.concat(pageRows) : pageRows; hasMore = pageRows.length === PAGE; lastErr = null; loaded = true; loading = false; draw(); })
          .catch((e) => { if (my !== seq) return; lastErr = e; loading = false; draw(); }) // loaded 는 받은 적이 있을 때만 true — 있으면 목록 유지 + 띠
          .finally(() => { loading = false; refresh.classList.remove('spin'); });
      }
      const FILTER_KEYS = ['kind', 'action', 'rule', 'container', 'since', 'until'];
      const setF = (k) => (v) => { f[k] = v; exportErr.hidden = true; clearTimeout(timer); timer = setTimeout(() => fetchPage(), 300); drawChips(); }; // 필터 변경 300ms 뒤 첫 페이지부터
      // CSV 내보내기 [10/20 D] — 기간(시작 · 끝)이 있어야 한다. 지금 필터 그대로, 최대 10,000행(실제 백엔드는 1,000행씩 나눠 받는다)
      const exportErr = h('span', { class: 'small tone-danger', 'data-part': 'export-error', role: 'alert', hidden: true });
      function exportCsv() {
        if (!f.since || !f.until) { exportErr.hidden = false; exportErr.textContent = '기간(시작 · 끝)을 먼저 고르세요 — 내보내기는 기간 안의 기록만 담습니다'; return; }
        exportErr.hidden = true;
        const q = { kind: f.kind, action: f.action, rule: f.rule, container: f.container, since: toIso(f.since), until: toIso(f.until) };
        const all = [];
        const page2 = (before) => U.api.audit(Object.assign({}, q, { limit: 1000, before })).then((rs) => { all.push(...rs); return rs.length === 1000 && all.length < 10000 ? page2(rs[rs.length - 1].id) : all; });
        Promise.all([page2(undefined), U.api.cases({}).catch(() => [])]).then(([rs, cs]) => {
          const byId = new Map(cs.map((c) => [c.id, c]));
          const day = (v) => v.slice(0, 10).replace(/-/g, '');
          U.downloadCSV(`supplyguard-audit-${day(f.since)}-${day(f.until)}.csv`, [['id', '시각', '컨테이너', '이미지', '종류', '상세', '규칙', '탐지 결과', '판정', '사유'],
            ...rs.map((a) => { const c = a.caseId ? byId.get(a.caseId) : null; return [a.id, a.event.timestamp, a.install ? a.install.label : a.event.containerName, a.event.imageName, a.event.kind, detailOf(a.event), a.ruleId, U.LEVEL_LABEL[levelOf(a)], U.DECISION_LABEL[c ? c.decision : 'none'], a.reason]; })]);
          U.toast(`감사 로그 ${fmt.num(rs.length)}행을 CSV 로 내려받았습니다`, { tone: 'ok', key: 'csv', replace: true });
        }).catch((e) => { exportErr.hidden = false; exportErr.textContent = `내보내기 실패 — ${e.message}`; });
      }
      const refresh = h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => (view === 'history' ? loadHistory() : fetchPage()) }, '⟳ 새로고침');
      const select = (id) => { selId = id; sheetTab = 'detail'; U.setQuery({ id: id || '', tab: '' }); draw(); };
      const seg = h('div', { class: 'seg', role: 'group', 'aria-label': '보기' });
      const filters = h('div', { class: 'filters' },
        U.select([['', '종류 전체'], ...KINDS.map((k) => [k, k === 'dns' ? 'dns (도메인 조회)' : k])], f.kind, setF('kind'), { 'aria-label': '종류' }),
        U.select([['', '대응 전체'], ['alert', '경고'], ['kill', '격리']], f.action, setF('action'), { 'aria-label': '대응' }),
        h('input', { class: 'ctl w-40', placeholder: '규칙 id', 'aria-label': '규칙 id', value: f.rule, oninput: (e) => setF('rule')(e.target.value) }),
        h('input', { class: 'ctl w-40', placeholder: '컨테이너', 'aria-label': '컨테이너', value: f.container, oninput: (e) => setF('container')(e.target.value) }),
        h('label', null, '기간 ', h('input', { type: 'datetime-local', class: 'ctl', 'aria-label': '시작', value: f.since, onchange: (e) => setF('since')(e.target.value) }), ' ~ ', h('input', { type: 'datetime-local', class: 'ctl', 'aria-label': '끝', value: f.until, onchange: (e) => setF('until')(e.target.value) })),
        h('span', { class: 'push-right row-inline' }, exportErr, h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': 'export-csv', title: '지금 필터 · 기간의 위반 기록을 CSV 로' }, '⤓ CSV 내보내기')));
      filters.querySelector('[data-action="export-csv"]').addEventListener('click', exportCsv);
      const ACTION_KO = { alert: '경고', kill: '격리' };
      const fdt = (v) => v.replace('T', ' ');
      function drawChips() {
        replace(applied, U.filterChips([f.kind ? { key: 'kind', label: `종류: ${f.kind}`, clear: () => clearFilter(f, ['kind']) } : null,
          f.action ? { key: 'action', label: `대응: ${ACTION_KO[f.action] || f.action}`, clear: () => clearFilter(f, ['action']) } : null,
          f.rule ? { key: 'rule', label: `규칙: ${f.rule}`, clear: () => clearFilter(f, ['rule']) } : null,
          f.container ? { key: 'container', label: `컨테이너: ${f.container}`, clear: () => clearFilter(f, ['container']) } : null,
          f.since || f.until ? { key: 'period', label: `기간: ${f.since ? fdt(f.since) : '처음'} ~ ${f.until ? fdt(f.until) : '지금'}`, clear: () => clearFilter(f, ['since', 'until']) } : null], () => clearFilter(f, FILTER_KEYS)));
      }
      const title = h('span');
      page.append(h('div', { class: 'split' }, panel({ title, class: 'grow', actions: [seg, refresh], body: h('div', { class: 'col' }, filters, applied, wrap, hist) }), sheetSlot));
      drawChips();
      function setView(v) { view = v; U.setQuery({ view: v === 'history' ? 'changes' : '', id: '' }); selId = null; syncView(); }
      function syncView() {
        title.textContent = view === 'history' ? '판정 · 변경 이력' : '위반 기록';
        replace(seg, [['violations', '위반 기록'], ['history', '판정 · 변경 이력']].map(([v, label]) => h('button', { type: 'button', class: `seg-btn ${view === v ? 'on' : ''}`, 'data-view-btn': v, 'aria-pressed': String(view === v), onclick: () => setView(v) }, label)));
        filters.hidden = view === 'history'; applied.hidden = view === 'history'; wrap.hidden = view === 'history'; hist.hidden = view !== 'history';
        if (view === 'history') { replace(sheetSlot); loadHistory(); } else draw();
      }
      // 설치 검사 컨테이너의 위반은 컨테이너 이름 대신 패키지 이름으로 보인다
      const who = (a) => (a.install ? h('span', { 'data-pkg': '', class: 'strong', title: a.event.containerName }, h('span', { class: 'mgr' }, a.install.label.split(' ')[0]), ' ', a.install.label.split(' ').slice(1).join(' '))
        : h('span', { class: 'strong', title: `${a.event.imageName} · ${fmt.shortId(a.event.containerId)}` }, a.event.containerName));
      const decisionCell = (a) => { if (casesErr) return h('span', { class: 'muted' }, '—'); const c = a.caseId ? cases.get(a.caseId) : null; return U.decisionBadge(c ? c.decision : null); };
      // 증거 탭 [10/20 I] — 격리된 행만. GET /api/evidence?container= (최근 것부터) 에서 이 컨테이너 ID 의 것을, 없으면 가장 최근 것
      function evidenceView(a) {
        const box = h('div', { class: 'col-gap', 'data-part': 'evidence' }, h('p', { class: 'small muted' }, '불러오는 중…'));
        U.api.evidence(a.event.containerName).then((list) => {
          const ev = list.find((x) => x.containerId === a.event.containerId) || list[0];
          if (!ev) { replace(box, U.emptyState({ icon: '▤', title: '모은 증거가 없습니다', hint: '격리 직전에 모은 기록이 없습니다 — 옛 버전에서 격리했거나 dry-run 이었습니다.' })); return; }
          replace(box,
            h('div', { class: 'row-inline' }, h('span', { class: 'small muted num' }, `${fmt.dateTime(ev.collectedAt)} · ${ev.durationMs}ms 동안 모음 · ${ev.image}`),
              ev.partial ? h('span', { class: 'badge badge-alert', 'data-part': 'evidence-partial', title: ev.error }, '일부만 모음') : h('span', { class: 'badge badge-level-normal' }, '모두 모음')),
            ev.partial && ev.error ? h('p', { class: 'small tone-warn' }, ev.error) : null,
            h('section', { class: 'sheet-section' }, h('h3', null, '로그 ', h('span', { class: 'small muted' }, '— 마지막 200줄')), h('pre', { class: 'json ev-logs', 'data-part': 'evidence-logs' }, ev.logs || '(비어 있음)')),
            h('section', { class: 'sheet-section' }, h('h3', null, `파일 변경 ${ev.changes.length}`, h('span', { class: 'small muted' }, ' — docker diff (A 추가 · C 변경 · D 삭제)')),
              ev.changes.length ? h('table', { class: 'table compact', 'data-part': 'evidence-changes' }, h('thead', null, h('tr', null, h('th', null, '종류'), h('th', null, '경로'))), h('tbody', null, ev.changes.map((x) => h('tr', null, h('td', { class: `mono ev-${x.kind}` }, x.kind), h('td', { class: 'mono small' }, x.path)))))
                : h('p', { class: 'small muted', 'data-part': 'evidence-changes' }, '없음')),
            h('section', { class: 'sheet-section' }, h('h3', null, `프로세스 ${ev.processes.length}`, h('span', { class: 'small muted' }, ' — docker top')),
              ev.processes.length ? h('table', { class: 'table compact', 'data-part': 'evidence-procs' }, h('thead', null, h('tr', null, ['PID', '사용자', '명령'].map((t) => h('th', null, t)))), h('tbody', null, ev.processes.map((p) => h('tr', null, h('td', { class: 'num' }, p.pid), h('td', null, p.user), h('td', { class: 'mono small' }, p.cmd)))))
                : h('p', { class: 'small muted', 'data-part': 'evidence-procs' }, ev.partial ? '모으지 못함 — 위 안내 참고' : '없음')));
        }).catch((e) => replace(box, U.errorState(e, () => replace(box, evidenceView(a)), { what: '증거' }))); // 증거는 자동 재시도 유지 [10/21 결정 ⑥]
        return box;
      }
      function auditSheet(a) {
        const c = a.caseId ? cases.get(a.caseId) : null;
        const killed = levelOf(a) === 'killed';
        const tab = killed ? sheetTab : 'detail';
        const setTab = (t) => { sheetTab = t; U.setQuery({ tab: t === 'evidence' ? 'evidence' : '' }); draw(); };
        const tabs = killed ? h('div', { class: 'seg sheet-tabs', role: 'tablist', 'aria-label': '보기' }, [['detail', '상세'], ['evidence', '증거']].map(([k, ko]) => h('button', { type: 'button', role: 'tab', class: `seg-btn ${tab === k ? 'on' : ''}`, 'data-tab': k, 'aria-selected': String(tab === k), onclick: () => setTab(k) }, ko))) : null;
        if (tab === 'evidence') return U.sheet({ kind: 'audit', title: `감사 기록 #${a.id}`, onClose: () => select(null), body: [tabs, evidenceView(a)] });
        return U.sheet({ kind: 'audit', title: `감사 기록 #${a.id}`, onClose: () => select(null), body: [tabs,
          h('dl', { class: 'dl' },
            h('dt', null, '탐지 결과'), h('dd', null, verdictBadge(a)),
            h('dt', null, '판정'), h('dd', null, decisionCell(a), c && c.decidedAt ? h('span', { class: 'small muted num' }, `  ${c.decidedBy} · ${fmt.dateTime(c.decidedAt)}`) : null, c ? h('span', { class: 'small muted' }, `  (건 ${c.id})`) : null),
            h('dt', null, '시각'), h('dd', { class: 'num' }, fmt.dateTime(a.event.timestamp)),
            h('dt', null, '사유'), h('dd', null, a.reason || '—'),
            a.enforceError ? [h('dt', null, '격리 오류'), h('dd', { class: 'tone-danger' }, a.enforceError)] : null,
            h('dt', null, '컨테이너'), h('dd', { class: 'mono' }, a.event.containerName),
            h('dt', null, '컨테이너 ID'), h('dd', { class: 'mono' }, fmt.shortId(a.event.containerId)),
            h('dt', null, '이미지'), h('dd', { class: 'mono' }, a.event.imageName),
            h('dt', null, '상세'), h('dd', { class: 'mono' }, detailOf(a.event)),
            a.event.kind === 'connect' ? dnsRow(a.event) : null),
          !c && levelOf(a) === 'alert' && !a.install ? h('p', { class: 'small muted' }, '런타임 경고는 판정할 건을 열지 않습니다(격리 · 격리 대상만).') : null,
          h('div', { class: 'row-actions' },
            a.install ? h('a', { ...U.to(`#/installs?id=${a.install.id}`, { status: 'all' }), class: 'btn btn-ghost btn-xs' }, '설치 검사에서 보기 →') : null,
            c && c.source === 'runtime' ? h('a', { ...U.to(U.topoLink(c.container)), class: 'btn btn-ghost btn-xs' }, '토폴로지 →') : null,
            a.ruleId ? h('a', { href: `#/policies?id=${encodeURIComponent(a.ruleId)}`, class: 'btn btn-ghost btn-xs' }, '정책 보기 →') : null),
          policyStarts(a)] });
      }
      function draw() {
        if (view !== 'violations') return;
        const filtered = FILTER_KEYS.some((k) => f[k]);
        const failing = !!lastErr && !loaded; // React AuditPage: 받은 적이 없을 때만 오류 칸(+ 다시 시도 · 30초 자동 재시도), 받은 적이 있으면 목록 위 작은 띠
        table.hidden = !loaded || rows.length === 0; more.hidden = !hasMore || !!lastErr;
        replace(noteSlot, lastErr && loaded ? U.loadErrorNote(lastErr, '감사 로그') : null);
        replace(stateSlot, failing ? U.errorState(lastErr, () => fetchPage(), { what: '감사 로그' }) : !loaded ? U.skeleton(8)
          : rows.length ? null : filtered ? U.emptyState({ icon: '⌕', title: '조건에 맞는 기록 없음', actions: h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => clearFilter(f, FILTER_KEYS) }, '필터 모두 해제') })
            : U.emptyState({ icon: '◷', title: '아직 감사 기록이 없습니다', hint: '정책에 걸린 행동(위반)만 여기에 쌓입니다.' }));
        replace(tbody, rows.map((a) => U.rowKeys(h('tr', { class: `clickable ${a.id === selId ? 'selected' : ''}`, 'data-audit': a.id, onclick: () => select(a.id) },
          h('td', { class: 'num muted right' }, a.id),
          h('td', { class: 'num mono nowrap' }, fmt.dateTime(a.event.timestamp)),
          h('td', { class: 'c-container nowrap' }, who(a)),
          h('td', null, kindBadge(a.event.kind)),
          h('td', { class: 'mono small trunc', title: detailOf(a.event) }, detailOf(a.event)),
          h('td', { class: 'mono small nowrap' }, a.ruleId),
          h('td', null, verdictBadge(a)),
          h('td', null, decisionCell(a))), () => select(a.id))));
        const cur = rows.find((a) => a.id === selId);
        replace(sheetSlot, cur ? auditSheet(cur) : null);
      }
      // 판정 · 변경 이력 — 판정(건) · 제안 적용 · 제안 버림 · 정책 편집 · 차단 해제를 시간순 하나로
      function loadHistory() {
        if (!histLoaded && !histBody.querySelector('[data-part="error"]')) replace(histBody, U.skeleton(6));
        Promise.all([U.api.cases({}), U.api.changes({ limit: 500 }), U.api.proposals({ state: 'discarded' }), U.api.installs().catch(() => [])]).then(([cs, chs, discarded, ins]) => {
          histLoaded = true; replace(histNote);
          const target = (c) => (c ? caseTarget(c, ins) : '—');
          const byId = new Map(cs.map((c) => [c.id, c]));
          const items = [
            ...cs.filter((c) => c.decidedAt && c.decision !== 'pending').map((c) => ({ at: c.decidedAt, by: c.decidedBy, what: c.decision === 'malicious' ? '판정: 악성 확정' : '판정: 오탐', tone: c.decision, caseId: c.id, target: target(c), detail: (c.proposalId ? `제안 ${c.proposalId} 초안` : '') + (c.note ? ` · 사유 「${c.note}」` : '') })),
            ...chs.map((x) => ({ at: x.at, by: x.by, what: CHANGE_KIND[x.kind] || x.kind, tone: x.kind, caseId: x.caseId, target: target(byId.get(x.caseId)), detail: x.summary + (x.proposalId ? ` · 제안 ${x.proposalId}` : ''), reason: x.reason })),
            ...discarded.map((p) => { const c = byId.get(p.caseId); return { at: (c && c.closedAt) || p.createdAt, by: p.createdBy, what: '제안 버림', tone: 'discarded', caseId: p.caseId, target: target(c), detail: `제안 ${p.id} — 변경 없이 종결`, reason: p.reason }; }),
          ].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
          replace(histBody, items.length ? h('table', { class: 'table', 'data-table': 'history' }, h('thead', null, h('tr', null, ['시각', '처리자', '한 일', '대상', '내용', '건'].map((t) => h('th', null, t)))),
            h('tbody', null, items.map((x) => { const c = byId.get(x.caseId); return h('tr', { 'data-kind': x.tone, 'data-case': x.caseId || '', 'data-source': c ? c.source : '' },
              h('td', { class: 'num mono nowrap' }, fmt.dateTime(x.at)), h('td', { class: 'nowrap' }, x.by),
              h('td', { class: 'nowrap' }, h('span', { class: `hist-what hist-${x.tone}` }, x.what)),
              h('td', { class: 'small trunc', title: x.target }, c ? sourceChip(c.source) : null, ' ', h('span', { class: 'mono' }, x.target)),
              h('td', { class: 'small trunc', title: x.detail + (x.reason ? ` · 사유 「${x.reason}」` : '') }, x.detail, x.reason ? ` · 사유 「${x.reason}」` : ''),
              h('td', { class: 'mono small nowrap' }, c ? h('a', { ...U.to(U.caseLink(c, true)), class: 'link' }, x.caseId) : x.caseId || '—')); })))
            : empty('판정 · 변경 이력 없음'));
        }).catch((e) => { if (view !== 'history') return; // 받은 적이 있으면 목록 유지 + 띠, 없으면 오류 칸 + 다시 시도 · 30초 자동 재시도 [10/21 React 맞춤]
          if (histLoaded) replace(histNote, U.loadErrorNote(e, '변경 이력')); else replace(histBody, U.errorState(e, () => loadHistory(), { what: '변경 이력' })); });
      }
      syncView();
      fetchPage();
      return {};
    },
  };
})();
