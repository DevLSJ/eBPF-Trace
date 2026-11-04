// SupplyGuard 목업 — 11/04e 공통 부품(UI 업그레이드). 외부 라이브러리 없음, 색은 전부 토큰(styles.css 「11/04e」 블록).
//   U.kpiCard   KPI 카드: 왼쪽 4px 띠(종류) · 오른쪽 위 아이콘 칩 · 이름 · 값(28/700, 단위 분리) · 증감 줄 · 보조 줄. 처음엔 바로 값, 바뀌면 600ms 카운트업 + 짧은 링
//   U.tableKit  표 도구: 머리 클릭 정렬(aria-sort) · 아래 쪽 번호 바닥줄(「1–20 / 45 · 페이지당 20▾ · 쪽 단추」) · 재조회 진행 띠(이전 데이터 유지)
//   U.lineChart · U.stackBars · U.donut  차트: 점선 가로 격자만 · y축 선 없음 · 축 글자 12 · 반전 툴팁 · 첫 렌더에만 그리기 애니메이션(reduced-motion 이면 없음)
(function () {
  'use strict';
  const U = window.UI;
  const { h, s, replace, fmt } = U;
  const motion = () => !U.reducedMotion();

  // ── 반전 툴팁(ink 바탕) — 차트 상자 안에서 마우스를 따라간다 ──
  function tipLayer(root) {
    const tip = h('div', { class: 'chart-tip tip-inverse', hidden: true, role: 'tooltip', 'data-part': 'chart-tip' });
    root.append(tip);
    const place = (x, y) => {
      const r = root.getBoundingClientRect(), w = tip.offsetWidth, hh = tip.offsetHeight;
      let left = x - r.left + 14; if (left + w > r.width) left = Math.max(0, x - r.left - w - 14);
      let top = y - r.top - hh - 10; if (top < 0) top = Math.min(r.height - hh, y - r.top + 14);
      tip.style.left = `${left}px`; tip.style.top = `${Math.max(0, top)}px`;
    };
    return {
      show(e, title, rows) { replace(tip, h('div', { class: 'tip-title' }, title), rows.map(([cls, text]) => h('div', { class: 'tip-row' }, cls ? h('i', { class: `sw ${cls}` }) : null, text))); tip.hidden = false; place(e.clientX, e.clientY); },
      hide() { tip.hidden = true; },
    };
  }
  // 첫 렌더에만 그리기 애니메이션 — 끝나면 클래스를 뗀다(다시 그릴 때는 붙이지 않는다)
  function drawIn(el) { if (!motion()) return; el.classList.add('draw-in'); const off = () => el.classList.remove('draw-in'); el.addEventListener('animationend', off, { once: true }); setTimeout(off, 900); }
  // 눈금: 1 · 2 · 5 × 10^k 로 3칸 안팎
  function niceMax(v, n) { const raw = Math.max(1, v) / (n || 3), e = Math.pow(10, Math.floor(Math.log10(raw))), f = raw / e, st = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * e; return { step: st, max: Math.max(st, Math.ceil(Math.max(1, v) / st) * st) }; }
  const short = (n) => (n >= 10000 ? `${Math.round(n / 1000)}k` : n >= 1000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k` : fmt.num(n));
  // x 축 글자: 칸 폭으로 몇 칸마다 하나씩 쓸지 — 글자(약 40px)가 서로 겹치지 않게
  const everyFor = (n, iw, labelW) => Math.max(1, Math.ceil(n / Math.max(1, Math.floor(iw / (labelW || 52)))));
  const tickText = (t, step) => (step >= 21600 ? `${new Date(t).getMonth() + 1}/${new Date(t).getDate()}` : fmt.time(t).slice(0, 5));

  // ── KPI 카드 ──
  // o = { key, label, icon, stripe(accent|info|danger|warn|ok), value(숫자 · 없으면 null), text?(숫자 대신 글자, 예 「—」), unit?, tone?(값 > 0 일 때 숫자 색: danger 등),
  //       delta?: { dir: up|down|flat|none, text, tone: danger|warn|ok|neutral, note }, sub, link(주소 · {href,state}), prev?(직전 값 — 다르면 카운트업 + 링), attrs? }
  function kpiCard(o) {
    const zero = o.value === 0 || o.value == null;
    const val = h('b', { class: `kpi-val num tone-${!zero && o.tone ? o.tone : 'default'}`, 'data-value': '' }, o.text != null ? o.text : fmt.num(o.value));
    if (o.text == null && Number.isFinite(o.value)) {
      if (Number.isFinite(o.prev) && o.prev !== o.value) { val.dataset.countup = String(o.prev); U.countUp(val, o.value); } else val.dataset.countup = String(o.value);
    }
    const d = o.delta || { dir: 'none', text: '', tone: 'neutral' };
    const arrow = d.dir === 'up' ? '▲' : d.dir === 'down' ? '▼' : '—';
    const delta = h('div', { class: `kpi-delta tone-${d.tone || 'neutral'}`, 'data-delta': d.dir, 'data-delta-tone': d.tone || 'neutral' },
      d.dir === 'none' ? h('small', { class: 'kpi-note' }, d.note || '이전 기간 정보 없음') : [h('b', { class: 'num' }, `${arrow} ${d.text}`), d.note ? h('small', { class: 'kpi-note' }, d.note) : null]);
    const attrs = Object.assign({ class: `ov-kpi kpi-card stripe-${o.stripe || 'accent'}${zero ? ' is-zero' : ''}`, 'data-kpi': o.key }, o.attrs || {});
    const body = [h('span', { class: 'kpi-name' }, o.label), h('i', { class: 'kpi-ico', 'data-icon': o.icon || '▦', 'aria-hidden': 'true' }),
      h('div', { class: 'kpi-num' }, val, o.unit ? h('small', { class: 'kpi-unit' }, o.unit) : null), delta, h('span', { class: 'kpi-sub' }, o.sub || '')];
    const el = o.link ? h('a', Object.assign(attrs, U.to(o.link)), body) : h('div', attrs, body);
    // 값이 바뀌면 짧은 링 — 붙인 뒤에 클래스를 줘서(속성 변화) 애니메이션이 한 번 돈다
    if (Number.isFinite(o.prev) && Number.isFinite(o.value) && o.prev !== o.value) requestAnimationFrame(() => { el.classList.add('kpi-ring'); setTimeout(() => el.classList.remove('kpi-ring'), 900); });
    return el;
  }
  // 증감: cur − prev. tone(dir) — 위반 증가 같은 위험만 빨강, 그 밖은 중립 · 경고
  function delta(cur, prev, { up = 'neutral', down = 'neutral', unit = '', note = '' } = {}) {
    if (!Number.isFinite(cur) || !Number.isFinite(prev)) return { dir: 'none', note: '이전 기간 정보 없음' };
    const d = cur - prev;
    if (!d) return { dir: 'flat', text: '변화 없음', tone: 'neutral', note };
    return { dir: d > 0 ? 'up' : 'down', text: `${fmt.num(Math.abs(d))}${unit}`, tone: d > 0 ? up : down, note };
  }

  // ── 표 도구 ──
  // columns: [{ key, label, sort?: (row) => 값 | null(정렬 안 함), num?, cls? }]. sort: { key, dir } 기본 정렬(목록 순서와 같은 값으로 두면 처음 모습 그대로)
  // 화면은 kit.thead 를 표에, kit.busyEl 을 몸통 위에, kit.foot 를 몸통 아래(채움 칸 밖)에 둔다. 그리기마다 rows = kit.view(list) — 정렬 · 자른 목록
  // server 모드(감사 로그): 화면이 kit.server({ total, offset, count, hasNext }) 로 알리고, 쪽 이동은 onPage({ page, size, dir }) 로 받는다
  function tableKit({ name, columns, sort, size = 20, sizes = [20, 50, 100], server = false, onChange, onPage }) {
    const st = { key: (sort && sort.key) || null, dir: (sort && sort.dir) || 'asc', page: 1, size, total: 0, srv: null };
    const ths = columns.map((c) => {
      const th = h('th', { 'data-col': c.key, class: `${c.num ? 'num-col ' : ''}${c.cls || ''}`.trim() || null, scope: 'col' });
      if (c.sort) { th.append(h('button', { type: 'button', class: 'th-sort', onclick: () => toggle(c.key) }, c.label)); } else th.append(c.label);
      return th;
    });
    const thead = h('thead', null, h('tr', null, ths));
    const busyEl = h('div', { class: 'tk-busy', 'data-part': 'busy', hidden: true, 'aria-hidden': 'true' }, h('i'));
    const range = h('span', { class: 'num', 'data-part': 'range' });
    const sizeSel = h('select', { class: 'ctl tk-size', 'data-part': 'page-size', 'aria-label': '페이지당 행 수', onchange: (e) => { st.size = Number(e.target.value); st.page = 1; changed('size'); } }, sizes.map((n) => h('option', { value: n, selected: n === st.size }, n)));
    const pages = h('nav', { class: 'tk-pages', 'aria-label': '쪽' });
    const foot = h('div', { class: 'tk-foot', 'data-table-foot': name }, h('div', { class: 'tk-pager', 'data-part': 'pager' }, range, h('span', { class: 'tk-dot', 'aria-hidden': 'true' }, '·'), h('label', { class: 'tk-size-label' }, '페이지당 ', sizeSel), pages));
    function syncHead() { for (const th of ths) { const c = columns.find((x) => x.key === th.dataset.col); if (!c.sort) continue; th.setAttribute('aria-sort', st.key === c.key ? (st.dir === 'asc' ? 'ascending' : 'descending') : 'none'); } }
    function toggle(key) { if (st.key === key) st.dir = st.dir === 'asc' ? 'desc' : 'asc'; else { st.key = key; st.dir = 'asc'; } st.page = 1; syncHead(); changed('sort'); }
    function changed(why) { if (server && why !== 'sort') { if (onPage) onPage({ page: st.page, size: st.size, why }); } else if (onChange) onChange(why); }
    const cmp = (a, b) => { if (a == null && b == null) return 0; if (a == null) return 1; if (b == null) return -1; return typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b), 'ko', { numeric: true }); };
    function sorted(list) {
      const c = columns.find((x) => x.key === st.key); if (!c || !c.sort) return list.slice();
      const m = list.map((r, i) => [c.sort(r), i, r]);
      m.sort((x, y) => { const v = cmp(x[0], y[0]); return (st.dir === 'asc' ? v : -v) || x[1] - y[1]; });
      return m.map((x) => x[2]);
    }
    function pageBtn(label, p, opts = {}) { return h('button', { type: 'button', class: `tk-page ${opts.cur ? 'on' : ''}`, 'data-page': opts.key || String(p), 'aria-current': opts.cur ? 'page' : null, 'aria-label': opts.aria || `${p}쪽`, disabled: opts.disabled || null, onclick: () => { if (opts.dir) { if (opts.onDir) opts.onDir(); return; } st.page = p; changed('page'); } }, label); }
    function drawPager(total, from, to, { hasPrev, hasNext, known }) {
      range.textContent = !total && known ? '0건' : known ? `${from}–${to} / ${fmt.num(total)}` : `${from}–${to}`;
      if (known) {
        const n = Math.max(1, Math.ceil(total / st.size)), p = st.page, nums = [];
        const add = (x) => { if (!nums.includes(x) && x >= 1 && x <= n) nums.push(x); };
        add(1); for (let x = p - 1; x <= p + 1; x++) add(x); add(n); nums.sort((a, b) => a - b);
        const out = [pageBtn('‹', p - 1, { key: 'prev', aria: '이전 쪽', disabled: p <= 1 })];
        nums.forEach((x, i) => { if (i && x - nums[i - 1] > 1) out.push(h('span', { class: 'tk-gap', 'aria-hidden': 'true' }, '…')); out.push(pageBtn(String(x), x, { cur: x === p })); });
        out.push(pageBtn('›', p + 1, { key: 'next', aria: '다음 쪽', disabled: p >= n }));
        replace(pages, total ? out : null);
      } else replace(pages, pageBtn('‹ 이전', 0, { key: 'prev', aria: '이전 쪽', disabled: !hasPrev, dir: true, onDir: () => { st.page = Math.max(1, st.page - 1); if (onPage) onPage({ page: st.page, size: st.size, why: 'prev' }); } }),
        pageBtn('다음 ›', 0, { key: 'next', aria: '다음 쪽', disabled: !hasNext, dir: true, onDir: () => { st.page += 1; if (onPage) onPage({ page: st.page, size: st.size, why: 'next' }); } }));
    }
    syncHead();
    return {
      thead, foot, busyEl, state: st,
      // 클라이언트 목록: 정렬 → 지금 쪽만
      view(list) {
        const all = sorted(list || []); st.total = all.length;
        const n = Math.max(1, Math.ceil(all.length / st.size)); if (st.page > n) st.page = n;
        const a = (st.page - 1) * st.size, rows = all.slice(a, a + st.size);
        drawPager(all.length, all.length ? a + 1 : 0, a + rows.length, { known: true });
        return rows;
      },
      // 서버 목록(감사 로그): 받은 행을 정렬만(쪽 안), 바닥줄은 total 이 있으면 쪽 번호 · 없으면 이전/다음
      serverView(rows, { total, hasNext }) {
        const a = (st.page - 1) * st.size, known = Number.isFinite(total);
        drawPager(known ? total : 0, rows.length ? a + 1 : 0, a + rows.length, { known, hasPrev: st.page > 1, hasNext });
        return sorted(rows);
      },
      // 고른 행이 보이는 쪽으로(주소 ?id= 로 들어온 경우)
      reveal(list, pred) { const all = sorted(list || []); const i = all.findIndex(pred); if (i >= 0) st.page = Math.floor(i / st.size) + 1; },
      reset() { st.page = 1; },
      busy(on) { busyEl.hidden = !on; },
      offset() { return (st.page - 1) * st.size; },
    };
  }

  // ── 선 차트(추이) — keys = [[키, 이름, 색 토큰]]. 선 굵기 2 · 점은 hover 때만 · 선 끝 「이름 값」 라벨(겹치면 밀어냄) ──
  function lineChart({ name, label, keys }) {
    const root = h('div', { class: 'chart line-chart', 'data-chart': name });
    const box = h('div', { class: 'chart-box' });
    root.append(box);
    const tip = tipLayer(root);
    let data = [], step = 3600, drawn = false;
    function draw() {
      box.replaceChildren();
      const W = box.clientWidth || 480, H = box.clientHeight || 160;
      const lastVals = keys.map(([k, ko]) => `${ko} ${short((data[data.length - 1] || {})[k] || 0)}`);
      const endW = Math.min(120, 16 + Math.max(...lastVals.map((t) => t.length * 7.2)));
      const m = { t: 10, r: endW, b: 24, l: 36 }, iw = Math.max(40, W - m.l - m.r), ih = Math.max(40, H - m.t - m.b);
      const top = Math.max(1, ...data.flatMap((d) => keys.map(([k]) => d[k] || 0)));
      const { step: gs, max } = niceMax(top, 3);
      const x = (i) => m.l + (data.length <= 1 ? iw / 2 : (i / (data.length - 1)) * iw), y = (v) => m.t + ih - (v / max) * ih;
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img', 'aria-label': label });
      for (let v = 0; v <= max + 1e-9; v += gs) svg.append(s('line', { x1: m.l, x2: m.l + iw, y1: y(v), y2: y(v), class: 'grid', 'stroke-dasharray': '3 4' }), s('text', { x: m.l - 8, y: y(v) + 4, 'text-anchor': 'end', class: 'tick tick-y' }, short(v)));
      const every = everyFor(data.length, iw, 54);
      data.forEach((d, i) => { if (i % every === 0) svg.append(s('text', { x: x(i), y: H - 6, 'text-anchor': i === 0 ? 'start' : 'middle', class: 'tick tick-x' }, tickText(d.t, step))); });
      const lines = s('g', { class: 'lines' });
      for (const [k, , color] of keys) {
        const dPath = data.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[k] || 0).toFixed(1)}`).join('');
        lines.append(s('path', { d: dPath || `M${m.l},${y(0)}`, class: `line k-line-${k}`, 'data-kind': k, style: `stroke:var(${color})`, fill: 'none', 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round', pathLength: 1 }));
      }
      svg.append(lines);
      // 끝 라벨 — 마지막 값 높이에 두고, 14px 보다 가까우면 아래로 밀어낸다(넘치면 위로 다시 민다)
      const GAP = 16;
      const ends = keys.map(([k, ko, color], j) => ({ k, ko, color, v: (data[data.length - 1] || {})[k] || 0, y: y((data[data.length - 1] || {})[k] || 0), text: lastVals[j] })).sort((a, b) => a.y - b.y);
      for (let i = 0; i < ends.length; i++) ends[i].y = Math.max(ends[i].y, i ? ends[i - 1].y + GAP : m.t + 6);
      for (let i = ends.length - 1; i >= 0; i--) ends[i].y = Math.min(ends[i].y, i < ends.length - 1 ? ends[i + 1].y - GAP : m.t + ih);
      for (const e of ends) svg.append(s('text', { x: m.l + iw + 8, y: e.y + 4, class: 'end-label', 'data-end-label': e.k, style: `fill:var(${e.color})` }, e.text));
      // hover: 칸마다 투명 판(rect.hit) — 세로 안내선 · 점 · 툴팁
      const hover = s('g', { class: 'hover', hidden: '' });
      const guide = s('line', { y1: m.t, y2: m.t + ih, class: 'guide' });
      const dots = keys.map(([k, , color]) => s('circle', { r: 4, class: 'dot', 'data-kind': k, style: `fill:var(${color})` }));
      hover.append(guide, ...dots);
      const buckets = s('g', { class: 'buckets' });
      const colW = data.length > 1 ? iw / (data.length - 1) : iw;
      data.forEach((d, i) => {
        const hit = s('rect', { x: x(i) - colW / 2, y: m.t, width: colW, height: ih, class: 'hit' });
        const g = s('g', { 'data-bucket': d.t }, hit);
        g.addEventListener('mouseenter', (e) => { hover.removeAttribute('hidden'); guide.setAttribute('x1', x(i)); guide.setAttribute('x2', x(i)); keys.forEach(([k], j) => { dots[j].setAttribute('cx', x(i)); dots[j].setAttribute('cy', y(d[k] || 0)); }); tip.show(e, tickText(d.t, step), keys.map(([k, ko]) => [`k-${k}`, `${ko} ${fmt.num(d[k] || 0)}`])); });
        g.addEventListener('mousemove', (e) => tip.show(e, tickText(d.t, step), keys.map(([k, ko]) => [`k-${k}`, `${ko} ${fmt.num(d[k] || 0)}`])));
        buckets.append(g);
      });
      buckets.addEventListener('mouseleave', () => { hover.setAttribute('hidden', ''); tip.hide(); });
      svg.append(hover, buckets);
      box.append(svg);
      if (!drawn && data.length) { drawn = true; drawIn(lines); }
    }
    new ResizeObserver(() => draw()).observe(box);
    root.set = (d, st) => { data = d || []; step = st || 3600; draw(); };
    return root;
  }

  // ── 쌓은 막대(위반 추이) — keys = [[키, 이름, 클래스]]. 막대 최대 폭 22 · 맨 위 조각만 위쪽 모서리 3 ──
  function stackBars({ name, label, keys }) {
    const root = h('div', { class: 'chart stack-bars', 'data-chart': name });
    const legend = h('div', { class: 'chart-legend' });
    const box = h('div', { class: 'chart-box' });
    root.append(legend, box);
    const tip = tipLayer(root);
    let data = [], step = 3600, drawn = false;
    const topRound = (x, y0, w, hh, r) => { const rr = Math.min(r, hh, w / 2); return `M${x},${y0 + hh}V${y0 + rr}Q${x},${y0} ${x + rr},${y0}H${x + w - rr}Q${x + w},${y0} ${x + w},${y0 + rr}V${y0 + hh}Z`; };
    function draw() {
      box.replaceChildren();
      const sums = keys.map(([k]) => data.reduce((n, d) => n + (d[k] || 0), 0));
      replace(legend, keys.map(([, ko, cls], i) => h('span', null, h('i', { class: `sw ${cls}` }), `${ko} `, h('b', { class: 'num' }, fmt.num(sums[i])))));
      const W = box.clientWidth || 320, H = box.clientHeight || 160, m = { t: 10, r: 6, b: 24, l: 30 };
      const iw = Math.max(40, W - m.l - m.r), ih = Math.max(40, H - m.t - m.b);
      const tot = (d) => keys.reduce((n, [k]) => n + (d[k] || 0), 0);
      const { step: gs, max } = niceMax(Math.max(1, ...data.map(tot)), 3);
      const y = (v) => m.t + ih - (v / max) * ih;
      const slot = iw / Math.max(1, data.length), bw = Math.min(22, Math.max(2, slot * 0.62));
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img', 'aria-label': label });
      for (let v = 0; v <= max + 1e-9; v += gs) svg.append(s('line', { x1: m.l, x2: m.l + iw, y1: y(v), y2: y(v), class: 'grid', 'stroke-dasharray': '3 4' }), s('text', { x: m.l - 6, y: y(v) + 4, 'text-anchor': 'end', class: 'tick tick-y' }, short(v)));
      const every = everyFor(data.length, iw, 54);
      const buckets = s('g', { class: 'buckets' });
      data.forEach((d, i) => {
        const x = m.l + i * slot + (slot - bw) / 2;
        const g = s('g', { 'data-bucket': d.t }, s('rect', { x: m.l + i * slot, y: m.t, width: slot, height: ih, class: 'hit' }));
        let acc = 0; const segs = keys.filter(([k]) => d[k]);
        segs.forEach(([k, , cls], j) => { const v = d[k]; const y1 = y(acc + v), hh = Math.max(1, y(acc) - y1); g.append(j === segs.length - 1 ? s('path', { d: topRound(x, y1, bw, hh, 3), class: `bar seg ${cls}`, 'data-kind': k }) : s('rect', { x, y: y1, width: bw, height: hh, class: `bar seg ${cls}`, 'data-kind': k })); acc += v; });
        if (!acc) g.append(s('rect', { x, y: m.t + ih - 1, width: bw, height: 1, class: 'bar seg zero' }));
        const lines = keys.map(([k, ko, cls]) => [cls, `${ko} ${fmt.num(d[k] || 0)}`]);
        g.addEventListener('mouseenter', (e) => { g.classList.add('on'); tip.show(e, tickText(d.t, step), lines); });
        g.addEventListener('mousemove', (e) => tip.show(e, tickText(d.t, step), lines));
        g.addEventListener('mouseleave', () => { g.classList.remove('on'); tip.hide(); });
        buckets.append(g);
        if (i % every === 0) svg.append(s('text', { x: x + bw / 2, y: H - 6, 'text-anchor': i === 0 ? 'start' : 'middle', class: 'tick tick-x' }, tickText(d.t, step)));
      });
      svg.append(buckets);
      box.append(svg);
      if (!drawn && data.length) { drawn = true; drawIn(buckets); }
    }
    new ResizeObserver(() => draw()).observe(box);
    root.set = (d, st) => { data = d || []; step = st || 3600; draw(); };
    return root;
  }

  // ── 도넛(분포) — items = [[키, 이름, 클래스, 값]]. 안 58% · 밖 84% · 조각 사이 간격 · 가운데 큰 숫자 · 합이 0 이면 회색 고리 ──
  const INNER = 0.58, OUTER = 0.84;
  function donut({ name, label, centerLabel }) {
    const root = h('div', { class: 'chart donut-chart', 'data-chart': name, 'data-inner': String(INNER), 'data-outer': String(OUTER) });
    const box = h('div', { class: 'chart-box donut-box' });
    root.append(box);
    const tip = tipLayer(root);
    let items = [], drawn = false;
    const arc = (cx, cy, r0, r1, a0, a1) => {
      const p = (r, a) => [cx + r * Math.sin(a), cy - r * Math.cos(a)];
      const large = a1 - a0 > Math.PI ? 1 : 0;
      const [x0, y0] = p(r1, a0), [x1, y1] = p(r1, a1), [x2, y2] = p(r0, a1), [x3, y3] = p(r0, a0);
      return `M${x0},${y0}A${r1},${r1} 0 ${large} 1 ${x1},${y1}L${x2},${y2}A${r0},${r0} 0 ${large} 0 ${x3},${y3}Z`;
    };
    function draw() {
      box.replaceChildren();
      const S = Math.max(80, Math.min(box.clientWidth || 140, box.clientHeight || 140)), R = S / 2, cx = R, cy = R, r1 = R * OUTER, r0 = R * INNER;
      const total = items.reduce((n, x) => n + (x[3] || 0), 0);
      const svg = s('svg', { width: S, height: S, viewBox: `0 0 ${S} ${S}`, class: 'chart-svg donut-svg', role: 'img', 'aria-label': `${label} — ${items.map((x) => `${x[1]} ${x[3]}`).join(', ')}` });
      const g = s('g', { class: 'slices' });
      if (!total) g.append(s('circle', { cx, cy, r: (r0 + r1) / 2, class: 'donut-zero', fill: 'none', 'stroke-width': r1 - r0 }));
      else {
        const live = items.filter((x) => x[3] > 0), pad = live.length > 1 ? 0.035 : 0;
        let a = 0;
        for (const [k, ko, cls, v] of live) {
          const span = (v / total) * Math.PI * 2;
          const a0 = a + pad / 2, a1 = a + span - pad / 2;
          const path = span >= Math.PI * 2 - 1e-6 ? `${arc(cx, cy, r0, r1, 0, Math.PI)}${arc(cx, cy, r0, r1, Math.PI, Math.PI * 2 - 1e-4)}` : arc(cx, cy, r0, r1, a0, Math.max(a0 + 0.001, a1));
          const p = s('path', { d: path, class: `slice ${cls}`, 'data-slice': k });
          p.addEventListener('mouseenter', (e) => { p.classList.add('on'); tip.show(e, ko, [[cls, `${fmt.num(v)}건 · ${Math.round((v / total) * 100)}%`]]); });
          p.addEventListener('mousemove', (e) => tip.show(e, ko, [[cls, `${fmt.num(v)}건 · ${Math.round((v / total) * 100)}%`]]));
          p.addEventListener('mouseleave', () => { p.classList.remove('on'); tip.hide(); });
          g.append(p); a += span;
        }
      }
      svg.append(g,
        s('text', { x: cx, y: cy + (centerLabel ? 2 : 8), 'text-anchor': 'middle', class: 'donut-num', 'data-part': 'donut-center' }, fmt.num(total)),
        centerLabel ? s('text', { x: cx, y: cy + 20, 'text-anchor': 'middle', class: 'donut-label' }, centerLabel) : null);
      box.append(svg);
      if (!drawn && total) { drawn = true; drawIn(g); }
    }
    new ResizeObserver(() => draw()).observe(box);
    root.set = (it) => { items = it || []; draw(); };
    return root;
  }

  // ── 코드 창(11/04f) — macOS 창 모양 카드: 머리줄(점 3개 · 파일명 · 종류 태그) + 어두운 코드 영역(.cw-body = 스크롤 요소) ──
  // o = { name?(파일명 — 없으면 종류만), lang?(없으면 파일명 확장자에서), body(문자열 → <pre> · 요소 → 그 요소가 코드 영역 · 배열 → <div> 로 감쌈),
  //       wrap?(로그 · 원문만 true — pre-wrap), fill?(남은 높이 채움 — 정책 YAML), href? · onClick?(눌러서 여는 카드일 때만 → hover 떠오름 + pointer), attrs? }
  // 점 색은 창 장식(위험 의미 아님) — 「빨강은 위험에만」의 예외, 채도를 낮춘 --win-* 토큰
  const LANGS = [[/\.py$/i, 'python'], [/\.ya?ml$/i, 'YAML'], [/\.json$/i, 'JSON'], [/\.(sh|bash)$/i, 'shell'], [/\.log$/i, 'log'], [/\.[cm]?js$/i, 'javascript'], [/\.tsx?$/i, 'typescript'], [/\.toml$/i, 'TOML'], [/\.rs$/i, 'rust'], [/\.(cfg|ini)$/i, 'ini'], [/\.txt$/i, 'text']];
  const LANG_ALIAS = { py: 'python', python: 'python', yaml: 'YAML', yml: 'YAML', json: 'JSON', sh: 'shell', bash: 'shell', shell: 'shell', log: 'log', js: 'javascript', javascript: 'javascript', ts: 'typescript', toml: 'TOML', text: 'text', txt: 'text' };
  function codeLang(name, lang) {
    if (lang) return LANG_ALIAS[String(lang).toLowerCase()] || lang;
    const hit = name ? LANGS.find(([re]) => re.test(name)) : null;
    return hit ? hit[1] : 'text';
  }
  function codeWin(o) {
    const lang = codeLang(o.name, o.lang);
    let body = o.body;
    if (typeof body === 'string' || body == null) body = h('pre', null, body || '');
    else if (Array.isArray(body)) body = h('div', null, body);
    body.classList.add('cw-body');
    if (body.tagName === 'TEXTAREA') body.setAttribute('wrap', o.wrap ? 'soft' : 'off');
    const head = h('div', { class: 'cw-head' },
      h('span', { class: 'cw-dots', 'aria-hidden': 'true' }, h('i', { class: 'cw-dot cw-close' }), h('i', { class: 'cw-dot cw-min' }), h('i', { class: 'cw-dot cw-max' })),
      o.name ? h('span', { class: 'cw-name', title: o.name }, o.name) : null,
      h('span', { class: 'cw-tag' }, lang));
    const click = !!(o.href || o.onClick);
    const attrs = Object.assign({ class: `code-win${o.fill ? ' cw-fill' : ''}`, 'data-codewin': '', 'data-lang': lang, 'data-wrap': o.wrap ? '1' : '0', 'data-click': click ? '1' : null, 'aria-label': o.name ? `${o.name} (${lang})` : lang }, o.attrs || {});
    if (o.href) return h('a', Object.assign(attrs, U.to(o.href)), head, body);
    if (o.onClick) {
      const el = h('div', Object.assign(attrs, { role: 'button', tabindex: '0', onclick: o.onClick }), head, body);
      el.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === el) { e.preventDefault(); o.onClick(e); } });
      return el;
    }
    return h('figure', Object.assign(attrs, { role: 'group' }), head, body);
  }

  Object.assign(U, { kpiCard, kpiDelta: delta, tableKit, lineChart, stackBars, donut, tipLayer, codeWin, codeLang });
})();
