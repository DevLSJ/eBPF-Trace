// SupplyGuard 목업 — 「평가」 화면 [11/04 U1 1단계 — 목업 먼저, 확정 뒤 React]. 경로 #/evaluation, 읽기 전용(조회자도 본다).
// 데이터: U.api.evaluation() → { static, runtime, model }(bench/reports 의 static.json · runtime.json · model.json 그대로, 없는 쪽은 null)
//   sim = shared/eval-data.js 예시(sample: true → 「예시 데이터」 배지) · ?fresh=1 이면 없음 · live = GET /api/evaluation(404 → 「평가 결과 없음」)
// 순서: 머리(결론 한 줄 · 출처 태그) → 지표 6칸 → 두 열(정적: 판정 분포 · 규칙 적중 상위 10 · 혼동 행렬 / 런타임: 시나리오 탐지율 · 지연 분포(+ 단계별 막대 [11/04b]) · 정상 설치 위반) → 모델 비교 → 결과의 한계
// 차트는 React 에서 Recharts 로 옮길 모양(점선 격자 · 아래 축 · 범례 · 마우스 올리면 툴팁)을 SVG 로 그린다 — 외부 라이브러리 없음
(function () {
  'use strict';
  const U = window.UI;
  const { h, s, replace, fmt } = U;

  const pct = (x) => (x == null || !Number.isFinite(x) ? '—' : `${(x * 100).toFixed(1)}%`);
  const pct0 = (x) => `${Math.round(x * 100)}%`;
  const dec = (x) => (x == null || !Number.isFinite(x) ? '—' : x.toFixed(2));
  const ms = (x) => (x == null ? '—' : `${fmt.num(x)} ms`);
  const total = (o) => Object.values(o || {}).reduce((a, b) => a + (Number(b) || 0), 0);
  // 축 이름이 칸(px)을 넘으면 끝을 말줄임 — 글자 폭 어림(한글 11px · 그 밖 6.6px, 고정폭 6.8px)
  const fitText = (t, px, mono) => { const w = (ch) => (mono ? 6.8 : /[\u3131-\uD7A3]/.test(ch) ? 11 : 6.6); let n = 0, out = ''; const str = String(t), all = [...str].reduce((a, ch) => a + w(ch), 0); if (all <= px) return str; for (const ch of str) { if (n + w(ch) > px - 8) break; n += w(ch); out += ch; } return out + '…'; };
  const hint = (...parts) => parts.filter(Boolean).map((t) => t.replace(/ /g, '\u00a0')).join(' · '); // 지표 보조 줄 — 조각 안에서는 줄을 바꾸지 않는다
  const ymdhm = (iso) => { const d = new Date(iso), p = (x) => String(x).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; };
  // 판정 색: 상태 색(위험 · 주의 · 정보 · 정상) + 오류는 회색. 순서 고정(검증 스크립트로 인접 쌍 구분 확인)
  const VERDICTS = [['malicious', '악성', 'ev-mal'], ['suspicious', '주의', 'ev-sus'], ['vulnerable', '취약', 'ev-vul'], ['clean', '정상', 'ev-clean'], ['error', '오류', 'ev-err']];
  const SOURCE = { static: '정적', runtime: '런타임', model: '모델' };
  // 축 눈금: 1 · 2 · 5 × 10^k 간격으로 4칸 안팎
  const niceStep = (x) => { if (!(x > 0)) return 1; const e = Math.pow(10, Math.floor(Math.log10(x))), f = x / e; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * e; };
  const niceTicks = (maxV) => { const st = niceStep(Math.max(1, maxV) / 4), top = Math.max(st, Math.ceil(Math.max(1, maxV) / st) * st); const out = []; for (let v = 0; v <= top + 1e-9; v += st) out.push(v); return out; };
  const RATE_TICKS = [0, 0.25, 0.5, 0.75, 1];

  // 툴팁(.chart-tip) — 차트 상자 안에서 마우스를 따라간다
  function tipLayer(root) {
    const tip = h('div', { class: 'chart-tip', hidden: true, role: 'tooltip', 'data-part': 'chart-tip' });
    root.append(tip);
    const move = (e) => {
      const r = root.getBoundingClientRect(), w = tip.offsetWidth;
      let x = e.clientX - r.left + 12; if (x + w > r.width) x = Math.max(0, e.clientX - r.left - w - 12);
      tip.style.left = `${x}px`; tip.style.top = `${Math.max(0, e.clientY - r.top + 12)}px`;
    };
    return {
      show(e, lines) { replace(tip, lines.map(([cls, text], i) => h('div', { class: i ? null : 'strong' }, cls ? h('i', { class: cls }) : null, text))); tip.hidden = false; move(e); },
      move, hide() { tip.hidden = true; },
    };
  }
  const legendEl = (items) => h('div', { class: 'chart-legend', 'data-part': 'legend' }, items.map(([ko, cls]) => h('span', null, h('i', { class: `sw ${cls}` }), ko)));

  // 가로 막대(쌓기 · 묶음): rows = [{ id, label, mono?, bars: [[{ key, v, cls }]], value, tip: [[cls, text]] }] — 한 행에 막대 bars.length 개, 막대마다 조각을 쌓는다(조각 사이 2px)
  function hbars({ name, label, rows, ticks, tickFmt, legend, labelW, nBars, valueW }) {
    const root = h('div', { class: 'chart ev-chart', 'data-chart': name });
    const box = h('div', { class: 'ev-box' });
    if (legend) root.append(legendEl(legend));
    root.append(box);
    const tip = tipLayer(root);
    const BAR = 10, n = nBars || 1, stackH = n * BAR + (n - 1) * 3, rowH = Math.max(30, stackH + 16), m = { t: 4, r: valueW || 64, b: 22 }; // valueW: 오른쪽 값 글자 칸(11/04b 단계 막대 「합계 N ms」)
    const H = m.t + rows.length * rowH + m.b, max = ticks[ticks.length - 1] || 1;
    box.style.height = `${H}px`; // 높이는 너비와 무관 — 다시 그려도 상자 크기가 바뀌지 않게
    function draw() {
      box.replaceChildren();
      const W = box.clientWidth || 480, lw = Math.min(labelW || 140, Math.round(W * 0.36)), iw = Math.max(40, W - lw - m.r);
      const x = (v) => lw + (Math.min(v, max) / max) * iw;
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img', 'aria-label': label });
      for (const t of ticks) svg.append(s('line', { x1: x(t), x2: x(t), y1: m.t, y2: H - m.b, class: t ? 'grid' : 'axis', 'stroke-dasharray': t ? '3 3' : null }), s('text', { x: x(t), y: H - 6, 'text-anchor': 'middle', class: 'tick' }, tickFmt(t)));
      rows.forEach((r, i) => {
        const y0 = m.t + i * rowH;
        const g = s('g', { 'data-row': r.id }, s('rect', { x: 0, y: y0, width: W, height: rowH, class: 'ev-row-bg' }),
          s('text', { x: lw - 8, y: y0 + rowH / 2 + 4, 'text-anchor': 'end', class: `tick ev-label ${r.mono ? 'ev-mono' : ''} ${r.strong ? 'ev-strong' : ''}` }, fitText(r.label, lw - 10, r.mono)));
        let by = y0 + (rowH - stackH) / 2;
        for (const segs of r.bars) {
          const on = segs.filter((sg) => sg.v > 0); let acc = 0;
          on.forEach((sg, j) => {
            const x0 = x(acc), x1 = x(acc + sg.v); acc += sg.v;
            g.append(s('rect', { x: x0, y: by, width: Math.max(1, x1 - x0 - (j < on.length - 1 ? 2 : 0)), height: BAR, rx: 2, class: `ev-seg ${sg.cls}`, 'data-key': sg.key, 'data-v': sg.v }));
          });
          if (!on.length) g.append(s('rect', { x: lw, y: by, width: 2, height: BAR, class: 'ev-seg ev-zero', 'data-key': 'zero', 'data-v': 0 }));
          by += BAR + 3;
        }
        g.append(s('text', { x: W - m.r + 8, y: y0 + rowH / 2 + 4, class: 'tick ev-value' }, r.value));
        const hit = s('rect', { x: 0, y: y0, width: W, height: rowH, class: 'ev-hit' });
        hit.addEventListener('mouseenter', (e) => { g.classList.add('on'); tip.show(e, r.tip); });
        hit.addEventListener('mousemove', tip.move);
        hit.addEventListener('mouseleave', () => { g.classList.remove('on'); tip.hide(); });
        g.append(hit); svg.append(g);
      });
      box.append(svg);
    }
    new ResizeObserver(draw).observe(box);
    return root;
  }

  // 지연 분포(범위 그림): 행마다 0~max 선 · p50~p95 띠 · p50 점 · max 눈금
  function rangeChart({ name, label, rows }) {
    const root = h('div', { class: 'chart ev-chart', 'data-chart': name });
    const legend = h('div', { class: 'chart-legend', 'data-part': 'legend' }, h('span', null, h('i', { class: 'sw ev-p50-sw' }), 'p50'), h('span', null, h('i', { class: 'sw ev-band' }), 'p50 ~ p95'), h('span', null, h('i', { class: 'sw ev-max-sw' }), 'max'));
    const box = h('div', { class: 'ev-box' });
    root.append(legend, box);
    const tip = tipLayer(root);
    const rowH = 30, m = { t: 4, r: 64, b: 22 }, H = m.t + rows.length * rowH + m.b;
    const ticks = niceTicks(Math.max(...rows.map((r) => r.lat.max || 0), 1)), max = ticks[ticks.length - 1];
    box.style.height = `${H}px`;
    function draw() {
      box.replaceChildren();
      const W = box.clientWidth || 480, lw = Math.min(150, Math.round(W * 0.36)), iw = Math.max(40, W - lw - m.r);
      const x = (v) => lw + (Math.min(v, max) / max) * iw;
      const svg = s('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img', 'aria-label': label });
      for (const t of ticks) svg.append(s('line', { x1: x(t), x2: x(t), y1: m.t, y2: H - m.b, class: t ? 'grid' : 'axis', 'stroke-dasharray': t ? '3 3' : null }), s('text', { x: x(t), y: H - 6, 'text-anchor': 'middle', class: 'tick' }, fmt.num(t)));
      rows.forEach((r, i) => {
        const y0 = m.t + i * rowH, cy = y0 + rowH / 2, L = r.lat;
        const g = s('g', { 'data-row': r.id, 'data-p50': L.p50, 'data-p95': L.p95, 'data-max': L.max }, s('rect', { x: 0, y: y0, width: W, height: rowH, class: 'ev-row-bg' }),
          s('text', { x: lw - 8, y: cy + 4, 'text-anchor': 'end', class: 'tick ev-label' }, fitText(r.label, lw - 10)),
          s('line', { x1: x(0), x2: x(L.max), y1: cy, y2: cy, class: 'ev-track' }),
          s('rect', { x: x(L.p50), y: cy - 4, width: Math.max(2, x(L.p95) - x(L.p50)), height: 8, rx: 2, class: 'ev-band' }),
          s('line', { x1: x(L.max), x2: x(L.max), y1: cy - 6, y2: cy + 6, class: 'ev-max' }),
          s('circle', { cx: x(L.p50), cy, r: 4.5, class: 'ev-p50' }),
          s('text', { x: W - m.r + 8, y: cy + 4, class: 'tick ev-value' }, `p95 ${fmt.num(L.p95)}`));
        const hit = s('rect', { x: 0, y: y0, width: W, height: rowH, class: 'ev-hit' });
        hit.addEventListener('mouseenter', (e) => { g.classList.add('on'); tip.show(e, r.tip); });
        hit.addEventListener('mousemove', tip.move);
        hit.addEventListener('mouseleave', () => { g.classList.remove('on'); tip.hide(); });
        g.append(hit); svg.append(g);
      });
      box.append(svg);
    }
    new ResizeObserver(draw).observe(box);
    return root;
  }

  const card = (key, title, body, opts) => { const o = opts || {}; const p = U.panel({ title, actions: o.actions, body, class: 'ev-card' }); p.dataset.part = key; return p; };
  const none = (what) => h('p', { class: 'small muted ev-none' }, `${what} 결과 없음`);

  // ── 계산 ──
  function attacks(rt) { const a = ((rt && rt.scenarios) || []).filter((x) => x.kind === 'attack'); return { list: a, runs: a.reduce((n, x) => n + x.runs, 0), detected: a.reduce((n, x) => n + x.detected, 0) }; }
  // 지표 칸 [11/04b]: 격리된 공격 전체(runtime.killLatencyMs — 백엔드 수신 → 격리). 키가 없는 옛 파일이면 격리까지 잰 공격 시나리오의 p50 · p95 중 가장 큰 값(가장 느린 쪽)
  function latencyHead(rt) {
    const k = rt && rt.killLatencyMs;
    if (k && k.p50 != null) return { p50: k.p50, p95: k.p95, hint: hint(`격리된 공격 ${fmt.num(k.n)}회 기준`, '백엔드 수신→격리') };
    const l = attacks(rt).list.map((x) => x.latencyMs).filter((x) => x && x.p50 != null);
    return l.length ? { p50: Math.max(...l.map((x) => x.p50)), p95: Math.max(...l.map((x) => x.p95)), hint: '공격 시나리오 중 가장 느린 값' } : null;
  }
  function conclusion(d) {
    const out = [];
    if (d.static && d.static.confusion) { const c = d.static.confusion; out.push(`정적 검사: 실제 악성 ${fmt.num(c.tp + c.fn)}개 중 ${fmt.num(c.tp)}개 탐지 · 정상 ${fmt.num(c.fp + c.tn)}개 중 ${fmt.num(c.fp)}개 오탐`); }
    if (d.runtime) { const a = attacks(d.runtime), b = d.runtime.benign || {}; out.push(`런타임: 공격 ${fmt.num(a.runs)}회 중 ${fmt.num(a.detected)}회 탐지 · 정상 설치 ${fmt.num(b.installs || 0)}건 중 ${fmt.num(b.violations || 0)}건 위반`); }
    return out.join(' — ');
  }
  function tags(d) {
    const st = d.static, rt = d.runtime, out = [];
    const tag = (key, k, v, title) => h('span', { class: 'ev-tag', 'data-tag': key, title: title || null }, h('span', { class: 'ev-tag-k' }, k), h('span', { class: 'ev-tag-v' }, v));
    for (const ds of (st && st.datasets) || []) out.push(tag(`dataset-${ds.id}`, ds.kind === 'malicious' ? '악성 세트' : '정상 세트', ds.label, `${ds.source} @ ${ds.sourceCommit} · 파일 ${fmt.num(ds.files)}개 · 목록 sha256 ${String(ds.listSha256 || '').slice(0, 12)}`));
    if (rt && rt.host) out.push(tag('host', '런타임', `${rt.host.name} · 커널 ${rt.host.kernel} · ${rt.host.discovery}`, `Inspektor Gadget ${rt.host.igVersion}`));
    const at = [st && st.generatedAt, rt && rt.generatedAt].filter(Boolean).sort().pop();
    if (at) out.push(tag('generated', '생성', ymdhm(at), [st && `정적 ${st.generatedAt}`, rt && `런타임 ${rt.generatedAt}`].filter(Boolean).join(' · ')));
    const commits = [...new Set([st && st.scanner && st.scanner.backendCommit, rt && rt.host && rt.host.backendCommit].filter(Boolean))];
    if (commits.length) out.push(tag('commit', '백엔드', commits.join(' · '), st && st.scanner ? `GuardDog ${st.scanner.guarddog} · OSV-Scanner ${st.scanner.osv}` : null));
    return out;
  }

  // ── 그리기 ──
  function kpis(d) {
    const st = d.static, rt = d.runtime, md = d.model;
    const mt = (st && st.metrics) || {}, c = (st && st.confusion) || null, a = attacks(rt), b = (rt && rt.benign) || null, lat = latencyHead(rt);
    const pref = md && (md.candidates || []).find((x) => x.id === md.preferredId);
    const by = b && b.byEcosystem ? Object.entries(b.byEcosystem).map(([k, v]) => `${k} ${fmt.num(v)}`).join(', ') : '';
    const el = h('div', { class: 'eval-kpis', 'data-part': 'kpis' },
      U.kpi({ key: 'static-detection', icon: '⌕', stripe: 'accent', label: '정적 악성 탐지율', value: st ? pct(mt.detectionRate) : '—', hint: c ? hint(`악성 ${fmt.num(c.tp)} / ${fmt.num(c.tp + c.fn)}`, `주의 포함 ${pct(mt.detectionRateWithSuspicious)}`) : '정적 결과 없음' }),
      U.kpi({ key: 'static-fpr', icon: '✓', stripe: 'info', label: '정상 오탐률', value: st ? pct(mt.falsePositiveRate) : '—', hint: c ? `인기 패키지 ${fmt.num(c.fp)} / ${fmt.num(c.fp + c.tn)}` : '정적 결과 없음' }),
      U.kpi({ key: 'runtime-detection', icon: '▣', stripe: 'accent', label: '런타임 공격 탐지율', value: a.runs ? pct(a.detected / a.runs) : '—', hint: a.runs ? hint(`공격 ${fmt.num(a.detected)} / ${fmt.num(a.runs)}회`, `${a.list.length}종`) : '런타임 결과 없음' }),
      U.kpi({ key: 'runtime-fpr', icon: '✓', stripe: 'info', label: '정상 설치 오탐률', value: b ? pct(b.falsePositiveRate) : '—', hint: b ? hint(`위반 ${fmt.num(b.violations)} / ${fmt.num(b.installs)}건`, by) : '런타임 결과 없음' }),
      U.kpi({ key: 'latency', icon: '◷', stripe: 'warn', label: '탐지 → 격리 p50 / p95', value: lat ? [fmt.num(lat.p50), h('span', { class: 'kpi-unit' }, ` / ${fmt.num(lat.p95)} ms`)] : '—', hint: lat ? lat.hint : '격리한 시나리오 없음' }),
      U.kpi({ key: 'model-f1', icon: '◔', stripe: 'ok', label: '모델 시험 F1', value: pref ? dec(pref.test.f1) : '—', hint: pref ? `${pref.label}${md.deploymentApproved ? '' : ' · 운영 미적용'}` : '모델 결과 없음' }));
    // 길게 눌러 순서 바꾸기 [11/04d] — 지표 6칸 순서는 localStorage supplyguard.layout.evaluationKpi(shared/sortable.js)
    if (U.sortable) U.sortable.attach(el, { scope: 'evaluationKpi', selector: '.kpi[data-kpi]', layout: 'grid', labelOf: (x) => x.querySelector('.kpi-label').textContent });
    return el;
  }

  function distCard(st) {
    if (!st) return card('dist', '세트별 판정 분포', none('정적'));
    const label = (id) => { const ds = (st.datasets || []).find((x) => x.id === id); return ds ? ds.label : id; };
    const rows = (st.sets || []).map((set) => {
      const n = total(set.verdicts) || 1, skip = total(set.skipped);
      return { id: set.id, label: label(set.id), value: `n=${fmt.num(set.scanned)}`,
        bars: [VERDICTS.map(([k, , cls]) => ({ key: k, v: (set.verdicts[k] || 0) / n, cls }))],
        tip: [[null, `${label(set.id)} · 검사 ${fmt.num(set.scanned)} / ${fmt.num(set.total)}`], ...VERDICTS.map(([k, ko, cls]) => [cls, `${ko} ${fmt.num(set.verdicts[k] || 0)} (${pct((set.verdicts[k] || 0) / n)})`]),
          ...(skip ? [[null, `건너뜀 ${fmt.num(skip)} — ${Object.entries(set.skipped).map(([k, v]) => `${k} ${v}`).join(' · ')}`]] : [])] };
    });
    const dur = st.durationsSec ? `검사 1건 p50 ${fmt.num(st.durationsSec.p50)}초 · p95 ${fmt.num(st.durationsSec.p95)}초` : '';
    return card('dist', '세트별 판정 분포', [hbars({ name: 'verdict-dist', label: '세트별 판정 분포 쌓은 막대', rows, ticks: RATE_TICKS, tickFmt: pct0, legend: VERDICTS.map(([, ko, cls]) => [ko, cls]), labelW: 130 }),
      dur ? h('p', { class: 'small muted' }, dur) : null]);
  }
  function scenarioCard(rt) {
    if (!rt) return card('scenarios', '시나리오별 탐지율', none('런타임'));
    const rows = (rt.scenarios || []).map((x) => ({ id: x.id, label: x.label, value: `${fmt.num(x.detected)}/${fmt.num(x.runs)}`,
      bars: [[{ key: x.kind, v: x.runs ? x.detected / x.runs : 0, cls: x.kind === 'attack' ? 'ev-attack' : 'ev-control' }]],
      tip: [[null, x.label], [x.kind === 'attack' ? 'ev-attack' : 'ev-control', `${x.kind === 'attack' ? '공격' : '대조(정상)'} · 탐지 ${fmt.num(x.detected)} / ${fmt.num(x.runs)}회`], [null, `격리 ${fmt.num(x.killed)}회${x.rule ? ` · 규칙 ${x.rule}` : ''}`]] }));
    return card('scenarios', '시나리오별 탐지율', hbars({ name: 'scenario-rate', label: '시나리오별 탐지율 막대', rows, ticks: RATE_TICKS, tickFmt: pct0, legend: [['공격', 'ev-attack'], ['대조(정상 — 0% 가 정답)', 'ev-control']], labelW: 150 }));
  }
  function latencyCard(rt) {
    const list = ((rt && rt.scenarios) || []).filter((x) => x.latencyMs && x.latencyMs.p50 != null);
    if (!list.length) return card('latency', '탐지 → 격리 지연 (ms)', rt ? h('p', { class: 'small muted ev-none' }, '격리까지 잰 시나리오가 없습니다') : none('런타임'));
    const rows = list.map((x) => ({ id: x.id, label: x.label, lat: x.latencyMs, tip: [[null, x.label], ['ev-p50-sw', `p50 ${ms(x.latencyMs.p50)}`], ['ev-band', `p95 ${ms(x.latencyMs.p95)}`], ['ev-max-sw', `max ${ms(x.latencyMs.max)}`], [null, `격리 ${fmt.num(x.killed)}회 기준`]] }));
    const skipped = ((rt && rt.scenarios) || []).filter((x) => x.kind === 'attack' && !(x.latencyMs && x.latencyMs.p50 != null));
    return card('latency', '탐지 → 격리 지연 (ms)', [rangeChart({ name: 'latency', label: '시나리오별 탐지에서 격리까지 지연 범위', rows }),
      skipped.length ? h('p', { class: 'small muted' }, `격리하지 않아 빠짐: ${skipped.map((x) => x.label).join(' · ')}`) : null,
      ...stagesBlock(rt)]);
  }
  // [11/04b] 단계별 막대 — p50 가로 누적(판정 → 증거 수집 → kill 호출, 합계), 첫 행은 격리된 실행 전체(runtime.killStagesMs) · 그 아래 격리한 시나리오별(matchLatencyMs · evidenceMs · killApiMs). 툴팁에 p95
  //   killStagesMs 가 없는 옛 파일이면 칸을 숨긴다
  const STAGES = [['match', '판정', 'ev-st-match'], ['evidence', '증거 수집', 'ev-st-evidence'], ['killApi', 'kill 호출', 'ev-st-kill']];
  const msv = (x) => (x >= 10 ? Math.round(x) : Math.round(x * 10) / 10); // 막대 글자 — 10ms 이상은 정수, 그 아래는 소수 한 자리
  function stagesBlock(rt) {
    const all = rt && rt.killStagesMs;
    if (!all) return [];
    const row = (id, label, st, n, strong) => {
      const p = (k) => (st[k] && st[k].p50 != null ? st[k].p50 : 0), sum = STAGES.reduce((a, [k]) => a + p(k), 0);
      return { id, label, strong, sum, value: `합계 ${fmt.num(msv(sum))} ms`,
        bars: [STAGES.map(([k, , cls]) => ({ key: k, v: p(k), cls }))],
        tip: [[null, label], ...STAGES.map(([k, ko, cls]) => [cls, st[k] ? `${ko} p50 ${fmt.num(msv(st[k].p50))} ms · p95 ${fmt.num(msv(st[k].p95))} ms` : `${ko} —`]), ...(n ? [[null, `격리 ${fmt.num(n)}회 기준`]] : [])] };
    };
    const lead = (st) => STAGES.map(([k]) => st[k]).find((x) => x && x.n);
    const rows = [row('all', '격리된 공격 전체', all, (lead(all) || {}).n || (rt.killLatencyMs && rt.killLatencyMs.n), true),
      ...(rt.scenarios || []).filter((x) => (x.evidenceMs && x.evidenceMs.p50 != null) || (x.killApiMs && x.killApiMs.p50 != null))
        .map((x) => { const st = { match: x.matchLatencyMs, evidence: x.evidenceMs, killApi: x.killApiMs }; return row(x.id, x.label, st, (lead(st) || {}).n || x.killed); })];
    const ticks = niceTicks(Math.max(1, ...rows.map((r) => r.sum)));
    return [h('p', { class: 'small ev-sub', 'data-part': 'stages-title' }, '단계별 시간 (p50)'),
      hbars({ name: 'kill-stages', label: '탐지에서 격리까지 단계별 시간 누적 막대', rows, ticks, tickFmt: (t) => fmt.num(t), legend: STAGES.map(([, ko, cls]) => [ko, cls]), labelW: 150, valueW: 88 }),
      h('p', { class: 'small muted', 'data-part': 'stages-caption' }, '증거를 먼저 모으고(≤0.7초) 격리합니다')];
  }
  function rulesCard(st) {
    if (!st) return card('rules', 'GuardDog 규칙 적중 상위 10', none('정적'));
    // 합 → 악성 적중 → 이름 순서로 상위 10
    const top = [...(st.rules || [])].sort((a, b) => (b.maliciousHits + b.benignHits) - (a.maliciousHits + a.benignHits) || b.maliciousHits - a.maliciousHits || a.rule.localeCompare(b.rule)).slice(0, 10);
    const ticks = niceTicks(Math.max(1, ...top.map((r) => Math.max(r.maliciousHits, r.benignHits))));
    const rows = top.map((r) => ({ id: r.rule, label: r.rule, mono: true, value: `${fmt.num(r.maliciousHits)} · ${fmt.num(r.benignHits)}`,
      bars: [[{ key: 'malicious', v: r.maliciousHits, cls: 'ev-mal' }], [{ key: 'benign', v: r.benignHits, cls: 'ev-benign' }]],
      tip: [[null, r.rule], ['ev-mal', `악성 세트 ${fmt.num(r.maliciousHits)}개`], ['ev-benign', `정상 세트 ${fmt.num(r.benignHits)}개`]] }));
    return card('rules', 'GuardDog 규칙 적중 상위 10', top.length ? hbars({ name: 'rule-hits', label: 'GuardDog 규칙별 악성 · 정상 세트 적중 수', rows, ticks, tickFmt: (t) => fmt.num(t), legend: [['악성 세트 적중', 'ev-mal'], ['정상 세트 적중', 'ev-benign']], labelW: 170, nBars: 2 }) : h('p', { class: 'small muted ev-none' }, '적중한 규칙 없음'));
  }
  function confusionCard(st) {
    if (!st || !st.confusion) return card('confusion', '혼동 행렬 · 정적 검사', none('정적'));
    const c = st.confusion, mt = st.metrics || {};
    const cell = (k, n, what) => h('td', { 'data-cell': k }, h('b', { class: 'num' }, fmt.num(n)), h('span', { class: 'small muted' }, what));
    return card('confusion', '혼동 행렬 · 정적 검사', [
      h('table', { class: 'table compact ev-confusion' },
        h('thead', null, h('tr', null, h('th', null, ''), h('th', null, '판정 악성'), h('th', null, '악성 아님'))),
        h('tbody', null, h('tr', null, h('th', null, '실제 악성'), cell('tp', c.tp, '잡음'), cell('fn', c.fn, '놓침')), h('tr', null, h('th', null, '실제 정상'), cell('fp', c.fp, '오탐'), cell('tn', c.tn, '통과')))),
      h('p', { class: 'small muted' }, `양성 = 판정 「악성」 · 정밀도 ${pct(mt.precision)} · 재현율 ${pct(mt.recall)} · F1 ${dec(mt.f1)}`)]);
  }
  function benignCard(rt) {
    if (!rt || !rt.benign) return card('benign', '정상 설치 위반', none('런타임'));
    const b = rt.benign, rows = (b.items || []).filter((x) => !['pass', 'passed'].includes(x.result) || x.rule);
    return card('benign', `정상 설치 위반 ${fmt.num(rows.length)}건`, rows.length ? h('div', { class: 'grid-scroll', 'data-fill': '' }, h('table', { class: 'table compact', 'data-table': 'benign-violations' },
      h('thead', null, h('tr', null, ['생태계', '패키지', '결과', '규칙', '걸린 시간'].map((t) => h('th', null, t)))),
      h('tbody', null, rows.map((x) => h('tr', { 'data-pkg': `${x.ecosystem}:${x.name}` }, h('td', null, x.ecosystem), h('td', { class: 'mono' }, x.name), h('td', null, U.INSTALL_STATUS[x.result] ? U.statusBadge(x.result) : x.result), h('td', { class: 'mono small' }, x.rule || '—'), h('td', { class: 'num' }, `${fmt.num(x.seconds)}초`))))))
      : h('p', { class: 'small muted ev-none' }, `위반 없음 — 정상 설치 ${fmt.num(b.installs)}건 모두 통과`), { actions: h('span', { class: 'small muted' }, `정상 설치 ${fmt.num(b.installs)}건 중`) });
  }
  function modelCard(md) {
    if (!md) return card('model', '모델 비교', none('모델'));
    const p = md.protocol || {};
    // 11/04c — 선택 모델은 보정 기준으로 고른 것. 시험 F1 이 그보다 높은 규칙 후보(id 가 rule 로 시작)가 있으면 표 아래 한 줄
    const pref = (md.candidates || []).find((x) => x.id === md.preferredId);
    const ruleWins = !!pref && (md.candidates || []).some((x) => /^rule/.test(x.id) && x.id !== md.preferredId && x.test.f1 > pref.test.f1);
    return card('model', '모델 비교', [h('div', { class: 'grid-scroll', 'data-fill': '' }, h('table', { class: 'table compact', 'data-table': 'models' },
      h('thead', null, h('tr', null, ['후보', '보정 F1', '시험 F1', '정밀도', '재현율', '오탐률'].map((t, i) => h('th', { class: i ? 'right' : null }, t)))),
      h('tbody', null, (md.candidates || []).map((x) => { const pick = x.id === md.preferredId; return h('tr', { 'data-model': x.id, class: pick ? 'ev-pick' : null, 'aria-current': pick ? 'true' : null },
        h('td', null, x.label, pick ? h('span', { class: 'badge badge-info ev-pick-badge', title: '보정 구간에서 고른 모델 — 시험 구간은 선택에 쓰지 않았습니다' }, '보정 기준 선택') : null), // 11/04c
        ...[x.calibration.f1, x.test.f1].map((v) => h('td', { class: 'num right' }, dec(v))), ...[x.test.precision, x.test.recall, x.test.fpr].map((v) => h('td', { class: 'num right' }, pct(v)))); })))),
      ruleWins ? h('p', { class: 'small', 'data-part': 'rule-wins' }, '시험에서는 규칙 판정이 우세 — 운영은 규칙') : null, // 11/04c
      h('p', { class: 'small muted', title: (md.features || []).join(', ') }, `seed ${p.seed} · ${p.split} · 선택 기준: ${p.selection} · 특징 ${fmt.num((md.features || []).length)}개`)],
    { actions: md.deploymentApproved ? null : h('span', { class: 'badge badge-level-normal', 'data-part': 'not-deployed', title: '선택 모델은 비교용이고 판정은 지금도 규칙으로 합니다' }, '운영 미적용') });
  }
  function limitsBox(d) {
    const items = ['static', 'runtime', 'model'].flatMap((k) => ((d[k] && d[k].limits) || []).map((t) => [k, t]));
    return h('section', { class: 'panel ev-limits', 'data-part': 'limits' }, h('h2', null, '결과의 한계'),
      items.length ? h('ul', null, items.map(([k, t]) => h('li', { 'data-src': k }, h('span', { class: 'ev-tag ev-tag-sm' }, SOURCE[k]), h('span', null, t)))) : h('p', { class: 'small muted' }, '적힌 한계 없음'));
  }
  function view(d) {
    return h('div', { class: 'eval' },
      h('section', { class: 'panel eval-head', 'data-part': 'eval-head' },
        h('div', { class: 'eval-head-top' }, d.sample ? h('span', { class: 'badge ev-sample', 'data-part': 'sample-badge', title: 'shared/eval-data.js 의 예시 값 — 실측이 아닙니다' }, '예시 데이터') : null, h('p', { class: 'eval-conclusion', 'data-part': 'conclusion' }, conclusion(d) || '결과 요약 없음')),
        h('div', { class: 'eval-tags', 'data-part': 'tags' }, tags(d))),
      kpis(d),
      // 두 열 = 정적(왼쪽) · 런타임(오른쪽) — 카드 높이가 달라도 열마다 위로 붙는다(Pinterest 식). 768 미만은 정적 → 런타임 한 열
      // 11/04e 스크롤 없는 페이지: 머리 · 지표 6칸은 제자리, 그 아래 몸통(.eval-body)만 스크롤(채움 칸)
      h('div', { class: 'eval-body', 'data-fill': '' },
        h('div', { class: 'eval-grid' }, h('div', { class: 'ev-col', 'data-col': 'static' }, distCard(d.static), rulesCard(d.static), confusionCard(d.static)),
          h('div', { class: 'ev-col', 'data-col': 'runtime' }, scenarioCard(d.runtime), latencyCard(d.runtime), benignCard(d.runtime))),
        modelCard(d.model),
        limitsBox(d)));
  }
  function download(d) {
    const at = ((d.static && d.static.generatedAt) || (d.runtime && d.runtime.generatedAt) || new Date().toISOString()).slice(0, 10);
    const url = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2) + '\n'], { type: 'application/json' }));
    const a = h('a', { href: url, download: `supplyguard-evaluation-${at}.json`, hidden: true });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  U.screens['/evaluation'] = {
    title: '평가',
    mount(page) {
      let alive = true;
      const wrap = h('div', { class: 'eval-wrap', 'data-part': 'evaluation', 'data-state': 'loading' }, U.skeleton(8));
      page.append(wrap);
      const load = () => U.api.evaluation().then((d) => {
        if (!alive) return;
        if (!d || (!d.static && !d.runtime && !d.model)) {
          U.headerActions(); wrap.dataset.state = 'empty';
          replace(wrap, U.emptyState({ icon: '◔', title: '평가 결과 없음', hint: '아직 평가를 돌린 결과가 없습니다 — 정적 · 런타임 · 모델 평가 결과가 서버에 올라오면 여기에 보입니다.' }));
          return;
        }
        U.headerActions(h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': 'download-json', title: '이 화면의 결과(static · runtime · model)를 JSON 한 파일로', onclick: () => download(d) }, '⤓ 결과 JSON'));
        wrap.dataset.state = 'ready'; replace(wrap, view(d));
      }).catch((e) => { if (!alive) return; U.headerActions(); wrap.dataset.state = 'error'; replace(wrap, U.errorState(e, load, { what: '평가 결과' })); });
      load();
      return { unmount() { alive = false; } };
    },
  };
})();
