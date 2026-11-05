/* 11/04f macOS 창 모양 코드 카드(U.codeWin) 회귀 — 코드가 나오는 6곳에 공용 부품 하나
   ① 공급망 검사 위협 파일 코드(code-view) ② 이벤트 상세 원본 JSON ③ 증거 시트 로그(마지막 200줄) ④ 시연 「왜」 카드 이벤트 원문
   ⑤ 정책 편집기 YAML(편집 가능 — 입력 · 422 표시 유지) ⑥ AI 도우미 답변 속 코드 블록
   각 곳: 점 3개(12px · 간격 8 · 위험 빨강과 다른 색) · 파일명(고정폭 · 말줄임)/종류 태그 · 어두운 코드 바탕(라이트 · 다크) · 대비 AA · 13~14px · 줄 간격 1.5 · 패딩 14~15 · 반경 6
   + 줄바꿈(로그 · 원문만 pre-wrap) · 스크롤바 8px · 읽기 전용은 떠오름 없음(그림자만) · 클릭 카드만 translateY(-5px) + pointer · reduced-motion 이동 없음
   + 390 넘침 0 · 1920×1080 정책 화면 문서 스크롤 0 · 콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8768 --bind 127.0.0.1 → BASE=http://127.0.0.1:8768 PLAYWRIGHT=<playwright 경로> node tests/codewin-1104.cjs
         (VERBOSE=1 · ONLY=정규식 · SHOTS=1 → screenshots/codewin-1104-*.png) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = (process.env.BASE || 'http://127.0.0.1:8768').replace(/\/index\.html$/, '').replace(/\/$/, '') + '/index.html';
const SHOTS = process.env.SHOTS === '1';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const W = { timeout: 8000 };
const ED = '[data-view="rule-editor"]';

// 6곳의 창 선택자
const SEL = {
  scan: '.sheet [data-part="code"] .code-win',
  event: '.sheet[data-sheet="event"] .code-win',
  logs: '.sheet[data-sheet="audit"] [data-part="evidence"] .code-win',
  why: '[data-part="why"] .code-win',
  yaml: `${ED} .code-win`,
  chat: '[data-part="chat-list"] .chat-msg.assistant .code-win',
};

(async () => {
  const br = await chromium.launch({ ignoreDefaultArgs: ['--hide-scrollbars'] }); // 헤드리스 기본은 스크롤바를 숨겨 폭이 0 — 실제 스크롤바 폭(8px)을 재려고 뺀다
  const newPage = async (opts = {}) => {
    const ctx = await br.newContext(Object.assign({ viewport: { width: 1440, height: 900 } }, opts));
    const pg = await ctx.newPage();
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    pg.done = () => ctx.close();
    return pg;
  };
  const go = async (pg, hash, extra = '') => { await pg.goto(`${BASE}?source=sim&as=admin${extra}#${hash}`); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(400); };
  const nav = async (pg, hash) => { await pg.evaluate((x) => { location.hash = x; }, hash); await pg.waitForTimeout(500); };
  const shot = async (pg, name) => { if (!SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `codewin-1104-${name}.png`) }); };

  // ── 각 곳으로 가는 길 ──
  const open = {
    async scan(pg) {
      await go(pg, '/scans');
      const id = await pg.evaluate(async () => (await UI.api.startScan({ kind: 'package', manager: 'pip', name: 'reqeusts' })).id);
      await pg.waitForFunction((i) => { const s = UI.state.scans.find((x) => x.id === i); return s && s.status === 'done'; }, id, W);
      await nav(pg, `#/scans?id=${id}`);
      await pg.waitForSelector('.sheet [data-part="code"]', W);
    },
    async event(pg) {
      await go(pg, '/events');
      await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(600);
      await pg.click('.feed-row'); await pg.waitForSelector('.sheet[data-sheet="event"]', W);
    },
    async logs(pg) {
      await go(pg, '/audit');
      const id = await pg.evaluate(() => UI.runInstallDemo('malicious'));
      await pg.waitForFunction((i) => { const s = UI.state.installs.find((x) => x.id === i); return s && s.finishedAt; }, id, W);
      await pg.waitForTimeout(300);
      const aid = await pg.evaluate((i) => { const s = UI.state.installs.find((x) => x.id === i); return UI.state.audit.find((a) => a.event.containerName === s.container && UI.levelOf(a) === 'killed').id; }, id);
      await nav(pg, `#/audit?id=${aid}`);
      await pg.waitForSelector('.sheet[data-sheet="audit"] [data-tab="evidence"]', W);
      await pg.click('.sheet [data-tab="evidence"]');
      await pg.waitForSelector('[data-part="evidence-logs"]', W);
    },
    async why(pg) {
      await go(pg, '/demo');
      await pg.click('[data-scenario="shell"]'); await pg.click('[data-action="demo-run"]');
      await pg.waitForSelector('[data-part="demo-outcome"][data-outcome]:not([data-outcome="running"])', { timeout: 14000 });
      await pg.waitForSelector('[data-part="why-event"]', W);
    },
    async yaml(pg, id = 'sensitive-files') {
      await go(pg, `/policies?id=${id}`);
      await pg.waitForSelector(ED, W);
      if (await pg.locator(`${ED} [data-mode="yaml"][aria-pressed="false"]`).count()) await pg.click(`${ED} [data-mode="yaml"]`);
      await pg.waitForSelector(`${ED} textarea[aria-label="정책 YAML"]`, W);
    },
    async chat(pg) {
      await go(pg, '/');
      await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(600);
      const name = await pg.evaluate(() => UI.state.audit.find((a) => !a.event.containerName.startsWith('sg-install')).event.containerName);
      await pg.evaluate(() => UI.assistant.open('chat')); // 공격 직후엔 도우미가 건 안내로 열려 단추 클릭이 닫기가 된다
      await pg.waitForSelector('[data-part="assistant"] [role="tab"][data-tab="chat"][aria-selected="true"]', W);
      await pg.waitForSelector('[data-part="chat-list"]', W);
      await pg.fill('.chat-input', `${name} 는 왜 격리됐어?`);
      await pg.keyboard.press('Enter');
      await pg.waitForSelector('[data-part="chat-list"] .chat-msg.assistant [data-part="chat-links"] a', { timeout: 15000 });
    },
  };
  // 기대값: [파일명(없으면 null), 종류 태그, 줄바꿈(pre-wrap)인가]
  const EXPECT = {
    scan: ['setup.py', 'python', false],
    event: ['event.json', 'JSON', false],
    logs: [null, 'log', true],
    why: [null, 'shell', true],
    yaml: ['sensitive-files.yaml', 'YAML', false],
    chat: ['event.json', 'JSON', false],
  };

  // 창 하나를 잰다
  const probe = (pg, sel) => pg.$eval(sel, (w) => {
    const cs = (e) => getComputedStyle(e);
    const rgb = (c) => (String(c).match(/[\d.]+/g) || []).slice(0, 3).map(Number);
    const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
    const probeColor = (v) => { const t = document.createElement('i'); t.style.color = `var(${v})`; document.body.append(t); const c = cs(t).color; t.remove(); return c; };
    const dots = [...w.querySelectorAll('.cw-head .cw-dot')];
    const body = w.querySelector('.cw-body');
    const text = body && (body.matches('textarea') ? body : body.querySelector('code') || body.querySelector('pre') || body);
    const nameEl = w.querySelector('.cw-head .cw-name'), tagEl = w.querySelector('.cw-head .cw-tag');
    const bg = body ? rgb(cs(body).backgroundColor) : [255, 255, 255], fg = text ? rgb(cs(text).color) : [0, 0, 0];
    const L1 = lum(bg), L2 = lum(fg);
    const dr = dots.map((d) => d.getBoundingClientRect());
    return {
      dots: dots.map((d, i) => [Math.round(dr[i].width), Math.round(dr[i].height), cs(d).backgroundColor, cs(d).borderRadius]),
      gap: dr.length > 1 ? Math.round(dr[1].left - dr[0].right) : null,
      danger: probeColor('--danger'),
      name: nameEl ? nameEl.textContent : null,
      nameMono: nameEl ? /monospace|Menlo|SFMono/i.test(cs(nameEl).fontFamily) : null,
      nameEllipsis: nameEl ? cs(nameEl).textOverflow === 'ellipsis' && cs(nameEl).whiteSpace === 'nowrap' : null,
      tag: tagEl ? tagEl.textContent : null,
      bgLum: L1, contrast: (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05),
      font: text ? [parseFloat(cs(text).fontSize), parseFloat(cs(text).lineHeight) / parseFloat(cs(text).fontSize), /monospace|Menlo|SFMono/i.test(cs(text).fontFamily)] : null,
      pad: body ? [parseFloat(cs(body).paddingTop), parseFloat(cs(body).paddingLeft)] : null,
      radius: body ? parseFloat(cs(body).borderTopLeftRadius) : null,
      ws: text ? cs(text).whiteSpace : null,
      card: [cs(w).borderTopWidth, cs(w).borderTopStyle, parseFloat(cs(w).borderTopLeftRadius), cs(w).boxShadow !== 'none'],
      click: w.dataset.click === '1', cursor: cs(w).cursor,
    };
  });
  const checkWin = (p, [name, tag, wrap], where) => {
    ok(p.dots.length === 3, `${where}: 점 ${p.dots.length}개`);
    ok(p.dots.every((d) => d[0] === 12 && d[1] === 12 && parseFloat(d[3]) >= 6), `${where}: 점 크기 ${JSON.stringify(p.dots)}`);
    ok(p.gap === 8, `${where}: 점 간격 ${p.gap}`);
    ok(new Set(p.dots.map((d) => d[2])).size === 3, `${where}: 점 색 셋이 같음`);
    ok(p.dots[0][2] !== p.danger, `${where}: 빨간 점이 위험 빨강(${p.danger})과 같음`);
    ok(p.name === name, `${where}: 파일명 ${JSON.stringify(p.name)} ≠ ${JSON.stringify(name)}`);
    if (name) ok(p.nameMono && p.nameEllipsis, `${where}: 파일명 고정폭 · 말줄임 ${p.nameMono} ${p.nameEllipsis}`);
    ok(p.tag === tag, `${where}: 종류 ${JSON.stringify(p.tag)} ≠ ${tag}`);
    ok(p.bgLum < 0.05, `${where}: 코드 바탕이 어둡지 않음 (밝기 ${p.bgLum.toFixed(3)})`);
    ok(p.contrast >= 4.5, `${where}: 대비 ${p.contrast.toFixed(2)}`);
    ok(p.font && p.font[0] >= 13 && p.font[0] <= 14 && Math.abs(p.font[1] - 1.5) < 0.06 && p.font[2], `${where}: 글꼴 ${JSON.stringify(p.font)}`);
    ok(p.pad && p.pad.every((x) => x >= 14 && x <= 15), `${where}: 패딩 ${JSON.stringify(p.pad)}`);
    ok(p.radius === 6, `${where}: 코드 영역 반경 ${p.radius}`);
    ok(wrap ? p.ws === 'pre-wrap' : p.ws === 'pre', `${where}: 줄바꿈 ${p.ws}`);
    ok(p.card[0] === '1px' && p.card[1] === 'solid' && p.card[2] >= 10 && p.card[2] <= 12 && p.card[3], `${where}: 카드 ${JSON.stringify(p.card)}`);
    ok(!p.click && p.cursor !== 'pointer', `${where}: 읽기 전용인데 클릭 카드 ${p.click} ${p.cursor}`);
  };
  // hover: 읽기 전용 → 떠오름 없음 · 그림자만 진해짐
  const hoverRO = async (pg, sel, where) => {
    await pg.mouse.move(2, 2); await pg.waitForTimeout(300);
    const before = await pg.$eval(sel, (w) => getComputedStyle(w).boxShadow);
    await pg.hover(`${sel} .cw-head`); await pg.waitForTimeout(350);
    const after = await pg.$eval(sel, (w) => [getComputedStyle(w).transform, getComputedStyle(w).boxShadow, getComputedStyle(w).cursor]);
    ok(after[0] === 'none', `${where}: 읽기 전용이 떠오름 ${after[0]}`);
    ok(after[1] !== before, `${where}: hover 그림자 변화 없음`);
    ok(after[2] !== 'pointer', `${where}: pointer 커서`);
  };

  for (const k of Object.keys(SEL)) {
    await T(`${k} 창 모양(라이트 · 다크) · 파일명 · 종류 · 어두운 바탕 · 대비 · 글꼴 · 줄바꿈 · 읽기 전용 hover`, async () => {
      for (const theme of ['light', 'dark']) {
        const pg = await newPage({ colorScheme: theme });
        await open[k](pg);
        await pg.waitForSelector(SEL[k], W);
        checkWin(await probe(pg, SEL[k]), EXPECT[k], `${k}/${theme}`);
        if (theme === 'light') await hoverRO(pg, SEL[k], k);
        if (k === 'scan' && theme === 'light') await shot(pg, 'scan');
        if (k === 'why' && theme === 'light') await shot(pg, 'why');
        if (k === 'yaml' && theme === 'light') await shot(pg, 'yaml');
        if (k === 'event' && theme === 'dark') await shot(pg, 'event-dark');
        await pg.done();
      }
    });
  }

  await T('강조 유지: 위협 줄 · 기능 줄 · 걸린 부분 mark(코드) · 원문 mark(시연)', async () => {
    const pg = await newPage();
    await open.scan(pg);
    ok(await pg.locator(`${SEL.scan} .code-line.hl-threat`).count() >= 3 && await pg.locator(`${SEL.scan} .code-line.hl-cap`).count() >= 1 && await pg.locator(`${SEL.scan} .code-line mark`).count() >= 1, '코드 강조');
    ok(await pg.locator(`${SEL.scan} .code-line .ln`).count() > 20, '줄 번호');
    await open.why(pg);
    ok(await pg.locator(`${SEL.why} [data-part="why-event"] mark`).count() === 1, '원문 mark');
    await pg.done();
  });

  await T('스크롤바 8px(코드 · YAML) — 넘치면 보임', async () => {
    const pg = await newPage();
    await open.scan(pg);
    const g1 = await pg.$eval(`${SEL.scan} .cw-body`, (b) => [b.scrollHeight > b.clientHeight, b.offsetWidth - b.clientWidth - parseFloat(getComputedStyle(b).borderLeftWidth) - parseFloat(getComputedStyle(b).borderRightWidth)]);
    ok(g1[0] && g1[1] === 8, `코드 스크롤바 ${JSON.stringify(g1)}`);
    await open.yaml(pg);
    const TA = `${ED} textarea[aria-label="정책 YAML"]`;
    const y = await pg.inputValue(TA);
    await pg.fill(TA, y + Array.from({ length: 80 }, (_, i) => `# ${i} ${'x'.repeat(240)}`).join('\n'));
    const g2 = await pg.$eval(`${SEL.yaml} .cw-body`, (b) => [b.matches('textarea'), b.offsetWidth - b.clientWidth - parseFloat(getComputedStyle(b).borderLeftWidth) - parseFloat(getComputedStyle(b).borderRightWidth), b.offsetHeight - b.clientHeight - parseFloat(getComputedStyle(b).borderTopWidth) - parseFloat(getComputedStyle(b).borderBottomWidth), b.scrollWidth > b.clientWidth]);
    ok(g2[0] && g2[1] === 8 && g2[2] === 8 && g2[3], `YAML 스크롤바 · 가로 스크롤 ${JSON.stringify(g2)}`);
    await pg.done();
  });

  await T('클릭 카드만 떠오름: translateY(-5px) · 그림자 · pointer, 읽기 전용 그대로 / reduced-motion 이면 이동 없음', async () => {
    for (const rm of ['no-preference', 'reduce']) {
      const pg = await newPage({ reducedMotion: rm });
      await go(pg, '/');
      ok(await pg.evaluate(() => typeof UI.codeWin === 'function'), 'UI.codeWin 없음');
      await pg.evaluate(() => { const w = UI.codeWin({ name: 'x.py', lang: 'python', href: '#/scans', body: 'print(1)' }); w.id = 'cw-click'; w.style.cssText = 'position:fixed;left:300px;top:300px;width:300px;z-index:999'; document.body.append(w); });
      const before = await pg.$eval('#cw-click', (w) => [w.dataset.click, w.tagName, getComputedStyle(w).boxShadow]);
      ok(before[0] === '1' && before[1] === 'A', `클릭 카드 표시 ${JSON.stringify(before)}`);
      await pg.hover('#cw-click .cw-head'); await pg.waitForTimeout(350);
      const after = await pg.$eval('#cw-click', (w) => [getComputedStyle(w).transform, getComputedStyle(w).boxShadow, getComputedStyle(w).cursor, getComputedStyle(w).transitionDuration]);
      if (rm === 'reduce') ok(after[0] === 'none', `reduced-motion 이동 ${after[0]}`);
      else { ok(after[0] === 'matrix(1, 0, 0, 1, 0, -5)', `떠오름 ${after[0]}`); ok(after[3].split(',').some((x) => parseFloat(x) === 0.2), `전환 0.2s ${after[3]}`); }
      ok(after[1] !== before[2] && after[2] === 'pointer', `그림자 · pointer ${JSON.stringify(after)}`);
      await pg.done();
    }
  });

  await T('정책 YAML: 같은 창 틀 안에서 입력 · 저장 전 확인 · 422 표시', async () => {
    const pg = await newPage();
    await open.yaml(pg, 'chain-download-secrets');
    const TA = `${ED} textarea[aria-label="정책 YAML"]`;
    ok(await pg.$eval(TA, (t) => !!t.closest('.code-win') && t.classList.contains('cw-body') && !t.readOnly && !t.disabled), 'YAML 입력칸이 창 틀 밖이거나 잠김');
    const y = await pg.inputValue(TA);
    await pg.click(TA); await pg.keyboard.press('End'); await pg.keyboard.type('#');
    ok((await pg.inputValue(TA)).length === y.length + 1, '입력이 안 됨');
    await pg.fill(TA, y.replace('windowSeconds: 10', 'windowSeconds: 0'));
    await pg.click(`${ED} [aria-label="저장 전 확인"]`); await pg.waitForTimeout(250);
    await pg.click('[data-part="save-check"] [aria-label="저장 후 적용"]'); await pg.waitForTimeout(300);
    const e = await pg.$eval(`${ED} .foot`, (x) => (x.querySelector('.tone-danger') || {}).textContent || '');
    ok(/422 · windowSeconds 0: 1~60/.test(e), `422 문구 「${e}」`);
    ok(await pg.locator(`${SEL.yaml} textarea[aria-label="정책 YAML"]`).count() === 1, '422 뒤 창 틀이 사라짐');
    // 1920×1080: 스크롤 없는 페이지 규칙 유지(문서 스크롤 0)
    await pg.setViewportSize({ width: 1920, height: 1080 }); await pg.waitForTimeout(300);
    const ov = await pg.evaluate(() => [document.documentElement.scrollWidth - innerWidth, document.documentElement.scrollHeight - innerHeight]);
    ok(ov[0] <= 0 && ov[1] <= 0, `1920 넘침 ${ov}`);
    await pg.done();
  });

  await T('390 · 다크: 넘침 0(코드 · 이벤트 · 정책 · 증거)', async () => {
    for (const k of ['scan', 'event', 'yaml', 'logs']) {
      const pg = await newPage({ viewport: { width: 390, height: 844 }, colorScheme: 'dark' });
      await open[k](pg);
      await pg.waitForSelector(SEL[k], W);
      // 11/05 슬라이드 패널: 패널이 미끄러져 들어오는 도중(left > 0)에 재면 넘침으로 보인다 — 패널 애니메이션이 끝난 뒤 잰다(최대 1.5초)
      await pg.evaluate(() => Promise.race([Promise.all(document.getAnimations().filter((a) => { const t = a.effect && a.effect.target; return t && t.closest && t.closest('.sheet-layer'); }).map((a) => a.finished.catch(() => {}))), new Promise((res) => setTimeout(res, 1500))]));
      const r = await pg.evaluate((sel) => { const w = document.querySelector(sel).getBoundingClientRect(); return [document.documentElement.scrollWidth - innerWidth, Math.round(w.right - innerWidth), Math.round(w.left)]; }, SEL[k]);
      ok(r[0] <= 0 && r[1] <= 0 && r[2] >= 0, `${k} 넘침 ${JSON.stringify(r)}`);
      if (k === 'scan') await shot(pg, 'mobile-dark');
      await pg.done();
    }
  });

  await T('콘솔 오류 0', async () => { ok(consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | ')); });

  await br.close();
  const pass = results.filter((r) => r[0]).length;
  for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  console.log(`codewin-1104: ${pass}/${results.length}`);
  process.exit(pass === results.length ? 0 : 1);
})();
