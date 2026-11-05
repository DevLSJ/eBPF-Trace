/* 11/05 슬라이드 패널 회귀(목업 먼저 — 확정 뒤 React). 사용자 결정 4건 모두 추천안:
   ① 폭 화면별 — 공급망 검사 · 설치 검사 = 본문 70%(최대 1080px), 이벤트 · 감사 로그 · 토폴로지 = 720px
   ② 표 옆 칸이 아니라 본문 위에 겹쳐 오른쪽에서 미끄러져 나온다 · 뒤는 살짝 어둡게(누르면 닫힘) · Esc · ✕ · 머리 「n / m ‹ ›」 · ↑↓
   ③ 적용: 공통 시트 4화면 + 토폴로지 노드 상세(오른쪽 칸에는 공격 체인만)
   ④ 내용: 주제별 블록(소제목 15px 굵게 · 구분선) · 「이름 | 값」 2열 격자 · 본문 14px
   + 768 미만 전체 화면 · 다크 · 1440 · 콘솔 오류 0
   + 11/05 하위 검증: 토스트 · 데모 제어 서랍 · 머리 알림은 패널 위 · Esc 는 맨 위(도우미 · 서랍)부터
   실행: BASE=http://127.0.0.1:8767/index.html PLAYWRIGHT=<playwright 경로> node tests/sheet-1105.cjs */
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOTS = process.env.SHOTS || `${__dirname}/../screenshots`;
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const near = (a, b, d = 2) => Math.abs(a - b) <= d;

(async () => {
  const br = await chromium.launch();
  const newPage = async (viewport = { width: 1440, height: 900 }, colorScheme = 'light') => {
    const pg = await br.newPage({ viewport, colorScheme });
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash) => { await pg.goto(`${BASE}?source=sim&as=admin#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(400); };
  const seedInstalls = async (pg, n = 3) => {
    for (let i = 0; i < n; i++) {
      const id = await pg.evaluate(() => UI.runInstallDemo('malicious'));
      await pg.waitForFunction((id) => { const s = UI.state.installs.find((x) => x.id === id); return s && s.finishedAt; }, id, { timeout: 10000 });
    }
    await pg.waitForTimeout(400);
  };
  const box = (pg, sel) => pg.$eval(sel, (e) => { const r = e.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height, right: r.right }; });
  const L = (k) => `.sheet-layer[data-layer="${k}"]`;
  const S = (k) => `.sheet-layer [data-sheet="${k}"]`;
  const hashId = (pg) => pg.evaluate(() => new URLSearchParams(location.hash.split('?')[1] || '').get('id') || '');

  await T('1 공급망 검사: 본문 위에 겹쳐 오른쪽에서 — 표 폭은 그대로, 패널 = 본문 70% · 들어올 때 미끄러짐 · 뒤 어둡게', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    const F = '[data-part="scan-form"]';
    await pg.fill(`${F} input[data-field="name"]`, 'reqeusts');
    await pg.click(`${F} button[aria-label="검사 시작"]`);
    const id = await pg.$eval('tr[data-scan]', (e) => e.dataset.scan);
    await pg.waitForSelector(`tr[data-scan="${id}"][data-status="done"]`, { timeout: 10000 });
    await pg.evaluate(() => { location.hash = '#/scans'; }); await pg.waitForTimeout(400); // 닫힌 상태에서 표 폭
    const before = await box(pg, 'table[data-table="scans"]');
    await pg.click(`tr[data-scan="${id}"]`);
    await pg.waitForSelector(S('scan'));
    const anim = await pg.$eval(S('scan'), (e) => getComputedStyle(e).animationName);
    ok(anim === 'sheet-slide-in', `들어오는 애니메이션 ${anim}`);
    await pg.waitForTimeout(500);
    const layer = await box(pg, L('scan')), sheet = await box(pg, S('scan')), after = await box(pg, 'table[data-table="scans"]');
    ok(near(after.w, before.w), `표 폭이 줄었다 ${before.w} → ${after.w} (옆 칸이면 줄어든다)`);
    ok(near(layer.x, 240) && near(layer.right, 1440) && near(layer.y, 56), `층 위치 ${JSON.stringify(layer)}`);
    ok(near(sheet.right, 1440) && near(sheet.w, Math.min(1080, layer.w * 0.7)), `패널 폭 ${sheet.w} (본문 ${layer.w} × 0.7)`);
    ok(sheet.x < after.right, '패널이 표 위를 덮지 않는다');
    const bg = await pg.$eval(L('scan'), (e) => getComputedStyle(e).backgroundColor);
    ok(/rgba\(15, 23, 42, 0\.2[0-9]*\)/.test(bg), `뒤 어둡게 ${bg}`);
    ok(await pg.$eval(S('scan'), (e) => e.getAttribute('role')) === 'dialog', 'role=dialog');
    await pg.screenshot({ path: `${SHOTS}/1105-scan-sheet.png` });
    await pg.close();
  });

  await T('2 내용: 소제목 15px 굵게 · 블록 사이 구분선 · 「이름 | 값」 2열(이름 칸 8.5rem) · 본문 14px · 머리 제목 16px', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    await seedInstalls(pg, 1);
    await pg.locator('tbody tr[data-id]').first().click();
    await pg.waitForSelector(S('install')); await pg.waitForTimeout(400);
    const st = await pg.$eval(S('install'), (e) => {
      const h3 = e.querySelector('.sheet-section > h3'), dl = e.querySelector('.sheet-section .dl'), body = e.querySelector('.sheet-body'), h2 = e.querySelector('.sheet-head h2');
      const secs = [...e.querySelectorAll('.sheet-body > .sheet-section')];
      const cs = (x) => getComputedStyle(x);
      return { h3: [cs(h3).fontSize, cs(h3).fontWeight], dl: cs(dl).gridTemplateColumns, body: cs(body).fontSize, h2: cs(h2).fontSize, borders: secs.slice(1).map((s) => cs(s).borderTopWidth), n: secs.length };
    });
    ok(st.h3[0] === '15px' && Number(st.h3[1]) >= 600, `소제목 ${st.h3}`);
    ok(/^136px /.test(st.dl), `2열 격자 ${st.dl}`);
    ok(st.body === '14px' && st.h2 === '16px', `글씨 본문 ${st.body} · 제목 ${st.h2}`);
    ok(st.n >= 3 && st.borders.every((b) => b === '1px'), `블록 ${st.n}개 · 구분선 ${st.borders}`);
    await pg.close();
  });

  await T('3 이전/다음: 머리 「1 / n」 · ‹ 비활성 · › 와 ↓ 는 다음 행(주소 ?id) · 되풀이 애니메이션 없음 · ↑ 는 앞으로', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    await seedInstalls(pg, 3);
    const ids = await pg.$$eval('tbody tr[data-id]', (els) => els.map((e) => e.dataset.id));
    ok(ids.length >= 3, `행 ${ids.length}`);
    await pg.click(`tbody tr[data-id="${ids[0]}"]`);
    await pg.waitForSelector(S('install')); await pg.waitForTimeout(400);
    ok((await pg.textContent(`${S('install')} [data-part="sheet-pos"]`)) === `1 / ${ids.length}`, '위치 표시');
    ok(await pg.$eval(`${S('install')} [data-action="sheet-prev"]`, (b) => b.disabled), '첫 행인데 ‹ 활성');
    await pg.click(`${S('install')} [data-action="sheet-next"]`); await pg.waitForTimeout(300);
    ok((await hashId(pg)) === ids[1], `› 뒤 id ${await hashId(pg)}`);
    ok(await pg.$eval(L('install'), (e) => e.classList.contains('still')), '다음으로 넘길 때 다시 미끄러진다');
    await pg.keyboard.press('ArrowDown'); await pg.waitForTimeout(300);
    ok((await hashId(pg)) === ids[2], `↓ 뒤 id ${await hashId(pg)}`);
    ok((await pg.textContent(`${S('install')} [data-part="sheet-pos"]`)) === `3 / ${ids.length}`, '위치 표시 3');
    await pg.keyboard.press('ArrowUp'); await pg.waitForTimeout(300);
    ok((await hashId(pg)) === ids[1], `↑ 뒤 id ${await hashId(pg)}`);
    ok(await pg.locator(`tbody tr[data-id="${ids[1]}"].selected`).count() === 1, '표의 선택 행이 따라오지 않음');
    await pg.close();
  });

  await T('4 닫기: Esc · 어두운 곳 · ✕ — 미끄러져 나가고(closing) 주소 ?id 비움, 패널 안 클릭은 닫지 않음', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    await seedInstalls(pg, 1);
    const row = pg.locator('tbody tr[data-id]').first();
    for (const how of ['inside', 'esc', 'scrim', 'x']) {
      await row.click(); await pg.waitForSelector(S('install')); await pg.waitForTimeout(350);
      if (how === 'inside') { await pg.click(`${S('install')} .sheet-body`, { position: { x: 20, y: 20 } }); await pg.waitForTimeout(300); ok(await pg.locator(L('install')).count() === 1, '패널 안 클릭에 닫힘'); ok(!(await row.isEnabled()) || await pg.evaluate(() => { const r = document.querySelector('tbody tr[data-id]').getBoundingClientRect(); return document.elementFromPoint(r.x + 20, r.y + r.height / 2)?.classList.contains('sheet-layer'); }), '열린 동안 뒤 표가 눌린다'); await pg.keyboard.press('Escape'); await pg.waitForTimeout(400); continue; }
      if (how === 'esc') await pg.keyboard.press('Escape');
      if (how === 'scrim') await pg.mouse.click(400, 500);
      if (how === 'x') await pg.click(`${S('install')} [data-action="sheet-close"]`);
      await pg.waitForTimeout(60);
      ok(await pg.locator(`${L('install')}.closing`).count() === 1, `${how}: 나가는 애니메이션 없음`);
      await pg.waitForTimeout(350);
      ok(await pg.locator(L('install')).count() === 0, `${how}: 안 닫힘`);
      ok((await hashId(pg)) === '', `${how}: 주소 id 남음`);
    }
    // 입력 칸에서 Esc 는 패널을 닫지 않는다
    await row.click(); await pg.waitForSelector(S('install')); await pg.waitForTimeout(350);
    await pg.evaluate(() => { const i = document.createElement('input'); i.id = 'tmp-in'; document.querySelector('[data-sheet="install"] .sheet-body').prepend(i); i.focus(); });
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(300);
    ok(await pg.locator(L('install')).count() === 1, '입력 칸 Esc 에 닫힘');
    await pg.close();
  });

  await T('5 화면별 폭(1440): 설치 검사 840 · 이벤트 · 감사 로그 720 — 모두 오른쪽 끝에 붙고 위치 표시', async () => {
    const pg = await newPage();
    await go(pg, '/installs'); await seedInstalls(pg, 2);
    for (const [hash, kind, click, w] of [['/installs', 'install', 'tbody tr[data-id]', 840], ['/events', 'event', '.feed-row', 720], ['/audit', 'audit', 'tbody tr.clickable', 720]]) {
      await pg.evaluate((h) => { location.hash = '#' + h; }, hash); await pg.waitForTimeout(500);
      await pg.waitForSelector(click, { timeout: 10000 });
      await pg.locator(click).first().click();
      await pg.waitForSelector(S(kind)); await pg.waitForTimeout(400);
      const b = await box(pg, S(kind));
      ok(near(b.w, w) && near(b.right, 1440), `${kind} 폭 ${b.w} 오른쪽 ${b.right}`);
      ok(/^1 \/ \d+$/.test(await pg.textContent(`${S(kind)} [data-part="sheet-pos"]`)), `${kind} 위치 표시`);
      await pg.keyboard.press('Escape'); await pg.waitForTimeout(350);
    }
    await pg.close();
  });

  await T('6 토폴로지: 노드를 고르면 노드 · 건 카드는 패널(720) 안 · 오른쪽 칸에는 공격 체인만 · 판정 버튼은 패널 안', async () => {
    const pg = await newPage();
    await go(pg, '/topology');
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(1300);
    ok(await pg.locator('.sheet-layer').count() === 0, '고르기 전 패널');
    await pg.click('.topo-side .chain-head:has-text("pkg-reqeusts")');
    await pg.waitForSelector(S('topo')); await pg.waitForTimeout(400);
    const b = await box(pg, S('topo'));
    ok(near(b.w, 720) && near(b.right, 1440), `토폴로지 폭 ${b.w}`);
    ok(await pg.locator(`${S('topo')} .case-card [data-part="decision"]`).count() === 1, '패널 안 판정 카드');
    ok(await pg.locator('.topo-side .case-card, .topo-side [data-part="node"]').count() === 0, '오른쪽 칸에 노드 · 건 카드가 남음');
    ok(await pg.locator('.topo-side .chain-head').count() >= 1, '오른쪽 칸 공격 체인');
    ok((await pg.textContent(`${S('topo')} .sheet-head h2`)).includes('pkg-reqeusts'), '패널 제목');
    await pg.screenshot({ path: `${SHOTS}/1105-topo-sheet.png` });
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(350);
    ok(await pg.locator('.sheet-layer').count() === 0, 'Esc 로 안 닫힘');
    await pg.close();
  });

  await T('7 768 미만(390): 전체 화면 · 다크: 뒤 어둡게가 더 진함', async () => {
    let pg = await newPage({ width: 390, height: 844 });
    await go(pg, '/installs'); await seedInstalls(pg, 1);
    await pg.locator('tbody tr[data-id]').first().click();
    await pg.waitForSelector(S('install')); await pg.waitForTimeout(400);
    const b = await box(pg, S('install'));
    ok(near(b.x, 0) && near(b.w, 390) && near(b.y, 0), `390 전체 화면 ${JSON.stringify(b)}`);
    const ov = await pg.evaluate(() => document.documentElement.scrollWidth - innerWidth);
    ok(ov <= 0, `가로 넘침 ${ov}`);
    await pg.close();
    pg = await newPage(undefined, 'dark');
    await go(pg, '/audit');
    await pg.locator('tbody tr.clickable').first().click();
    await pg.waitForSelector(S('audit')); await pg.waitForTimeout(400);
    const bg = await pg.$eval(L('audit'), (e) => getComputedStyle(e).backgroundColor);
    ok(/rgba\(0, 0, 0, 0\.4[0-9]*\)/.test(bg), `다크 뒤 ${bg}`);
    await pg.screenshot({ path: `${SHOTS}/1105-audit-dark.png` });
    await pg.close();
  });

  await T('9 패널 위: 토스트 · 데모 제어 서랍은 패널 층 위(누르면 그것이 눌림) · 도우미가 열려 있으면 Esc 는 도우미만 닫고, 다음 Esc 에 패널', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    await seedInstalls(pg, 1);
    await pg.locator('tbody tr[data-id]').first().click();
    await pg.waitForSelector(S('install')); await pg.waitForTimeout(400);
    const toast = await pg.evaluate(() => { const t = document.querySelector('.toasts .toast'); if (!t) return 'no-toast'; const r = t.getBoundingClientRect(); const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2); return !!top && !!top.closest('.toasts'); });
    ok(toast === true, `토스트가 패널 층 아래 ${toast}`);
    await pg.evaluate(() => document.getElementById('demo').classList.add('open')); await pg.waitForTimeout(300);
    const drawer = await pg.evaluate(() => { const r = document.getElementById('demo').getBoundingClientRect(); const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2); return !!top && !!top.closest('#demo'); });
    ok(drawer, '데모 제어 서랍이 패널 층 아래');
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(350);
    ok(await pg.locator(L('install')).count() === 1, '서랍이 열려 있는데 Esc 가 패널을 닫음');
    await pg.evaluate(() => document.getElementById('demo').classList.remove('open')); await pg.waitForTimeout(300);
    await pg.click('.assist-fab'); await pg.waitForSelector('[data-part="assistant"]:not([hidden])');
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(350);
    ok(await pg.locator('[data-part="assistant"][hidden]').count() === 1, 'Esc 에 도우미가 안 닫힘');
    ok(await pg.locator(L('install')).count() === 1, '도우미와 패널이 함께 닫힘');
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(350);
    ok(await pg.locator(L('install')).count() === 0, '두 번째 Esc 에 패널이 안 닫힘');
    await pg.close();
  });

  await T('8 콘솔 오류 0', async () => { ok(consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | ')); });

  await br.close();
  for (const [p, n, m] of results) console.log(`${p ? 'PASS' : 'FAIL'}  ${n}${m ? '  — ' + m : ''}`);
  const pass = results.filter((r) => r[0]).length;
  console.log(`\nsheet-1105: ${pass}/${results.length}`);
  process.exit(pass === results.length ? 0 : 1);
})();
