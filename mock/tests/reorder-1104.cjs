/* 11/04d 길게 눌러 순서 바꾸기 회귀 — 사이드바 메뉴(묶음 안에서만) · 대시보드 종합 숫자 칸 · (eval 연결 뒤) 평가 지표 6칸
   1 사이드바: 0.4초 누르면 「집힘」(떠오름 · 자리 표시 · grabbing) → 끌어 놓으면 묶음 안 순서가 바뀜 · 이동 없음 · 저장 · 알림
   2 묶음 밖으로는 안 옮겨짐 · 대시보드 항목은 맨 위 고정(길게 눌러도 집히지 않음)
   3 짧은 클릭(0.4초 전 뗌)은 지금처럼 이동
   4 누른 뒤 0.4초 안에 8px 넘게 움직이면 취소(집히지 않음 · 순서 그대로)
   5 Esc → 원래 자리 · 놓아도 이동 없음 · 저장 안 함
   6 키보드 Alt+↑/↓(사이드바) · Alt+←/→(카드) 한 칸 · 포커스 유지 · aria-live 알림 · 끝에서는 그대로
   7 새로고침 뒤 유지(localStorage supplyguard.layout {v:1, sidebar, dashboardKpi})
   8 깨진 저장값(JSON 오류 · v 다름 · 모양 틀림) → 기본 순서 · 콘솔 오류 없음
   9 모르는 id 는 버리고 새 항목은 기본 순서 자리에 끼움
   10 대시보드 KPI 끌어 놓기 · 클릭 이동 없음 · 데이터가 다시 그려져도 순서 유지
   11 설정 「화면 배치 기본 순서로」 → 확인 없이 즉시 · 토스트 · 사이드바 · 대시보드 기본 순서
   12 다크: 자리 표시 · 집힌 칸 색이 토큰(다크 accent · surface)
   13 390 터치: 서랍 사이드바에서 길게 눌러 끌기(서랍 열린 채 · 이동 없음 · 스크롤 없음) · KPI 2열 끌기 · 짧은 탭은 이동
   14 prefers-reduced-motion: 다른 항목 이동 애니메이션(transform) 없음
   15 평가 지표 6칸 끌기 · Alt+→ · 유지 · 기본 순서로
   콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8768 --bind 127.0.0.1 → BASE=http://127.0.0.1:8768/index.html PLAYWRIGHT=<playwright 경로> node tests/reorder-1104.cjs
         (VERBOSE=1 · ONLY=정규식 · SHOTS=1 → screenshots/reorder-1104-{desktop,dark,mobile}.png · EVAL_SORT=1 → 15번) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = (process.env.BASE || 'http://127.0.0.1:8768').replace(/\/index\.html$/, '').replace(/\/$/, '') + '/index.html';
const SHOTS = process.env.SHOTS === '1';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
const KEY = 'supplyguard.layout';
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const NAV_DEFAULT = ['/', '/installs', '/scans', '/evaluation', '/events', '/topology', '/policies', '/audit', '/settings'];
const KPI_DEFAULT = ['collected', 'violations', 'isolated', 'installs', 'decided', 'isolation'];
const EVAL_DEFAULT = ['static-detection', 'static-fpr', 'runtime-detection', 'runtime-fpr', 'latency', 'model-f1'];

(async () => {
  const br = await chromium.launch();
  const newPage = async (opts = {}) => {
    const ctx = await br.newContext(Object.assign({ viewport: { width: 1440, height: 900 } }, opts));
    const pg = await ctx.newPage();
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    pg.done = () => ctx.close();
    return pg;
  };
  const go = async (pg, hash, extra = '') => { await pg.goto(`${BASE}?source=sim&as=admin${extra}#${hash}`); await pg.waitForSelector('.page-title', { timeout: 6000 }); await pg.waitForTimeout(450); };
  const navOrder = (pg) => pg.$$eval('.side-nav .nav-link', (els) => els.map((e) => e.dataset.to));
  const kpiOrder = (pg) => pg.$$eval('.ov-kpis > [data-kpi]', (els) => els.map((e) => e.dataset.kpi));
  const evalOrder = (pg) => pg.$$eval('.eval-kpis > [data-kpi]', (els) => els.map((e) => e.dataset.kpi));
  const stored = (pg) => pg.evaluate((k) => localStorage.getItem(k), KEY);
  const live = (pg) => pg.$eval('#sg-sort-live', (e) => e.textContent.trim()).catch(() => '');
  const hash = (pg) => pg.evaluate(() => location.hash);
  const picked = (pg) => pg.$$eval('.sg-sort-picked', (els) => els.length);
  // 숫자 칸은 시뮬 데이터로 자주 다시 그려진다 — 잰 순간 떨어져 나가 null 이면 다시 잰다
  const center = async (pg, sel) => { let b = null; for (let i = 0; i < 6 && !b; i++) { b = await pg.locator(sel).first().boundingBox().catch(() => null); if (!b) await pg.waitForTimeout(80); } ok(b, `상자 없음 ${sel}`); return { x: b.x + b.width / 2, y: b.y + b.height / 2, w: b.width, h: b.height }; };
  const shot = async (pg, name) => { if (!SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.screenshot({ path: path.join(SHOT_DIR, `reorder-1104-${name}.png`) }); };
  // 마우스로 길게 눌러(0.55초) 끌기 — to 의 중심 + (dx, dy) 로 8단계 이동. release=false 면 누른 채 돌려준다
  async function drag(pg, from, to, { dx = 0, dy = 0, release = true, hold = 550 } = {}) {
    const a = await center(pg, from), b = await center(pg, to);
    await pg.mouse.move(a.x, a.y); await pg.mouse.down(); await pg.waitForTimeout(hold);
    for (let i = 1; i <= 8; i++) { await pg.mouse.move(a.x + (b.x + dx - a.x) * i / 8, a.y + (b.y + dy - a.y) * i / 8); await pg.waitForTimeout(16); }
    await pg.waitForTimeout(250);
    if (release) { await pg.mouse.up(); await pg.waitForTimeout(350); }
  }
  // 터치(CDP) 길게 눌러 끌기
  async function touchDrag(pg, from, to, { dx = 0, dy = 0, release = true, hold = 600 } = {}) {
    const cdp = pg.cdp || (pg.cdp = await pg.context().newCDPSession(pg));
    const a = await center(pg, from), b = await center(pg, to);
    await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x: a.x, y: a.y }] });
    await pg.waitForTimeout(hold);
    for (let i = 1; i <= 10; i++) { await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x: a.x + (b.x + dx - a.x) * i / 10, y: a.y + (b.y + dy - a.y) * i / 10 }] }); await pg.waitForTimeout(20); }
    await pg.waitForTimeout(250);
    if (release) { await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] }); await pg.waitForTimeout(400); }
    return cdp;
  }

  await T('1 사이드바: 0.4초 누르면 집힘(떠오름 · 자리 표시 · grabbing) → 끌어 놓으면 묶음 안 순서 변경 · 이동 없음 · 저장 · 알림', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    ok(same(await navOrder(pg), NAV_DEFAULT), `처음 순서 ${await navOrder(pg)}`);
    const h0 = await hash(pg);
    // 0.25초에는 아직 안 집힘
    const a = await center(pg, '.nav-link[data-to="/evaluation"]');
    await pg.mouse.move(a.x, a.y); await pg.mouse.down(); await pg.waitForTimeout(250);
    ok(await picked(pg) === 0, '0.25초에 이미 집힘');
    await pg.waitForTimeout(300);
    ok(await picked(pg) === 1, '0.55초에 집히지 않음');
    const st = await pg.evaluate(() => { const el = document.querySelector('.sg-sort-picked'); const cs = getComputedStyle(el); return { to: el.dataset.to, shadow: cs.boxShadow, cursor: cs.cursor, marker: document.querySelectorAll('.side-nav .sg-sort-marker').length, sorting: document.documentElement.classList.contains('sg-sorting') }; });
    ok(st.to === '/evaluation' && st.shadow !== 'none' && st.cursor === 'grabbing' && st.marker === 1 && st.sorting, `집힌 모습 ${JSON.stringify(st)}`);
    const b = await center(pg, '.nav-link[data-to="/installs"]');
    for (let i = 1; i <= 8; i++) { await pg.mouse.move(a.x, a.y + (b.y - 6 - a.y) * i / 8); await pg.waitForTimeout(16); }
    await pg.waitForTimeout(250);
    ok(same(await navOrder(pg), ['/', '/evaluation', '/installs', '/scans', ...NAV_DEFAULT.slice(4)]), `끄는 중 순서 ${await navOrder(pg)}`);
    await shot(pg, 'desktop');
    await pg.mouse.up(); await pg.waitForTimeout(400);
    ok(await picked(pg) === 0 && !(await pg.$('.sg-sort-marker')), '놓은 뒤 집힘 · 자리 표시가 남음');
    ok(await hash(pg) === h0, `놓았는데 이동함 ${await hash(pg)}`);
    ok(same(await navOrder(pg), ['/', '/evaluation', '/installs', '/scans', ...NAV_DEFAULT.slice(4)]), `놓은 뒤 순서 ${await navOrder(pg)}`);
    const s = JSON.parse(await stored(pg) || 'null');
    ok(s && s.v === 1 && same(s.sidebar.install, ['evaluation', 'installs', 'scans']), `저장 ${JSON.stringify(s)}`);
    ok(/평가를 1번째로 옮김/.test(await live(pg)), `알림 「${await live(pg)}」`);
    ok(await pg.$eval('#sg-sort-live', (e) => e.getAttribute('aria-live')) === 'polite', 'aria-live');
    await pg.done();
  });

  await T('2 묶음 밖으로는 안 옮겨짐 · 대시보드 항목은 맨 위 고정', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    await drag(pg, '.nav-link[data-to="/topology"]', '.nav-link[data-to="/installs"]', { dy: -6 });
    ok(same(await navOrder(pg), ['/', '/installs', '/scans', '/evaluation', '/topology', '/events', '/policies', '/audit', '/settings']), `토폴로지는 런타임 묶음 맨 앞까지만 ${await navOrder(pg)}`);
    await drag(pg, '.nav-link[data-to="/installs"]', '.nav-link[data-to="/"]', { dy: -10 });
    ok((await navOrder(pg))[0] === '/' && (await navOrder(pg))[1] === '/installs', `대시보드 위로 못 감 ${await navOrder(pg)}`);
    await drag(pg, '.nav-link[data-to="/policies"]', '.nav-link[data-to="/events"]', { release: false });
    ok(await picked(pg) === 1, '정책이 집히지 않음');
    ok((await navOrder(pg)).indexOf('/policies') === 6, `설정 · 기록 묶음을 벗어남 ${await navOrder(pg)}`);
    await pg.mouse.up(); await pg.waitForTimeout(300);
    // 대시보드는 길게 눌러도 집히지 않고, 떼면 지금처럼 이동
    const d = await center(pg, '.nav-link[data-to="/"]');
    await pg.mouse.move(d.x, d.y); await pg.mouse.down(); await pg.waitForTimeout(550);
    ok(await picked(pg) === 0, '대시보드가 집힘');
    await pg.mouse.up(); await pg.waitForTimeout(400);
    ok(await hash(pg) === '#/', `대시보드 클릭 이동 안 됨 ${await hash(pg)}`);
    await pg.done();
  });

  await T('3 짧은 클릭(0.4초 전 뗌)은 지금처럼 이동', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const c = await center(pg, '.nav-link[data-to="/events"]');
    await pg.mouse.move(c.x, c.y); await pg.mouse.down(); await pg.waitForTimeout(150); await pg.mouse.up(); await pg.waitForTimeout(400);
    ok(await hash(pg) === '#/events', `이동 안 됨 ${await hash(pg)}`);
    await pg.click('.nav-link[data-to="/scans"]'); await pg.waitForTimeout(300);
    ok(await hash(pg) === '#/scans', 'click() 이동 안 됨');
    ok(await stored(pg) === null, '클릭만 했는데 저장됨');
    await pg.done();
  });

  await T('4 누른 뒤 0.4초 안에 8px 넘게 움직이면 취소(집히지 않음 · 순서 그대로)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const c = await center(pg, '.nav-link[data-to="/scans"]');
    await pg.mouse.move(c.x, c.y); await pg.mouse.down(); await pg.waitForTimeout(80);
    await pg.mouse.move(c.x + 12, c.y, { steps: 3 }); await pg.waitForTimeout(600);
    ok(await picked(pg) === 0, '8px 넘게 움직였는데 집힘');
    const b = await center(pg, '.nav-link[data-to="/installs"]');
    await pg.mouse.move(c.x + 12, b.y - 6, { steps: 4 }); await pg.waitForTimeout(150);
    await pg.mouse.up(); await pg.waitForTimeout(300);
    ok(same(await navOrder(pg), NAV_DEFAULT), `순서 바뀜 ${await navOrder(pg)}`);
    ok(await stored(pg) === null, '저장됨');
    // 7px 흔들림은 그대로 집힌다
    await pg.mouse.move(c.x, c.y); await pg.mouse.down(); await pg.waitForTimeout(80); await pg.mouse.move(c.x + 5, c.y + 4, { steps: 2 }); await pg.waitForTimeout(500);
    ok(await picked(pg) === 1, '작은 흔들림(6px)에 집히지 않음');
    await pg.keyboard.press('Escape'); await pg.mouse.up(); await pg.waitForTimeout(200);
    await pg.done();
  });

  await T('5 Esc → 원래 자리 · 놓아도 이동 없음 · 저장 안 함', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    await drag(pg, '.nav-link[data-to="/settings"]', '.nav-link[data-to="/policies"]', { dy: -6, release: false });
    ok(same(await navOrder(pg), ['/', '/installs', '/scans', '/evaluation', '/events', '/topology', '/settings', '/policies', '/audit']), `끄는 중 ${await navOrder(pg)}`);
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(250);
    ok(same(await navOrder(pg), NAV_DEFAULT), `Esc 뒤 원래 자리 아님 ${await navOrder(pg)}`);
    ok(await picked(pg) === 0 && !(await pg.$('.sg-sort-marker')), 'Esc 뒤 집힘이 남음');
    await pg.mouse.up(); await pg.waitForTimeout(400);
    ok(await hash(pg) === '#/audit', `Esc 뒤 놓았는데 이동 ${await hash(pg)}`);
    ok(await stored(pg) === null, 'Esc 했는데 저장됨');
    ok(/취소/.test(await live(pg)), `취소 알림 「${await live(pg)}」`);
    await pg.done();
  });

  await T('6 키보드 Alt+↑/↓ · Alt+←/→ 한 칸 · 포커스 유지 · 알림 · 끝에서는 그대로', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.focus('.nav-link[data-to="/scans"]');
    await pg.keyboard.press('Alt+ArrowUp'); await pg.waitForTimeout(150);
    ok(same((await navOrder(pg)).slice(1, 4), ['/scans', '/installs', '/evaluation']), `Alt+↑ ${await navOrder(pg)}`);
    ok(await pg.evaluate(() => document.activeElement && document.activeElement.dataset.to) === '/scans', '포커스를 잃음');
    ok(/공급망 검사를 1번째로 옮김/.test(await live(pg)), `알림 「${await live(pg)}」`);
    await pg.keyboard.press('Alt+ArrowUp'); await pg.waitForTimeout(150);
    ok(same((await navOrder(pg)).slice(0, 4), ['/', '/scans', '/installs', '/evaluation']), `맨 앞에서 Alt+↑ 는 그대로 ${await navOrder(pg)}`);
    ok(/맨 앞/.test(await live(pg)), `맨 앞 알림 「${await live(pg)}」`);
    await pg.keyboard.press('Alt+ArrowDown'); await pg.keyboard.press('Alt+ArrowDown'); await pg.waitForTimeout(150);
    ok(same((await navOrder(pg)).slice(1, 4), ['/installs', '/evaluation', '/scans']), `Alt+↓ 두 번 ${await navOrder(pg)}`);
    ok(same(JSON.parse(await stored(pg)).sidebar.install, ['installs', 'evaluation', 'scans']), '키보드 이동 저장');
    // 사이드바는 ←/→ 로 움직이지 않는다
    await pg.keyboard.press('Alt+ArrowLeft'); await pg.waitForTimeout(100);
    ok(same((await navOrder(pg)).slice(1, 4), ['/installs', '/evaluation', '/scans']), '사이드바가 Alt+← 로 움직임');
    // 카드: Alt+→ · Alt+←
    await pg.focus('.ov-kpis > [data-kpi="collected"]');
    await pg.keyboard.press('Alt+ArrowRight'); await pg.waitForTimeout(150);
    ok(same((await kpiOrder(pg)).slice(0, 2), ['violations', 'collected']), `Alt+→ ${await kpiOrder(pg)}`);
    ok(await pg.evaluate(() => document.activeElement && document.activeElement.dataset.kpi) === 'collected', 'KPI 포커스를 잃음');
    ok(/수집한 이벤트를 2번째로 옮김/.test(await live(pg)), `KPI 알림 「${await live(pg)}」`);
    await pg.keyboard.press('Alt+ArrowLeft'); await pg.waitForTimeout(150);
    ok(same(await kpiOrder(pg), KPI_DEFAULT), `Alt+← ${await kpiOrder(pg)}`);
    ok(await hash(pg) === '#/', '키보드 이동 중 화면 이동');
    await pg.done();
  });

  await T('7 새로고침 뒤 유지(사이드바 · 대시보드 KPI)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await drag(pg, '.nav-link[data-to="/topology"]', '.nav-link[data-to="/events"]', { dy: -6 });
    // 시뮬 데이터가 주기적으로 숫자 칸을 다시 그려 잡아 둔 요소가 교체될 수 있다 — 매번 새로 찾아 스크롤(11/04d 흔들림 수정)
    await pg.evaluate(() => document.querySelector('.ov-kpis > [data-kpi="isolation"]').scrollIntoView({ block: 'center' }));
    const c = await center(pg, '.ov-kpis > [data-kpi="collected"]');
    await drag(pg, '.ov-kpis > [data-kpi="isolation"]', '.ov-kpis > [data-kpi="collected"]', { dx: -c.w / 4 });
    const nav = await navOrder(pg), kpi = await kpiOrder(pg);
    ok(kpi[0] === 'isolation', `KPI 끌기 ${kpi}`);
    await pg.reload(); await pg.waitForSelector('.ov-kpis > [data-kpi]', { timeout: 6000 }); await pg.waitForTimeout(400);
    ok(same(await navOrder(pg), nav), `새로고침 뒤 사이드바 ${await navOrder(pg)}`);
    ok(same(await kpiOrder(pg), kpi), `새로고침 뒤 KPI ${await kpiOrder(pg)}`);
    const s = JSON.parse(await stored(pg));
    ok(same(Object.keys(s).sort(), ['dashboardKpi', 'sidebar', 'v']) && same(s.sidebar.runtime, ['topology', 'events']) && same(s.dashboardKpi, kpi), `저장 모양 ${JSON.stringify(s)}`);
    await pg.done();
  });

  await T('8 깨진 저장값(JSON 오류 · v 다름 · 모양 틀림) → 기본 순서 · 콘솔 오류 없음', async () => {
    for (const bad of ['{oops', '"text"', 'null', '[1,2]', JSON.stringify({ v: 2, sidebar: { install: ['evaluation', 'installs', 'scans'] } }), JSON.stringify({ v: 1, sidebar: { install: 'evaluation' }, dashboardKpi: { a: 1 } }), JSON.stringify({ v: 1, sidebar: [1, 2], dashboardKpi: [3, null, 'isolation', 'collected'] })]) {
      const pg = await newPage();
      const before = consoleErrors.length;
      await pg.addInitScript(([k, v]) => { if (!sessionStorage.getItem('seeded')) { localStorage.setItem(k, v); sessionStorage.setItem('seeded', '1'); } }, [KEY, bad]);
      await go(pg, '/');
      await pg.waitForSelector('.ov-kpis > [data-kpi]', { timeout: 6000 });
      const nav = await navOrder(pg), kpi = await kpiOrder(pg);
      const wantKpi = bad.includes('"isolation"') ? ['isolation', ...KPI_DEFAULT.filter((x) => x !== 'isolation')] : KPI_DEFAULT; // 숫자 · null 은 버리고 문자열 id 만(isolation · collected → 나머지는 collected 뒤 기본 순서)
      ok(same(nav, NAV_DEFAULT), `${bad} → 사이드바 ${nav}`);
      ok(same(kpi, wantKpi), `${bad} → KPI ${kpi}`);
      // 깨진 값이 있어도 끌어 놓으면 새 값으로 저장
      await pg.focus('.nav-link[data-to="/installs"]'); await pg.keyboard.press('Alt+ArrowDown'); await pg.waitForTimeout(100);
      const s = JSON.parse(await stored(pg));
      ok(s.v === 1 && same(s.sidebar.install, ['scans', 'installs', 'evaluation']), `${bad} → 다시 저장 ${JSON.stringify(s)}`);
      ok(consoleErrors.length === before, `${bad} → 콘솔 오류 ${consoleErrors.slice(before).join(' | ')}`);
      await pg.done();
    }
  });

  await T('9 모르는 id 는 버리고 새 항목은 기본 순서 자리에 끼움', async () => {
    const pg = await newPage();
    const saved = { v: 1, sidebar: { install: ['ghost', 'evaluation', 'installs', 'evaluation'], runtime: ['topology'], gone: ['x'] }, dashboardKpi: ['isolation', 'nope', 'collected'], evaluationKpi: ['zzz'] };
    await pg.addInitScript(([k, v]) => { if (!sessionStorage.getItem('seeded')) { localStorage.setItem(k, v); sessionStorage.setItem('seeded', '1'); } }, [KEY, JSON.stringify(saved)]);
    await go(pg, '/');
    await pg.waitForSelector('.ov-kpis > [data-kpi]', { timeout: 6000 });
    // install: ghost · 중복 버림 → evaluation, installs + 새 scans 는 기본 순서의 앞 항목(installs) 뒤. runtime: 저장에 없는 events 는 기본 자리(맨 앞)
    ok(same(await navOrder(pg), ['/', '/evaluation', '/installs', '/scans', '/events', '/topology', '/policies', '/audit', '/settings']), `사이드바 ${await navOrder(pg)}`);
    ok(same(await kpiOrder(pg), ['isolation', 'collected', 'violations', 'isolated', 'installs', 'decided']), `KPI ${await kpiOrder(pg)}`);
    await pg.done();
  });

  await T('10 대시보드 KPI 끌어 놓기 · 클릭 이동 없음 · 다시 그려져도 순서 유지', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.waitForSelector('.ov-kpis > [data-kpi]', { timeout: 6000 });
    ok(same(await kpiOrder(pg), KPI_DEFAULT), `처음 ${await kpiOrder(pg)}`);
    const c = await center(pg, '.ov-kpis > [data-kpi="violations"]');
    await drag(pg, '.ov-kpis > [data-kpi="decided"]', '.ov-kpis > [data-kpi="violations"]', { dx: -c.w / 4, release: false });
    ok(await picked(pg) === 1 && await pg.$$eval('.ov-kpis > .sg-sort-marker', (e) => e.length) === 1, '집힘 · 자리 표시 없음');
    ok(same(await kpiOrder(pg), ['collected', 'decided', 'violations', 'isolated', 'installs', 'isolation']), `끄는 중 ${await kpiOrder(pg)}`);
    await pg.mouse.up(); await pg.waitForTimeout(400);
    ok(await hash(pg) === '#/', `KPI 놓았는데 이동 ${await hash(pg)}`);
    ok(same(JSON.parse(await stored(pg)).dashboardKpi, ['collected', 'decided', 'violations', 'isolated', 'installs', 'isolation']), '저장');
    // 숫자 칸이 다시 그려져도(기간 바꿈 → 새 요소) 순서 유지
    await pg.$$eval('.ov-kpis > [data-kpi]', (els) => els.forEach((e) => { e.dataset.old = '1'; }));
    await pg.click('[data-range="1h"]');
    await pg.waitForFunction(() => document.querySelector('.ov-kpis > [data-kpi]') && !document.querySelector('.ov-kpis > [data-kpi][data-old]'), null, { timeout: 8000 });
    ok(same(await kpiOrder(pg), ['collected', 'decided', 'violations', 'isolated', 'installs', 'isolation']), `다시 그린 뒤 ${await kpiOrder(pg)}`);
    // 끄는 동안(누르고 있는 동안)에는 다시 그리지 않고, 놓은 뒤 미뤄 둔 값으로 그린다
    await drag(pg, '.ov-kpis > [data-kpi="isolated"]', '.ov-kpis > [data-kpi="isolated"]', { release: false });
    await pg.$$eval('.ov-kpis > [data-kpi]', (els) => els.forEach((e) => { e.dataset.old = '2'; }));
    await pg.evaluate(() => document.querySelector('[data-range="24h"]').click()); await pg.waitForTimeout(500);
    ok(await pg.$$eval('.ov-kpis > [data-kpi][data-old="2"]', (e) => e.length) === 6 && await picked(pg) === 1, '끄는 중에 숫자 칸을 다시 그림');
    await pg.mouse.up();
    await pg.waitForFunction(() => !document.querySelector('.ov-kpis > [data-kpi][data-old]'), null, { timeout: 8000 });
    ok(same(await kpiOrder(pg), ['collected', 'decided', 'violations', 'isolated', 'installs', 'isolation']), `미뤄 그린 뒤 ${await kpiOrder(pg)}`);
    // 짧은 클릭은 지금처럼 이동
    await pg.click('.ov-kpis > [data-kpi="installs"]'); await pg.waitForTimeout(400);
    ok(await hash(pg) === '#/installs', `KPI 클릭 이동 안 됨 ${await hash(pg)}`);
    await pg.done();
  });

  await T('11 설정 「화면 배치 기본 순서로」 → 즉시 · 토스트 · 사이드바 · 대시보드 기본 순서', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.focus('.nav-link[data-to="/evaluation"]'); await pg.keyboard.press('Alt+ArrowUp'); await pg.keyboard.press('Alt+ArrowUp');
    await pg.focus('.ov-kpis > [data-kpi="collected"]'); await pg.keyboard.press('Alt+ArrowRight');
    ok(!same(await navOrder(pg), NAV_DEFAULT) && !same(await kpiOrder(pg), KPI_DEFAULT), '바꾸기 실패');
    await pg.click('.nav-link[data-to="/settings"]'); await pg.waitForTimeout(400);
    const btn = pg.locator('[data-action="layout-reset"]');
    ok(await btn.count() === 1, '「화면 배치 기본 순서로」 버튼 없음');
    ok((await btn.textContent()).includes('화면 배치 기본 순서로'), `버튼 글자 ${await btn.textContent()}`);
    await btn.click(); await pg.waitForTimeout(300);
    ok(!(await pg.$('dialog[open]')), '확인 대화상자가 뜸');
    ok(/기본 순서/.test(await pg.$eval('#toasts', (e) => e.textContent)), `토스트 ${await pg.$eval('#toasts', (e) => e.textContent)}`);
    ok(same(await navOrder(pg), NAV_DEFAULT), `사이드바 즉시 기본 아님 ${await navOrder(pg)}`);
    ok(await stored(pg) === null, `저장값 남음 ${await stored(pg)}`);
    await pg.click('.nav-link[data-to="/"]'); await pg.waitForSelector('.ov-kpis > [data-kpi]', { timeout: 6000 }); await pg.waitForTimeout(300);
    ok(same(await kpiOrder(pg), KPI_DEFAULT), `대시보드 기본 아님 ${await kpiOrder(pg)}`);
    // 조회자도 쓸 수 있다(이 브라우저 설정)
    const pv = await newPage();
    await pv.goto(`${BASE}?source=sim&as=viewer#/settings`); await pv.waitForSelector('.page-title'); await pv.waitForTimeout(300);
    ok(await pv.locator('[data-action="layout-reset"]').count() === 1, '조회자에게 버튼 없음');
    await pv.done();
    await pg.done();
  });

  await T('12 다크: 자리 표시 · 집힌 칸 색이 토큰(다크 accent · surface)', async () => {
    const pg = await newPage({ colorScheme: 'dark' });
    await go(pg, '/', '&theme=dark');
    await pg.waitForSelector('.ov-kpis > [data-kpi]', { timeout: 6000 });
    const c = await center(pg, '.ov-kpis > [data-kpi="collected"]');
    await drag(pg, '.ov-kpis > [data-kpi="installs"]', '.ov-kpis > [data-kpi="collected"]', { dx: -c.w / 4, release: false });
    const col = await pg.evaluate(() => { const m = document.querySelector('.sg-sort-marker'), p = document.querySelector('.sg-sort-picked'); return { theme: document.documentElement.dataset.theme, marker: getComputedStyle(m).borderTopColor, markerStyle: getComputedStyle(m).borderTopStyle, markerBg: getComputedStyle(m).backgroundColor, picked: getComputedStyle(p).backgroundColor }; });
    ok(col.theme === 'dark', '다크 아님');
    ok(col.marker === 'rgb(109, 124, 255)' && col.markerStyle === 'dashed', `자리 표시 선 ${JSON.stringify(col)}`);
    ok(col.markerBg === 'rgb(30, 35, 66)', `자리 표시 바탕 ${col.markerBg}`);
    ok(col.picked === 'rgb(23, 26, 33)', `집힌 칸 바탕 ${col.picked}`);
    await shot(pg, 'dark');
    await pg.keyboard.press('Escape'); await pg.mouse.up(); await pg.waitForTimeout(300);
    ok(same(await kpiOrder(pg), KPI_DEFAULT), 'Esc 뒤 KPI 원래 자리 아님');
    await pg.done();
  });

  await T('13 390 터치: 서랍 사이드바 길게 눌러 끌기 · KPI 2열 끌기 · 짧은 탭은 이동', async () => {
    const pg = await newPage({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
    await go(pg, '/');
    await pg.tap('[data-action="menu"]'); await pg.waitForTimeout(400);
    ok(await pg.$eval('.shell', (e) => e.classList.contains('drawer-open')), '서랍 안 열림');
    const cdp = await touchDrag(pg, '.nav-link[data-to="/evaluation"]', '.nav-link[data-to="/installs"]', { dy: -6, release: false });
    ok(await picked(pg) === 1, '터치 길게 눌러 집히지 않음');
    ok(same(await navOrder(pg), ['/', '/evaluation', '/installs', '/scans', ...NAV_DEFAULT.slice(4)]), `터치 끄는 중 ${await navOrder(pg)}`);
    await shot(pg, 'mobile');
    await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] }); await pg.waitForTimeout(400);
    ok(await picked(pg) === 0, '터치 놓은 뒤 집힘이 남음');
    ok(await pg.$eval('.shell', (e) => e.classList.contains('drawer-open')), '놓았더니 서랍이 닫힘');
    ok(await hash(pg) === '#/', `터치 놓았는데 이동 ${await hash(pg)}`);
    ok(same(JSON.parse(await stored(pg)).sidebar.install, ['evaluation', 'installs', 'scans']), '터치 저장');
    // 짧은 탭은 이동 + 서랍 닫힘
    await pg.tap('.nav-link[data-to="/events"]'); await pg.waitForTimeout(450);
    ok(await hash(pg) === '#/events', `짧은 탭 이동 안 됨 ${await hash(pg)}`);
    ok(!(await pg.$eval('.shell', (e) => e.classList.contains('drawer-open'))), '탭 뒤 서랍이 안 닫힘');
    // KPI 2열 — 끄는 동안 화면이 스크롤되지 않는다
    await go(pg, '/');
    await pg.waitForSelector('.ov-kpis > [data-kpi]', { timeout: 6000 });
    await pg.locator('.ov-kpis').scrollIntoViewIfNeeded(); await pg.waitForTimeout(200);
    await pg.evaluate(() => document.querySelector('.ov-kpis').scrollIntoView({ block: 'center' })); await pg.waitForTimeout(200);
    const cols = await pg.$eval('.ov-kpis', (e) => getComputedStyle(e).gridTemplateColumns.split(' ').length);
    ok(cols === 2, `KPI ${cols}열`);
    const y0 = await pg.evaluate(() => scrollY);
    const c = await center(pg, '.ov-kpis > [data-kpi="collected"]');
    await touchDrag(pg, '.ov-kpis > [data-kpi="isolation"]', '.ov-kpis > [data-kpi="collected"]', { dx: -c.w / 4 });
    ok((await kpiOrder(pg))[0] === 'isolation', `터치 KPI ${await kpiOrder(pg)}`);
    ok(Math.abs((await pg.evaluate(() => scrollY)) - y0) < 2, `끄는 동안 스크롤됨 ${y0} → ${await pg.evaluate(() => scrollY)}`);
    ok(await hash(pg) === '#/', `KPI 터치 놓았는데 이동 ${await hash(pg)}`);
    const o = await pg.evaluate(() => document.documentElement.scrollWidth - innerWidth);
    ok(o <= 0, `가로 넘침 ${o}`);
    await pg.done();
  });

  await T('14 prefers-reduced-motion: 다른 항목 이동 애니메이션 없음', async () => {
    const pg = await newPage({ reducedMotion: 'reduce' });
    await go(pg, '/');
    await drag(pg, '.nav-link[data-to="/settings"]', '.nav-link[data-to="/policies"]', { dy: -6, release: false });
    const moving = await pg.$$eval('.side-nav .nav-link:not(.sg-sort-picked)', (els) => els.filter((e) => e.style.transform && e.style.transform !== 'none').length);
    ok(moving === 0, `이동 애니메이션 ${moving}개`);
    await pg.mouse.up(); await pg.waitForTimeout(200);
    ok((await navOrder(pg)).indexOf('/settings') === 6, `reduce 에서도 순서 변경 ${await navOrder(pg)}`);
    await pg.done();
  });

  if (process.env.EVAL_SORT !== '0') { // 11/04d: eval.js 연결이 main 에 합쳐져 기본으로 켠다(끄기 EVAL_SORT=0)
    await T('15 [EVAL_SORT] 평가 지표 6칸 끌기 · Alt+→ · 새로고침 유지 · 기본 순서로', async () => {
      const pg = await newPage();
      await go(pg, '/evaluation');
      await pg.waitForSelector('[data-part="evaluation"][data-state="ready"]', { timeout: 6000 });
      ok(same(await evalOrder(pg), EVAL_DEFAULT), `처음 ${await evalOrder(pg)}`);
      const c = await center(pg, '.eval-kpis > [data-kpi="static-detection"]');
      await drag(pg, '.eval-kpis > [data-kpi="model-f1"]', '.eval-kpis > [data-kpi="static-detection"]', { dx: -c.w / 4 });
      ok(same(await evalOrder(pg), ['model-f1', ...EVAL_DEFAULT.slice(0, 5)]), `끌기 ${await evalOrder(pg)}`);
      ok(/모델 시험 F1을 1번째로 옮김/.test(await live(pg)), `알림 「${await live(pg)}」`);
      await pg.focus('.eval-kpis > [data-kpi="model-f1"]'); await pg.keyboard.press('Alt+ArrowRight'); await pg.waitForTimeout(150);
      ok(same((await evalOrder(pg)).slice(0, 2), ['static-detection', 'model-f1']), `Alt+→ ${await evalOrder(pg)}`);
      ok(await pg.evaluate(() => document.activeElement && document.activeElement.dataset.kpi) === 'model-f1', '포커스');
      const want = await evalOrder(pg);
      await pg.reload(); await pg.waitForSelector('[data-part="evaluation"][data-state="ready"]', { timeout: 6000 });
      ok(same(await evalOrder(pg), want), `새로고침 뒤 ${await evalOrder(pg)}`);
      ok(same(JSON.parse(await stored(pg)).evaluationKpi, want), '저장');
      await pg.click('.nav-link[data-to="/settings"]'); await pg.waitForTimeout(300);
      await pg.click('[data-action="layout-reset"]'); await pg.waitForTimeout(200);
      await pg.click('.nav-link[data-to="/evaluation"]'); await pg.waitForSelector('[data-part="evaluation"][data-state="ready"]', { timeout: 6000 });
      ok(same(await evalOrder(pg), EVAL_DEFAULT), `기본 순서로 뒤 ${await evalOrder(pg)}`);
      await pg.done();
    });
  } else console.log('SKIP  15 [EVAL_SORT=0] 평가 지표 6칸');

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
