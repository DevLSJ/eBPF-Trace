/* 10/16 eBPF 수집 종합(대시보드) 회귀 — 판정 대기 아래에 저장된 기록 기반 종합
   1 판정 대기가 맨 위, 그 아래 「eBPF 수집 종합」 영역 + 기간 칩(1시간 · 24시간 · 7일, 기본 24시간)
   2 숫자 칸: 수집 이벤트(종류별 합 = 전체) · 위반(격리 + 경고 = 전체) · 격리한 컨테이너 · 설치 검사 · 판정 — API(GET /api/summary) 값 그대로
   3 수집량 추이(종류별 쌓은 막대) · 위반 추이(격리 · 경고) — 기간별 칸 수(1시간 60 · 24시간 24 · 7일 28)
   4 상위 규칙 · 상위 컨테이너 5개, 많은 순
   5 설치 검사 결과 · 판정 결과 · 차단 목록 수
   6 기간을 바꾸면 칸 수가 바뀐다 — 기간은 화면 상태만, 주소에 range 를 남기지 않는다(10/21b)
   7 공격이 들어오면 위반 숫자가 바로 늘어난다
   8 1440 · 1280 넘침 0 · 콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8766 → PLAYWRIGHT=<playwright 경로> node tests/overview-1016.cjs   (VERBOSE=1 · ONLY · SHOTS=1) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots', '1016-overview');
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const num = (s) => Number(String(s).replace(/[^\d]/g, ''));

(async () => {
  const br = await chromium.launch();
  const newPage = async (viewport = { width: 1440, height: 900 }) => {
    const pg = await br.newPage({ viewport });
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash) => { await pg.goto(`${BASE}?as=admin#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(500); }; // 10/20: 로그인 건너뜀(?as=admin)
  const shot = async (pg, n) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `${n}.png`) }); };
  const OV = '[data-section="overview"]';
  const summary = (pg, range) => pg.evaluate(async (r) => UI.api.summary(r), range);
  const kpi = (pg, k) => pg.textContent(`${OV} [data-kpi="${k}"] [data-value]`).then(num);

  await T('1 판정 대기가 맨 위, 그 아래 eBPF 수집 종합 + 기간 칩(기본 24시간)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const [p, o] = await Promise.all(['[data-section="pending"]', OV].map((q) => pg.$eval(q, (e) => e.getBoundingClientRect().top)));
    ok(p < o, `판정 대기 ${p} · 종합 ${o}`);
    ok((await pg.textContent(`${OV} h2`)).includes('eBPF 수집 종합'), '제목');
    const chips = await pg.$$eval(`${OV} [data-range]`, (els) => els.map((e) => [e.dataset.range, e.getAttribute('aria-pressed')]));
    ok(JSON.stringify(chips) === JSON.stringify([['1h', 'false'], ['24h', 'true'], ['7d', 'false']]), `기간 칩 ${JSON.stringify(chips)}`);
    await shot(pg, '01-dashboard-overview');
    await pg.close();
  });

  await T('2 숫자 칸 = API 값: 수집(종류별 합 = 전체) · 위반(격리 + 경고) · 격리한 컨테이너 · 설치 검사 · 판정', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await summary(pg, '24h');
    ok(s.collected.total > 0 && s.collected.byKind.exec + s.collected.byKind.open + s.collected.byKind.connect === s.collected.total, `수집 ${JSON.stringify(s.collected.byKind)} / ${s.collected.total}`);
    ok(s.violations.killed + s.violations.alert + s.violations.held === s.violations.total, `위반 ${JSON.stringify(s.violations)}`);
    ok(await kpi(pg, 'collected') === s.collected.total, `수집 칸 ${await kpi(pg, 'collected')} / ${s.collected.total}`);
    ok(await kpi(pg, 'violations') === s.violations.total, '위반 칸');
    ok(await kpi(pg, 'isolated') === s.isolatedContainers, '격리 칸');
    ok(await kpi(pg, 'installs') === s.installs.total, '설치 검사 칸');
    ok(await kpi(pg, 'decided') === s.decisions.malicious + s.decisions.falsePositive, '판정 칸');
    const kinds = await pg.textContent(`${OV} [data-kpi="collected"]`);
    ok(kinds.includes('실행') && kinds.includes('파일') && kinds.includes('통신'), `종류별 표시 "${kinds}"`);
    await pg.close();
  });

  await T('3 수집량 추이(종류별 쌓은 막대) · 위반 추이(격리 · 경고), 24시간 = 24칸', async () => {
    const pg = await newPage();
    await go(pg, '/');
    ok(await pg.locator(`${OV} [data-chart="collected"] [data-bucket]`).count() === 24, `수집 칸 ${await pg.locator(`${OV} [data-chart="collected"] [data-bucket]`).count()}`);
    ok(await pg.locator(`${OV} [data-chart="violations"] [data-bucket]`).count() === 24, '위반 칸');
    const kinds = await pg.$$eval(`${OV} [data-chart="collected"] rect[data-kind]`, (els) => [...new Set(els.map((e) => e.dataset.kind))].sort());
    ok(JSON.stringify(kinds) === JSON.stringify(['connect', 'exec', 'open']), `종류 ${JSON.stringify(kinds)}`);
    const legend = await pg.textContent(`${OV} [data-chart="violations"]`);
    ok(legend.includes('격리') && legend.includes('경고'), '위반 범례');
    await pg.close();
  });

  await T('4 상위 규칙 · 상위 컨테이너: 5개 이하, 많은 순, API 와 같다', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await summary(pg, '24h');
    for (const [k, list, key] of [['rules', s.topRules, 'ruleId'], ['containers', s.topContainers, 'container']]) {
      const rows = await pg.$$eval(`${OV} [data-top="${k}"] [data-row]`, (els) => els.map((e) => [e.dataset.row, Number(e.dataset.count)]));
      ok(rows.length > 0 && rows.length <= 5, `${k} ${rows.length}행`);
      ok(rows.every((r, i) => i === 0 || rows[i - 1][1] >= r[1]), `${k} 정렬 ${JSON.stringify(rows)}`);
      ok(JSON.stringify(rows) === JSON.stringify(list.slice(0, 5).map((x) => [x[key], x.count])), `${k} API 다름 ${JSON.stringify(rows)}`);
    }
    await pg.close();
  });

  await T('5 설치 검사 결과 · 판정 결과 · 차단 목록 수', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await summary(pg, '24h');
    const t = await pg.textContent(`${OV} [data-results]`);
    for (const w of ['통과', '격리', '설치 전 거부', '악성', '오탐', '차단 목록']) ok(t.includes(w), `결과에 「${w}」 없음`);
    const bl = num(await pg.textContent(`${OV} [data-results] [data-blocklist-total]`));
    ok(bl === s.blocklist.packages + s.blocklist.images + s.blocklist.hosts, `차단 목록 ${bl}`);
    await pg.close();
  });

  await T('6 기간 1시간 → 60칸(주소에 range 없음), 7일 → 28칸', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.click(`${OV} [data-range="1h"]`);
    await pg.waitForTimeout(300);
    ok(!pg.url().includes('range='), `주소에 기간이 남음 ${pg.url()}`); // 10/21b
    ok(await pg.locator(`${OV} [data-chart="collected"] [data-bucket]`).count() === 60, '1시간 칸 수');
    await pg.click(`${OV} [data-range="7d"]`);
    await pg.waitForTimeout(300);
    ok(await pg.locator(`${OV} [data-chart="collected"] [data-bucket]`).count() === 28, '7일 칸 수');
    await shot(pg, '02-overview-7d');
    await pg.close();
  });

  await T('7 공격이 들어오면 위반 숫자가 바로 늘어난다', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const before = await kpi(pg, 'violations');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(800);
    const after = await kpi(pg, 'violations');
    ok(after > before, `위반 ${before} → ${after}`);
    await pg.close();
  });

  await T('8 1440 · 1280 넘침 0', async () => {
    for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) {
      const pg = await newPage(vp);
      await go(pg, '/');
      await pg.evaluate(() => UI.runAttackNow());
      await pg.waitForTimeout(500);
      const o = await pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'); return [d.scrollHeight - innerHeight, d.scrollWidth - innerWidth, m.scrollHeight - m.clientHeight, m.scrollWidth - m.clientWidth]; });
      ok(o.every((x) => x <= 0), `${vp.width} 넘침 ${JSON.stringify(o)}`);
      if (vp.width === 1280) await shot(pg, '03-overview-1280');
      await pg.close();
    }
  });

  await br.close();
  const pass = results.filter((r) => r[0]).length;
  if (!process.env.VERBOSE) for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  for (const e of consoleErrors) console.log(`CONSOLE  ${e}`);
  console.log(`\n${pass}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  process.exit(pass === results.length && !consoleErrors.length ? 0 : 1);
})();
