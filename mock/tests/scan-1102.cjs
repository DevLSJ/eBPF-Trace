/* 11/02 공급망 검사 보완 회귀(목업 먼저 — 확정 뒤 React)
   1 테스트 코드 탐지는 「테스트 코드 N — 위험 점수 · 판정에 넣지 않음」 묶음으로 따로, 위협 수 · 판정에 들지 않는다(저장소 psf/requests: tests/test_requests.py /etc/passwd)
   2 패키지 이름 검사도 자기 버전의 알려진 취약점(pip django 2.2.0 → 75건 · 9.8) — 판정 문구 「이 버전에 …」 · 표 제목 「이 패키지 버전」
   3 AI 도우미가 꺼져 있으면(?ai=off) 탭은 보이고 안내 문구(OLLAMA_URL), 켜져 있으면 그대로 대화
   4 1440 · 콘솔 오류 0
   실행: BASE=http://127.0.0.1:8767 PLAYWRIGHT=<playwright 경로> node tests/scan-1102.cjs */
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };

(async () => {
  const br = await chromium.launch();
  const newPage = async (viewport = { width: 1440, height: 900 }) => {
    const pg = await br.newPage({ viewport });
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash, extra = '') => { await pg.goto(`${BASE}?source=sim&as=admin${extra}#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(400); };
  const F = '[data-part="scan-form"]';
  const S = '.sheet[data-sheet="scan"]';
  const waitScan = async (pg) => { const id = await pg.$eval('tr[data-scan]', (e) => e.dataset.scan); await pg.waitForSelector(`tr[data-scan="${id}"][data-status="done"]`, { timeout: 8000 }); await pg.click(`tr[data-scan="${id}"]`); await pg.waitForSelector(S); return id; };

  await T('1 테스트 코드는 따로 묶고 위협 수 · 판정에서 뺀다(저장소 psf/requests)', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    await pg.click(`${F} [data-input="repo"]`);
    await pg.fill(`${F} input[data-field="url"]`, 'https://github.com/psf/requests');
    await pg.click(`${F} button[aria-label="검사 시작"]`);
    const id = await waitScan(pg);
    const sum = await pg.$eval(`${S} [data-part="tests"] summary`, (e) => e.textContent.trim());
    ok(sum === '테스트 코드 1 — 위험 점수 · 판정에 넣지 않음', `묶음 제목 "${sum}"`);
    const t = await pg.$$eval(`${S} [data-part="tests"] [data-finding]`, (els) => els.map((e) => [e.dataset.loc, e.dataset.test, e.textContent]));
    ok(t.length === 1 && t[0][0] === 'tests/test_requests.py:1827' && t[0][1] === 'true' && t[0][2].includes('테스트 코드'), `테스트 탐지 ${JSON.stringify(t)}`);
    ok((await pg.textContent(`${S} [data-part="findings"] h3`)).startsWith('위협 0'), '위협 수에 테스트가 들어감');
    const v = await pg.evaluate(async (sid) => { const d = await UI.api.scan(sid); return [d.verdict, d.threats, d.testFindings]; }, id);
    ok(v[0] !== 'malicious' && v[1] === 0 && v[2] === 1, `판정 · 수 ${JSON.stringify(v)}`);
    await pg.close();
  });

  await T('2 패키지 이름 검사도 자기 버전의 알려진 취약점(pip django 2.2.0)', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    await pg.click(`${F} [data-input="package"]`);
    await pg.selectOption(`${F} select[data-field="manager"]`, 'pip');
    await pg.fill(`${F} input[data-field="name"]`, 'django');
    await pg.fill(`${F} input[data-field="version"]`, '2.2.0');
    await pg.click(`${F} button[aria-label="검사 시작"]`);
    await waitScan(pg);
    const row = await pg.$eval(`${S} [data-part="vulns"] tr[data-vpkg="django"]`, (e) => [e.dataset.count, e.dataset.max, e.dataset.direct]);
    ok(JSON.stringify(row) === JSON.stringify(['75', '9.8', 'true']), `django 행 ${JSON.stringify(row)}`);
    ok((await pg.textContent(`${S} [data-part="verdict"] p`)).includes('이 버전에 알려진 취약점이 75건'), '판정 문구');
    ok((await pg.textContent(`${S} [data-part="vulns"] h3`)).includes('이 패키지 버전 · 의존성 포함'), '표 제목');
    // 자기 버전 0 · 의존성만 취약하면 「의존성에 …」(11/02 sg-vm 실측: 최신 requests → certifi · idna 간접 4건)
    const txt = await pg.evaluate(() => UI.scanVerdictText({ status: 'done', verdict: 'vulnerable', target: { kind: 'package' }, vulns: [{ direct: false, count: 2 }, { direct: false, count: 2 }] }, 0));
    ok(txt.startsWith('의존성에 알려진 취약점이 4건'), `의존성만 "${txt}"`);
    await pg.close();
  });

  await T('3 AI 도우미 꺼짐(?ai=off): 탭은 보이고 OLLAMA_URL 안내 · 켜짐은 대화창', async () => {
    const pg = await newPage();
    await go(pg, '/', '&ai=off');
    await pg.click('[data-part="assist-fab"], .assist-fab'); await pg.waitForTimeout(300);
    const tabs = await pg.$$eval('.assist-panel [role="tab"]', (els) => els.map((e) => e.textContent.trim()));
    ok(tabs.some((x) => x.includes('AI 도우미')), `탭 ${JSON.stringify(tabs)}`);
    await pg.click('.assist-panel [role="tab"]:has-text("AI 도우미")'); await pg.waitForTimeout(200);
    const off = await pg.$eval('.assist-panel [data-part="chat-off"]', (e) => e.textContent);
    ok(off.includes('AI 도우미가 꺼져 있습니다') && off.includes('OLLAMA_URL'), `안내 "${off}"`);
    ok(await pg.locator('.assist-panel textarea, .assist-panel input[type="text"]').count() === 0, '꺼졌는데 입력칸');
    const p2 = await newPage(); await go(p2, '/'); await p2.click('[data-part="assist-fab"], .assist-fab'); await p2.waitForTimeout(300);
    await p2.click('.assist-panel [role="tab"]:has-text("AI 도우미")'); await p2.waitForTimeout(200);
    ok(await p2.locator('.assist-panel [data-part="chat-off"]').count() === 0, '켜졌는데 꺼짐 안내');
    await p2.close(); await pg.close();
  });

  await br.close();
  const pass = results.filter((r) => r[0]).length;
  if (!process.env.VERBOSE) for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  for (const e of consoleErrors) console.log(`CONSOLE  ${e}`);
  console.log(`\n${pass}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  process.exit(pass === results.length && !consoleErrors.length ? 0 : 1);
})();
