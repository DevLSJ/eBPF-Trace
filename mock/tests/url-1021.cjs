/* 2026-10-21b 목록 필터를 주소에서 뺀다 — 이유: 필터를 주소에 남기면 보안 취약성이 올라간다(사용자). React 에도 같은 결정
   주소에 남는 것: id · proposal · tab · view(감사 changes) · node(컨테이너 c: 만). 필터는 화면 상태만 — 다시 열거나 새로고침하면 기본값
   ① 목록 필터를 바꿔도 해시에 필터 키 없음(설치 · 이벤트 · 감사 · 공급망 · 토폴로지 · 대시보드 기간)
   ② 주소로 들어온 필터(옛 링크 · 알림)는 한 번 읽어 적용하고 주소에서 지운다 — 링크용 키는 남김
   ③ 토폴로지: 파일 · 도메인 노드 선택은 주소에 안 남고, 컨테이너 노드는 ?node=c:<이름>
   ④ 화면 안 링크(대시보드 카드 → 설치 「전체」 등)는 필터를 상태로 넘긴다(주소 아님)
   ⑤ 새로고침하면 기본값
   ⑥ 옛 view=history 주소 → view=changes
   실행: (mock/ 에서) python3 -m http.server 8768 --bind 127.0.0.1 → BASE=http://127.0.0.1:8768/index.html PLAYWRIGHT=<playwright 경로> node tests/url-1021.cjs   (VERBOSE=1 · ONLY) */
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8768/index.html';
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const W = { timeout: 4000 };
const FILTER_RE = /[?&](status|manager|kind|verdict|level|normal|container|action|rule|since|until|range|intent|value|tpl|default)=/;

(async () => {
  const br = await chromium.launch();
  const newPage = async () => {
    const pg = await br.newPage({ viewport: { width: 1440, height: 900 } });
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash) => { await pg.goto(`${BASE}?source=sim&as=admin#${hash}`); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(450); };
  const hash = (pg) => pg.evaluate(() => location.hash);
  const noFilter = async (pg, where) => { const x = await hash(pg); ok(!FILTER_RE.test(x), `${where}: 주소에 필터 ${x}`); return x; };
  const chips = (pg) => pg.$$eval('#page [data-part="filter-chips"] [data-chip]', (els) => els.map((e) => e.textContent.trim()));

  // ① 목록 필터를 바꿔도 해시에 필터 키가 없다
  await T('① 설치 검사: 결과 · 매니저 칩을 바꿔도 주소에 필터 없음(필터는 걸림)', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    await pg.click('[data-filter="status"] button[data-value="all"]'); await pg.waitForTimeout(200);
    await pg.click('[data-filter="manager"] button[data-value="npm"]'); await pg.waitForTimeout(200);
    const m = await pg.$$eval('table[data-table="installs"] tbody tr[data-id] [data-manager]', (els) => els.map((e) => e.dataset.manager));
    ok(m.length > 0 && m.every((x) => x === 'npm'), `매니저 ${JSON.stringify(m)}`);
    await noFilter(pg, '설치');
    await pg.close();
  });
  await T('① 이벤트: 종류 · 탐지 결과 · 정상 포함 · 컨테이너 검색을 바꿔도 주소에 필터 없음', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    await pg.selectOption('#page .filters label:has-text("종류") select', 'exec');
    await pg.selectOption('#page .filters label:has-text("탐지 결과") select', 'kill');
    await pg.click('#page [data-toggle="normal"] input');
    await pg.fill('#page input[aria-label="컨테이너 검색"]', 'web'); await pg.waitForTimeout(300);
    ok((await chips(pg)).length === 4, `칩 ${JSON.stringify(await chips(pg))}`);
    await noFilter(pg, '이벤트');
    await pg.close();
  });
  await T('① 감사 로그: 종류 · 대응 · 규칙 · 컨테이너 · 기간을 바꿔도 주소에 필터 없음', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    await pg.selectOption('#page select[aria-label="종류"]', 'open');
    await pg.selectOption('#page select[aria-label="대응"]', 'kill');
    await pg.fill('#page input[aria-label="규칙 id"]', 'sens');
    await pg.fill('#page input[aria-label="컨테이너"]', 'pkg');
    await pg.fill('#page input[aria-label="시작"]', '2026-10-01T00:00');
    await pg.fill('#page input[aria-label="끝"]', '2026-12-31T00:00'); await pg.waitForTimeout(500);
    ok((await chips(pg)).length === 5, `칩 ${JSON.stringify(await chips(pg))}`);
    await noFilter(pg, '감사');
    await pg.close();
  });
  await T('① 공급망 검사 · 토폴로지 · 대시보드 기간: 바꿔도 주소에 필터 없음', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    await pg.click('#page [data-verdict="malicious"]'); await pg.waitForTimeout(200);
    ok((await chips(pg)).length === 1, '공급망 결과 칩');
    await noFilter(pg, '공급망');
    await go(pg, '/topology');
    const opt = await pg.$$eval('#page select[aria-label="컨테이너"] option', (els) => els.map((e) => e.value).filter(Boolean));
    ok(opt.length > 0, '토폴로지 컨테이너 없음');
    await pg.selectOption('#page select[aria-label="컨테이너"]', opt[0]); await pg.waitForTimeout(1200);
    ok(await pg.$eval('#page select[aria-label="컨테이너"]', (e) => e.value) === opt[0], '토폴로지 필터');
    await noFilter(pg, '토폴로지');
    await go(pg, '/');
    await pg.click('[data-section="overview"] [data-range="7d"]'); await pg.waitForTimeout(300);
    ok(await pg.$eval('[data-section="overview"] [data-range="7d"]', (e) => e.getAttribute('aria-pressed')) === 'true', '기간 칩');
    await noFilter(pg, '대시보드');
    await pg.close();
  });

  // ② 주소로 들어온 필터 — 한 번 적용, 주소에서 지움(링크용 키는 남김)
  await T('② #/topology?container=X 진입 → 그 컨테이너로 필터 + 주소에서 container 사라짐(컨테이너 노드는 node=c:)', async () => {
    const pg = await newPage();
    await go(pg, '/topology');
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(600);
    await go(pg, '/topology?container=pkg-reqeusts'); await pg.waitForTimeout(1200);
    ok(await pg.$eval('#page select[aria-label="컨테이너"]', (e) => e.value) === 'pkg-reqeusts', '필터가 걸리지 않음');
    const x = await noFilter(pg, '토폴로지 진입');
    ok(x.startsWith('#/topology'), x);
    await pg.close();
  });
  await T('② #/audit?rule=R 진입 → 규칙 필터 적용 + 주소에서 rule 사라짐', async () => {
    const pg = await newPage();
    await go(pg, '/audit?rule=sensitive-files'); await pg.waitForTimeout(500);
    ok(await pg.$eval('#page input[aria-label="규칙 id"]', (e) => e.value) === 'sensitive-files', '규칙 입력 칸');
    const rules = await pg.$$eval('[data-table="audit"] tbody tr td:nth-child(6)', (els) => els.map((e) => e.textContent.trim()));
    ok(rules.length > 0 && rules.every((r) => r === 'sensitive-files'), `규칙 ${JSON.stringify(rules.slice(0, 5))}`);
    ok(await hash(pg) === '#/audit', `주소 ${await hash(pg)}`);
    await pg.close();
  });
  await T('② #/installs?status=all&id=X 진입 → 「전체」 + 시트, 주소는 #/installs?id=X 만', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const id = await pg.evaluate(() => UI.state.installs.find((s) => window.MOCK.statusOf(s) === 'passed').id);
    await go(pg, `/installs?status=all&id=${id}`);
    ok(await pg.$eval('[data-filter="status"] button[data-value="all"]', (e) => e.getAttribute('aria-pressed')) === 'true', '「전체」가 아님');
    ok(await pg.locator('.sheet[data-sheet="install"]').count() === 1, '시트 없음');
    ok(await hash(pg) === `#/installs?id=${id}`, `주소 ${await hash(pg)}`);
    await pg.close();
  });

  // ③ 토폴로지 노드 선택
  await T('③ 토폴로지: 파일 노드 선택은 주소에 안 남고, 컨테이너 노드는 ?node=c:<이름>', async () => {
    const pg = await newPage();
    await go(pg, '/topology');
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(1500);
    await pg.click('.topo-side button.chain-step:has(.step-open)'); await pg.waitForTimeout(300);
    // 11/05 슬라이드 패널: 노드 카드는 .topo-side 가 아니라 토폴로지 패널 안
    ok(await pg.locator('.sheet-layer [data-sheet="topo"] [data-part="node"]:has-text("선택한 노드")').count() === 1, '파일 노드가 선택되지 않음');
    ok(!/[?&]node=/.test(await hash(pg)), `파일 노드가 주소에 ${await hash(pg)}`);
    // 11/05 슬라이드 패널: 패널이 공격 체인을 가린다 — 닫고 컨테이너를 고른다
    await pg.click('.sheet-layer [data-action="sheet-close"]'); await pg.waitForSelector('.sheet-layer', { state: 'detached', timeout: 2000 });
    await pg.click('.topo-side .chain-head'); await pg.waitForTimeout(300);
    const x = decodeURIComponent(await hash(pg));
    ok(/[?&]node=c:/.test(x), `컨테이너 노드가 주소에 없음 ${x}`);
    await pg.click('.sheet-layer [data-sheet="topo"] [data-action="sheet-close"]'); await pg.waitForTimeout(400); // ✕ 로 선택 해제 — 11/05 슬라이드 패널: 노드 카드 ✕ 대신 패널 머리 ✕(닫힘 180ms)
    ok(!/[?&]node=/.test(await hash(pg)), `해제 뒤 주소에 node ${await hash(pg)}`);
    await pg.close();
  });

  // ④ 화면 안 링크는 필터를 상태로
  await T('④ 대시보드 「설치 검사」 카드 → 설치 「전체」 — 링크 주소에 필터 없음, 이동 뒤에도 주소는 #/installs', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const href = await pg.getAttribute('[data-kpi="installs"]', 'href');
    ok(href === '#/installs' && !FILTER_RE.test(href), `링크 ${href}`);
    await pg.click('[data-kpi="installs"]'); await pg.waitForTimeout(500);
    ok(await pg.$eval('[data-filter="status"] button[data-value="all"]', (e) => e.getAttribute('aria-pressed')) === 'true', '「전체」가 아님');
    ok(await hash(pg) === '#/installs', `주소 ${await hash(pg)}`);
    await pg.click('a[href="#/"]'); await pg.waitForTimeout(400);
    await pg.click('[data-kpi="isolated"]'); await pg.waitForTimeout(600); // 격리 카드 → 감사 「격리」
    ok(await pg.$eval('#page select[aria-label="대응"]', (e) => e.value) === 'kill', '감사 대응 필터');
    ok(await hash(pg) === '#/audit', `주소 ${await hash(pg)}`);
    await pg.close();
  });
  await T('④ 화면 안 해시 링크 전체에 필터 키가 없다(대시보드 · 설치 시트 · 이벤트 시트)', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(600);
    const bad = [];
    const scan = async (where) => { for (const h of await pg.$$eval('a[href^="#/"]', (els) => els.map((e) => e.getAttribute('href')))) if (FILTER_RE.test(h)) bad.push(`${where} ${h}`); };
    await pg.click('.feed-row'); await pg.waitForSelector('.sheet[data-sheet="event"]'); await scan('이벤트');
    await go(pg, '/'); await scan('대시보드');
    await go(pg, '/installs'); await pg.click('[data-filter="status"] button[data-value="all"]'); await pg.click('table[data-table="installs"] tbody tr[data-id]'); await pg.waitForTimeout(300); await scan('설치');
    ok(!bad.length, bad.slice(0, 4).join(' · '));
    await pg.close();
  });

  // ⑤ 새로고침하면 기본값
  await T('⑤ 새로고침하면 필터는 기본값(설치 「판정 대기」 · 이벤트 「위반 전체」)', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    await pg.click('[data-filter="status"] button[data-value="all"]'); await pg.waitForTimeout(200);
    await pg.reload(); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(500);
    ok(await pg.$eval('[data-filter="status"] button[data-value="pending"]', (e) => e.getAttribute('aria-pressed')) === 'true', '설치 기본값이 아님');
    await go(pg, '/events');
    await pg.selectOption('#page .filters label:has-text("탐지 결과") select', 'kill'); await pg.waitForTimeout(200);
    await pg.reload(); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(500);
    ok(await pg.$eval('#page .filters label:has-text("탐지 결과") select', (e) => e.value) === 'violation', '이벤트 기본값이 아님');
    await pg.close();
  });

  // ⑥ 옛 view=history
  await T('⑥ 옛 #/audit?view=history → 주소 view=changes + 판정 · 변경 이력', async () => {
    const pg = await newPage();
    await go(pg, '/audit?view=history');
    ok(await hash(pg) === '#/audit?view=changes', `주소 ${await hash(pg)}`);
    ok(await pg.$eval('[data-view-btn="history"]', (e) => e.getAttribute('aria-pressed')) === 'true', '변경 이력 보기가 아님');
    await pg.click('[data-view-btn="violations"]'); await pg.waitForTimeout(300);
    ok(await hash(pg) === '#/audit', `위반 기록 주소 ${await hash(pg)}`);
    await pg.click('[data-view-btn="history"]'); await pg.waitForTimeout(300);
    ok(await hash(pg) === '#/audit?view=changes', `변경 이력 주소 ${await hash(pg)}`);
    await pg.close();
  });

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
