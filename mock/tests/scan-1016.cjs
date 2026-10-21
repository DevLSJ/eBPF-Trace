/* 10/16 공급망 검사 회귀 — 패키지 이름 · 저장소 주소 · 파일을 실제 오픈소스(GuardDog · OSV-Scanner)로 정적 검사
   1 사이드바 「설치 검사」 묶음에 「공급망 검사」(#/scans)
   2 입력 3종(패키지 이름 · 저장소 주소 · 파일 올리기), 틀린 입력은 이유를 보이고 시작하지 않는다(주소 형식 · 50MB 초과)
   3 패키지 이름 검사(pip reqeusts): 목록 맨 위 「검사 중」 → 「악성 의심」 · 위험 점수 8.6
   4 상세: 위협(threat, 빨강)은 파일:줄, 기능(capability)은 정보로 따로. 코드 보기 = 줄 번호 + 위협 줄 빨간 배경, 위협을 누르면 그 줄로
   5 의존성 파일 업로드(requirements.txt): 알려진 취약점 — 패키지별 건수 · 최고 심각도 · 간접 의존성 표시
   6 정상 패키지(pip requests): 「위협 없음」, 기능만 정보로, 빨간 줄 없음
   7 저장소 주소 검사(GitHub) 완료
   8 결과에서: 「설치 검사로 실제 설치해 보기」 명령 복사, 「차단 목록에 올리기」 → 정책 제안(패키지 차단)
   9 1440 · 1280 넘침 0 · 콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8766 → PLAYWRIGHT=<playwright 경로> node tests/scan-1016.cjs   (VERBOSE=1 · ONLY · SHOTS=1) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots', '1016-scan');
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
  const go = async (pg, hash) => { await pg.goto(`${BASE}?source=sim&as=admin#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(400); }; // 10/20: 로그인 건너뜀(?as=admin)
  const shot = async (pg, n) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `${n}.png`) }); };
  const F = '[data-part="scan-form"]';
  // 패키지 이름으로 검사 시작 → 끝날 때까지 기다리고 그 검사의 id
  const scanPackage = async (pg, mgr, name, version = '') => {
    await pg.click(`${F} [data-input="package"]`);
    await pg.selectOption(`${F} select[data-field="manager"]`, mgr);
    await pg.fill(`${F} input[data-field="name"]`, name);
    await pg.fill(`${F} input[data-field="version"]`, version);
    await pg.click(`${F} button[aria-label="검사 시작"]`);
    const id = await pg.$eval('tr[data-scan]', (e) => e.dataset.scan);
    await pg.waitForSelector(`tr[data-scan="${id}"][data-status="done"]`, { timeout: 8000 });
    return id;
  };

  await T('1 사이드바: 설치 검사 묶음에 공급망 검사', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const order = await pg.$$eval('.nav-link', (els) => els.map((e) => e.dataset.to));
    ok(JSON.stringify(order.slice(0, 3)) === JSON.stringify(['/', '/installs', '/scans']), `순서 ${JSON.stringify(order)}`);
    await go(pg, '/scans');
    ok((await pg.textContent('.page-title')).includes('공급망 검사'), '화면 이름');
    await pg.close();
  });

  await T('2 입력 3종 · 틀린 입력은 이유를 보이고 시작하지 않음(주소 형식 · 50MB 초과)', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    const tabs = await pg.$$eval(`${F} [data-input]`, (els) => els.map((e) => e.dataset.input));
    ok(JSON.stringify(tabs) === JSON.stringify(['package', 'repo', 'file']), `입력 ${JSON.stringify(tabs)}`);
    const before = await pg.locator('tr[data-scan]').count();
    await pg.click(`${F} [data-input="repo"]`);
    await pg.fill(`${F} input[data-field="url"]`, 'not a url');
    await pg.click(`${F} button[aria-label="검사 시작"]`);
    ok((await pg.textContent(`${F} [data-form-error]`)).includes('https://github.com/'), '주소 형식 안내 없음');
    await pg.click(`${F} [data-input="file"]`);
    const big = path.join(require('os').tmpdir(), 'sg-big-51mb.tar.gz'); // Playwright 는 50MB 넘는 버퍼를 못 받아 파일로
    if (!fs.existsSync(big)) fs.writeFileSync(big, Buffer.alloc(51 * 1024 * 1024));
    await pg.setInputFiles(`${F} input[type="file"]`, big);
    ok((await pg.textContent(`${F} [data-form-error]`)).includes('50MB'), '크기 안내 없음');
    ok(await pg.locator('tr[data-scan]').count() === before, '틀린 입력으로 검사가 시작됨');
    await pg.close();
  });

  await T('3 패키지 이름 검사(pip reqeusts): 검사 중 → 악성 의심 · 위험 점수 8.6', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    await pg.click(`${F} [data-input="package"]`);
    await pg.fill(`${F} input[data-field="name"]`, 'reqeusts');
    await pg.click(`${F} button[aria-label="검사 시작"]`);
    const row = pg.locator('tr[data-scan]').first();
    ok((await row.getAttribute('data-status')) === 'running' && (await row.textContent()).includes('검사 중'), '검사 중 표시 없음');
    await pg.waitForSelector('tr[data-scan][data-status="done"]', { timeout: 8000 });
    const t = await row.textContent();
    ok(t.includes('pip reqeusts') && t.includes('악성 의심') && t.includes('8.6'), `행 "${t}"`);
    await shot(pg, '01-list');
    await pg.close();
  });

  await T('4 상세: 위협은 빨강(파일:줄), 기능은 정보로, 코드 보기 위협 줄 빨간 배경, 누르면 그 줄로', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    const id = await scanPackage(pg, 'pip', 'reqeusts');
    await pg.click(`tr[data-scan="${id}"]`);
    const sh = '.sheet[data-sheet="scan"]';
    await pg.waitForSelector(sh);
    ok((await pg.textContent(`${sh} [data-part="verdict"]`)).includes('악성 의심'), '판정 요약');
    const threats = await pg.$$eval(`${sh} [data-finding][data-category="threat"]`, (els) => els.map((e) => e.dataset.loc));
    ok(threats.includes('setup.py:35') && threats.includes('setup.py:41'), `위협 ${JSON.stringify(threats)}`);
    ok(await pg.locator(`${sh} [data-finding][data-category="capability"]`).count() >= 1, '기능(정보) 없음');
    const red = await pg.$$eval(`${sh} [data-part="code"] [data-line].hl-threat`, (els) => els.map((e) => Number(e.dataset.line)));
    ok(red.includes(35) && red.includes(41), `빨간 줄 ${JSON.stringify(red)}`);
    ok((await pg.textContent(`${sh} [data-part="code"] [data-line="35"]`)).includes('wget'), '35번 줄 코드');
    await pg.click(`${sh} [data-finding][data-loc="setup.py:41"]`);
    await pg.waitForTimeout(300);
    ok(await pg.locator(`${sh} [data-part="code"] [data-line="41"].focus`).count() === 1, '누른 위협 줄 강조 없음');
    await shot(pg, '02-detail-code');
    await pg.close();
  });

  await T('5 의존성 파일(requirements.txt): 알려진 취약점 — 패키지별 건수 · 최고 심각도 · 간접 의존성', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    await pg.click(`${F} [data-input="file"]`);
    await pg.setInputFiles(`${F} input[type="file"]`, { name: 'requirements.txt', mimeType: 'text/plain', buffer: Buffer.from('requests==2.19.0\ndjango==3.2.0\nflask==2.3.3\n') });
    await pg.click(`${F} button[aria-label="검사 시작"]`);
    await pg.waitForSelector('tr[data-scan][data-status="done"]', { timeout: 8000 });
    const id = await pg.$eval('tr[data-scan]', (e) => e.dataset.scan);
    ok((await pg.textContent(`tr[data-scan="${id}"]`)).includes('취약점'), '행 판정');
    await pg.click(`tr[data-scan="${id}"]`);
    const rows = await pg.$$eval('.sheet [data-part="vulns"] [data-vpkg]', (els) => els.map((e) => [e.dataset.vpkg, Number(e.dataset.count), e.dataset.max, e.dataset.direct]));
    const dj = rows.find((r) => r[0] === 'django');
    ok(dj && dj[1] === 66 && dj[2] === '9.8' && dj[3] === 'true', `django ${JSON.stringify(dj)}`);
    ok(rows.some((r) => r[0] === 'urllib3' && r[3] === 'false'), '간접 의존성 표시 없음');
    ok(rows.every((r, i) => i === 0 || Number(rows[i - 1][2]) >= Number(r[2])), `심각도 순 ${JSON.stringify(rows.map((r) => r[2]))}`);
    await shot(pg, '03-vulns');
    await pg.close();
  });

  await T('6 정상 패키지(pip requests): 위협 없음, 기능은 정보만, 빨간 줄 없음', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    const id = await scanPackage(pg, 'pip', 'requests');
    ok((await pg.textContent(`tr[data-scan="${id}"]`)).includes('위협 없음'), '행 판정');
    await pg.click(`tr[data-scan="${id}"]`);
    ok(await pg.locator('.sheet [data-finding][data-category="threat"]').count() === 0, '위협이 있음');
    ok(await pg.locator('.sheet [data-finding][data-category="capability"]').count() === 3, '기능 3건 아님');
    ok(await pg.locator('.sheet [data-part="code"] .hl-threat').count() === 0, '빨간 줄이 있음');
    await pg.close();
  });

  await T('7 저장소 주소(GitHub) 검사 완료', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    await pg.click(`${F} [data-input="repo"]`);
    await pg.fill(`${F} input[data-field="url"]`, 'https://github.com/psf/requests');
    await pg.click(`${F} button[aria-label="검사 시작"]`);
    await pg.waitForSelector('tr[data-scan][data-status="done"]', { timeout: 8000 });
    ok((await pg.textContent('tr[data-scan]')).includes('github.com/psf/requests'), '저장소 표시');
    await pg.close();
  });

  await T('8 결과에서: 설치 검사 명령 복사 · 차단 목록에 올리기 → 정책 제안(패키지 차단)', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    const id = await scanPackage(pg, 'pip', 'reqeusts');
    await pg.click(`tr[data-scan="${id}"]`);
    await pg.click('.sheet button[aria-label="설치 검사로 실제 설치해 보기"]');
    await pg.waitForTimeout(200);
    ok((await pg.textContent('.toasts')).includes('sg-install pip reqeusts'), '명령 복사 토스트');
    await pg.click('.sheet button[aria-label="차단 목록에 올리기"]');
    await pg.waitForURL(/#\/policies\?proposal=/, { timeout: 5000 });
    await pg.waitForSelector('[data-view="proposal"] [data-change]');
    const ch = await pg.$$eval('[data-view="proposal"] [data-change]', (els) => els.map((e) => e.dataset.change));
    ok(ch.includes('block:packages:pip:reqeusts'), `제안 ${JSON.stringify(ch)}`);
    ok((await pg.textContent('[data-view="proposal"] [data-part="basis"]')).includes('공급망 검사'), '근거에 공급망 검사 없음');
    await pg.close();
  });

  await T('9 1440 · 1280 넘침 0', async () => {
    for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) {
      const pg = await newPage(vp);
      await go(pg, '/scans');
      const id = await scanPackage(pg, 'pip', 'reqeusts');
      await pg.click(`tr[data-scan="${id}"]`);
      await pg.waitForSelector('.sheet[data-sheet="scan"]');
      const o = await pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'); return [d.scrollHeight - innerHeight, d.scrollWidth - innerWidth, m.scrollHeight - m.clientHeight, m.scrollWidth - m.clientWidth]; });
      ok(o.every((x) => x <= 0), `${vp.width} 넘침 ${JSON.stringify(o)}`);
      if (vp.width === 1280) await shot(pg, '04-detail-1280');
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
