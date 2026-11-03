/* 11/04 종합 판정 회귀(목업 먼저 — 확정 뒤 React · 백엔드). 설계: 2026-11-03 사용자 승인(모두 추천안)
   sg-install 세션이 시작되면 모의 서버가 같은 패키지(첫 패키지)의 정적 검사(GuardDog + OSV)를 자동으로 시작하고, 설치 화면 한 건에 런타임 + 정적 결과를 나란히 보인다
   1 정상 pip requests → 목록 「정적 검사」 열 「검사 중…」 → 「위협 없음」(받은 버전 2.32.3 · 공급망 검사 기록에 trigger install)
   2 목록 열 순서(설치 결과 다음 정적 검사) · 빨간 행 = 런타임 격리 · 경고 또는 정적 악성 · 옛 세션은 「—」 · 정적만 악성이면 건을 열지 않음
   3 상세 「정적 분석 비교」 왼쪽 칸 = 정적 검사 · GuardDog + OSV(배지 · 위험 점수 N / 10 · 대상 + 받은 버전 · 「공급망 검사에서 보기 →」) · 엇갈릴 때만 한 줄
   4 pip ./reqeusts(로컬) → 정적 건너뜀 → 지금의 OSV 칸 그대로(부제에 이유) · 대본 1:15(체인 1실행 → 2파일 → 3통신 + OSV 0건) 그대로
   5 cargo → 「—」(title 에 이유) · 대상 파싱(정확한 버전 · 범위 · [extras] · ; 표식 · 로컬 · 이름 오류) · busy · off · 거부 세션은 시작 안 함
   6 같은 패키지 재실행 → 24시간 안 done 재사용 · 실행 중 합류 · failed 는 재검사
   7 375px · 다크 — 정적 칸이 넘치지 않고 한 열
   8 콘솔 오류 0
   9 시트가 열리면 「걸린 시간」 열 숨김(11/04 결정 — 1440 에서도 표가 가로로 넘치지 않게)
   실행: (mock/ 에서) python3 -m http.server 8768 → BASE=http://127.0.0.1:8768/index.html PLAYWRIGHT=<playwright 경로> node tests/combined-1104.cjs  (VERBOSE=1 · ONLY=정규식 · SHOTS=1 → screenshots/1104-*.png) */
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const path = require('path');
const fs = require('fs');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const OSV_FIXED = { reqeusts: 0, requests: 16 }; // goals-1015 와 같은 고정 응답(2026-10-15 실측값)
const NOTE_RUNTIME = '정적 검사로는 악성 코드를 찾지 못했지만, 설치 중 행동을 커널에서 보고 잡았습니다.';
const NOTE_STATIC = '설치 중 정책 위반은 없었지만, 정적 검사에서 설치 단계의 위험한 코드가 나왔습니다 — 공급망 검사에서 코드를 확인하세요.';
// 정적 악성 · 런타임 통과: 이름으로 받는 reqeusts(GuardDog 8.6 · 설치 시점 규칙 2) — 설치 중에는 아무 정책에도 안 걸리는 행동만
const STATIC_ONLY = { pkg: 'reqeusts', manager: 'pip', exitCode: 0, events: [[{ kind: 'exec', comm: 'pip', args: 'pip install --no-cache-dir --progress-bar off reqeusts' }, 1], [{ kind: 'connect', comm: 'pip', dstIp: '151.101.0.223', dstPort: 443, dstHost: 'pypi.org' }, 2]] };
const CARGO = { pkg: 'ripgrep', manager: 'cargo', exitCode: 0, events: [[{ kind: 'exec', comm: 'cargo', args: 'cargo install ripgrep' }, 1], [{ kind: 'connect', comm: 'cargo', dstIp: '18.65.3.11', dstPort: 443, dstHost: 'crates.io' }, 2]] };

(async () => {
  const br = await chromium.launch();
  const newPage = async (viewport = { width: 1440, height: 900 }) => {
    const pg = await br.newPage({ viewport });
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    await pg.route('https://api.osv.dev/**', (route) => {
      let body = {}; try { body = JSON.parse(route.request().postData() || '{}'); } catch { /* 빈 본문 */ }
      const n = OSV_FIXED[(body.package || {}).name] || 0;
      const vulns = Array.from({ length: n }, (_, i) => ({ id: `GHSA-test-${i + 1}`, modified: '2026-01-01T00:00:00Z' }));
      return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: JSON.stringify(n ? { vulns } : {}) });
    });
    return pg;
  };
  const go = async (pg, hash, extra = '') => { await pg.goto(`${BASE}?source=sim&as=admin${extra}#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(300); };
  const nav = async (pg, hash, st) => { await pg.evaluate(([x, s]) => UI.go(x, s), [hash, st || null]); await pg.waitForTimeout(350); }; // 화면 안 링크처럼(필터는 상태로)
  const shot = async (pg, name) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `1104-${name}.png`) }); };
  // 데모 제어 설치 실행 → 끝 보고까지 기다린다(정적 검사도 끝날 때까지 — wantScan)
  const runInstall = async (pg, kind, wantScan = true) => {
    const id = await pg.evaluate((k) => UI.runInstallDemo(k), kind);
    await pg.waitForFunction((sid) => UI.state.installs.find((s) => s.id === sid && (s.finishedAt || s.refusedBy)), id, { timeout: 8000 });
    if (wantScan) await pg.waitForFunction(async (sid) => { const s = await UI.api.install(sid); return !s.scan || s.scan.status !== 'running'; }, id, { timeout: 8000, polling: 100 });
    return pg.evaluate(async (sid) => UI.api.install(sid), id);
  };
  const row = (id) => `table[data-table="installs"] tbody tr[data-id="${id}"]`;
  const SHEET = '.sheet[data-sheet="install"]';
  const openSheet = async (pg, id) => { await nav(pg, `#/installs?id=${id}`, { status: 'all' }); await pg.waitForSelector(`${SHEET} [data-part="osv"]`, { timeout: 5000 }); };

  // ---------------- 1. 정상 pip requests ----------------
  await T('1 정상 pip requests → 정적 검사 열 「검사 중…」 → 「위협 없음」(받은 버전 · 공급망 검사 기록)', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const id = await pg.evaluate(() => UI.runInstallDemo('benign'));
    await pg.waitForSelector(`${row(id)} [data-static="running"]`, { timeout: 2000 });
    ok((await pg.textContent(`${row(id)} [data-static]`)).includes('검사 중…'), '「검사 중…」 아님');
    await pg.waitForFunction((sid) => UI.state.installs.find((s) => s.id === sid && s.finishedAt), id, { timeout: 8000 });
    await nav(pg, '#/installs', { status: 'all' });
    await pg.waitForSelector(`${row(id)} [data-static="clean"]`, { timeout: 5000 });
    ok((await pg.textContent(`${row(id)} [data-static]`)).trim() === '위협 없음', '「위협 없음」 아님');
    ok((await pg.textContent(`${row(id)} [data-status]`)).includes('통과'), '런타임 통과 아님');
    await shot(pg, 'list');
    const s = await pg.evaluate(async (sid) => UI.api.install(sid), id);
    ok(s.scan && s.scan.status === 'done' && s.scan.verdict === 'clean' && s.scan.label === 'pip requests' && s.scan.version === '2.32.3' && /^scan-/.test(s.scan.id) && s.scan.riskScore === 0 && !s.scan.reused, `scan ${JSON.stringify(s.scan)}`);
    for (const k of ['installThreats', 'threats', 'vulnCount']) ok(s.scan[k] === 0, `${k} ${s.scan[k]}`);
    const scans = await pg.evaluate(async () => UI.api.scans());
    const sc = scans.find((x) => x.id === s.scan.id);
    ok(sc && sc.trigger === 'install' && sc.target.version === '2.32.3', `공급망 검사 기록 ${JSON.stringify(sc && [sc.trigger, sc.target])}`);
    await pg.close();
  });

  // ---------------- 2. 목록 ----------------
  await T('2 목록: 설치 결과 다음 정적 검사 열 · 빨간 행(런타임 격리 · 경고 또는 정적 악성) · 옛 세션 「—」', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const ths = await pg.$$eval('table[data-table="installs"] thead th', (els) => els.map((e) => e.textContent.trim()));
    ok(ths.indexOf('정적 검사') === ths.indexOf('설치 결과') + 1 && ths.indexOf('설치 결과') > 0, `열 ${JSON.stringify(ths)}`);
    const mal = await runInstall(pg, 'malicious');
    const stat = await runInstall(pg, STATIC_ONLY);
    const ben = await runInstall(pg, 'benign');
    ok(stat.status === 'passed' && stat.scan && stat.scan.verdict === 'malicious' && !stat.caseId, `정적만 악성 ${JSON.stringify([stat.status, stat.scan, stat.caseId])}`);
    await nav(pg, '#/installs', { status: 'all' });
    const red = (id) => pg.$eval(row(id), (e) => e.classList.contains('needs-action'));
    ok(await red(mal.id), '런타임 격리 행이 빨갛지 않음');
    ok(await red(stat.id), '정적 악성 행이 빨갛지 않음');
    ok(!(await red(ben.id)), '정상 행이 빨감');
    ok((await pg.textContent(`${row(stat.id)} [data-static]`)).trim() === '악성 의심', '정적 악성 배지');
    const seedPassed = await pg.$$eval('table[data-table="installs"] tbody tr[data-id]', (els) => els.filter((e) => e.querySelector('[data-status="passed"]') && e.querySelector('[data-static="none"]')).map((e) => [e.querySelector('[data-static]').textContent.trim(), e.classList.contains('needs-action')]));
    ok(seedPassed.length >= 1 && seedPassed.every(([t, r]) => t === '—' && !r), `옛 세션 ${JSON.stringify(seedPassed)}`);
    const seed = await pg.evaluate(async () => (await UI.api.installs({})).filter((s) => !s.scan).length);
    ok(seed >= 8, `scan 필드 없는 옛 세션 ${seed}`);
    const pending = await pg.evaluate(async () => (await UI.api.cases({ state: 'open' })).length);
    ok(pending === 1, `열린 건 ${pending} (정적만 악성은 건을 열지 않음)`);
    await pg.close();
  });

  // ---------------- 3. 상세 ----------------
  await T('3 상세: 정적 검사 · GuardDog + OSV 칸(배지 · 위험 점수 · 대상 + 받은 버전 · 링크) · 엇갈림 한 줄', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const ben = await runInstall(pg, 'benign');
    await openSheet(pg, ben.id);
    const cell = `${SHEET} [data-part="osv"] [data-cell="static"]`;
    await pg.waitForSelector(cell, { timeout: 3000 });
    const t = await pg.textContent(cell);
    ok(t.includes('정적 검사 · GuardDog + OSV') && t.includes('위협 없음') && t.includes('위험 점수 0.0 / 10') && t.includes('pip requests') && t.includes('2.32.3'), `정적 칸 "${t}"`);
    ok(await pg.locator(`${SHEET} [data-part="osv"] [data-osv-count]`).count() === 0, '정적 검사가 있는데 OSV 이름 조회 칸이 남음');
    ok((await pg.textContent(`${SHEET} [data-part="osv"]`)).includes('커널 관찰 (SupplyGuard)'), '커널 칸 없음');
    ok(await pg.$eval(`${SHEET} .cmp-note`, (e) => e.hidden), '정상 + 통과인데 한 줄이 보임');
    const href = await pg.$eval(`${cell} a[data-action="scan-link"]`, (e) => [e.getAttribute('href'), e.textContent.trim()]);
    ok(href[0] === `#/scans?id=${ben.scan.id}` && href[1] === '공급망 검사에서 보기 →', `링크 ${JSON.stringify(href)}`);
    await shot(pg, 'detail-clean');
    await pg.click(`${cell} a[data-action="scan-link"]`);
    await pg.waitForSelector(`.sheet[data-sheet="scan"]`, { timeout: 5000 });
    ok(await pg.locator(`tr[data-scan="${ben.scan.id}"].selected`).count() === 1, '공급망 검사 화면에서 그 검사가 열리지 않음');
    // 엇갈림: 런타임 통과 + 정적 악성 → 정적 쪽 한 줄
    const stat = await runInstall(pg, STATIC_ONLY);
    await openSheet(pg, stat.id);
    await pg.waitForSelector(`${SHEET} .cmp-note:not([hidden])`, { timeout: 3000 });
    ok((await pg.textContent(`${SHEET} .cmp-note`)).trim() === NOTE_STATIC, `한 줄 "${await pg.textContent(`${SHEET} .cmp-note`)}"`);
    ok((await pg.textContent(`${SHEET} [data-part="osv"] [data-cell="static"]`)).includes('위험 점수 8.6 / 10'), '악성 점수');
    await shot(pg, 'note');
    await pg.close();
  });

  // ---------------- 4. 로컬 → OSV 대체 · 대본 1:15 ----------------
  await T('4 pip ./reqeusts → 정적 건너뜀(local) → OSV 칸 그대로(부제에 이유) · 대본 1:15 그대로', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const mal = await runInstall(pg, 'malicious');
    ok(mal.scan && mal.scan.status === 'skipped' && mal.scan.skip === 'local' && mal.scan.id === '', `scan ${JSON.stringify(mal.scan)}`);
    ok(!(await pg.evaluate(async () => (await UI.api.scans()).length)), '로컬인데 공급망 검사가 시작됨');
    await nav(pg, '#/');
    await pg.click('[data-section="pending"] [data-case][data-source="install"]'); // 대본 1:15 — 판정 대기에서 상세로
    await pg.waitForSelector(`${SHEET} [data-part="osv"] [data-osv-count]`, { timeout: 5000 });
    const steps = await pg.$$eval(`${SHEET} [data-part="attack-chain"] .step-no`, (els) => [...new Set(els.map((e) => e.textContent))]);
    ok(steps.join() === '1 실행,2 파일,3 통신', `체인 ${steps}`);
    const t = await pg.textContent(`${SHEET} [data-part="osv"]`);
    ok(t.includes('0건') && t.includes('버전 무관') && t.includes('osv.dev') && t.includes('정적 분석 (OSV)'), `OSV 칸 "${t}"`);
    ok(t.includes('로컬'), `부제에 건너뛴 이유 없음 "${t}"`);
    ok(await pg.locator(`${SHEET} [data-cell="static"]`).count() === 0, '건너뛰었는데 정적 검사 칸');
    ok((await pg.textContent(`${SHEET} .cmp-note`)).trim() === NOTE_RUNTIME, `한 줄 "${await pg.textContent(`${SHEET} .cmp-note`)}"`);
    await nav(pg, '#/installs', { status: 'all' });
    ok((await pg.textContent(`${row(mal.id)} [data-static]`)).trim() === '—', '건너뜀 행이 「—」 아님');
    await nav(pg, `#/installs?id=${mal.id}`, { status: 'all' });
    await pg.waitForSelector(`${SHEET} [data-part="osv"] [data-osv-count]`, { timeout: 5000 });
    await shot(pg, 'detail-demo');
    await pg.close();
  });

  // ---------------- 5. cargo · 파싱 · busy · off · 거부 ----------------
  await T('5 cargo → 「—」(title 에 이유) · 대상 파싱 · busy · off · 거부 세션은 시작 안 함', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const cg = await runInstall(pg, CARGO);
    ok(cg.scan && cg.scan.status === 'skipped' && cg.scan.skip === 'unsupported', `cargo ${JSON.stringify(cg.scan)}`);
    await nav(pg, '#/installs', { status: 'all' });
    const cell = await pg.$eval(`${row(cg.id)} [data-static]`, (e) => [e.textContent.trim(), e.getAttribute('title') || '', e.dataset.static]);
    ok(cell[0] === '—' && cell[1].includes('cargo') && cell[2] === 'skipped', `cargo 칸 ${JSON.stringify(cell)}`);
    await openSheet(pg, cg.id);
    await pg.waitForSelector(`${SHEET} [data-part="osv"] [data-osv-count]`, { timeout: 5000 });
    ok((await pg.textContent(`${SHEET} [data-part="osv"]`)).includes('crates.io'), 'cargo 는 OSV 칸 그대로');
    const P = await pg.evaluate(() => [
      ['pip', 'requests==2.19.0'], ['pip', 'requests>=2'], ['pip', 'requests~=2.31'], ['pip', 'Requests[socks]==2.31.0; python_version>"3.8"'], ['pip', 'requests'],
      ['npm', 'lodash@4.17.21'], ['npm', 'lodash@4'], ['npm', 'lodash@latest'], ['npm', 'lodash@^4.17.0'], ['npm', '@babel/core@7.1.0'],
      ['pip', './reqeusts'], ['pip', '~/src/x'], ['pip', '/abs/pkg'], ['pip', 'git+https://github.com/psf/requests'], ['pip', 'https://example.com/x.tar.gz'], ['npm', 'file:../x'], ['pip', 'pkg-1.0-py3-none-any.whl'], ['pip', 'pkg-1.0.tar.gz'],
      ['cargo', 'ripgrep'], ['pip', 'bad name!'],
    ].map(([m, p]) => { const t = UI.srv.autoScanTarget(m, p); return t.skip ? t.skip : `${t.name}@${t.version}${t.exact ? '' : '(latest)'}`; }));
    const want = ['requests@2.19.0', 'requests@2.32.3(latest)', 'requests@2.32.3(latest)', 'requests@2.31.0', 'requests@2.32.3(latest)',
      'lodash@4.17.21', 'lodash@4.17.21(latest)', 'lodash@4.17.21(latest)', 'lodash@4.17.21(latest)', '@babel/core@7.1.0',
      'local', 'local', 'local', 'local', 'local', 'local', 'local', 'local', 'unsupported', 'invalid'];
    ok(JSON.stringify(P) === JSON.stringify(want), `파싱 ${JSON.stringify(P)}`);
    // busy: 실행 중 검사 = 동시 1 + 대기열 4 가 차 있으면 건너뜀
    await pg.evaluate(async () => { for (const n of ['a1', 'a2', 'a3', 'a4', 'a5']) await UI.api.startScan({ kind: 'package', manager: 'npm', name: n }); });
    const busy = await pg.evaluate(async () => { const id = UI.runInstallDemo({ pkg: 'flask', manager: 'pip', exitCode: 0, events: [] }); return (await UI.api.install(id)).scan; });
    ok(busy && busy.status === 'skipped' && busy.skip === 'busy', `busy ${JSON.stringify(busy)}`);
    // off: 검사기 없음 · Ping 실패
    const off = await pg.evaluate(async () => { UI.srv.scannerUp = false; const id = UI.runInstallDemo({ pkg: 'flask', manager: 'pip', exitCode: 0, events: [] }); const s = (await UI.api.install(id)).scan; UI.srv.scannerUp = true; return s; });
    ok(off && off.status === 'skipped' && off.skip === 'off', `off ${JSON.stringify(off)}`);
    // 거부 세션: 정적 검사를 시작하지 않음(scan 필드 없음)
    await pg.evaluate(() => { UI.state.blocklist.packages.push({ value: 'pip:evilpkg', caseId: null, addedAt: new Date().toISOString() }); });
    const ref = await runInstall(pg, { pkg: 'evilpkg', manager: 'pip', exitCode: 0, events: [] }, false);
    ok(ref.status === 'refused' && !ref.scan, `거부 ${JSON.stringify([ref.status, ref.scan])}`);
    await pg.close();
  });

  // ---------------- 6. 재사용 · 합류 · 재검사 ----------------
  await T('6 같은 패키지 재실행 → 24시간 안 done 재사용 · 실행 중 합류 · failed 는 재검사', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const a = await runInstall(pg, 'benign');
    const b = await runInstall(pg, 'benign');
    ok(a.scan.id && b.scan.id === a.scan.id && b.scan.reused === true && !a.scan.reused, `재사용 ${JSON.stringify([a.scan, b.scan])}`);
    ok(b.scan.status === 'done' && b.scan.verdict === 'clean', '재사용 결과');
    const n = await pg.evaluate(async () => (await UI.api.scans()).filter((x) => x.trigger === 'install' && x.target.name === 'requests').length);
    ok(n === 1, `검사 기록 ${n}건(재사용이면 1건)`);
    await openSheet(pg, b.id);
    ok((await pg.textContent(`${SHEET} [data-cell="static"]`)).includes('재사용'), '재사용 표시 없음');
    // 실행 중 합류: 같은 이름 · 버전을 동시에
    const ids = await pg.evaluate(() => [UI.runInstallDemo({ pkg: 'axios', manager: 'npm', exitCode: 0, events: [] }), UI.runInstallDemo({ pkg: 'axios@1.7.9', manager: 'npm', exitCode: 0, events: [] })]);
    const j = await pg.evaluate(async (xs) => Promise.all(xs.map(async (x) => (await UI.api.install(x)).scan)), ids);
    ok(j[0].status === 'running' && j[1].id === j[0].id && j[1].reused === true, `합류 ${JSON.stringify(j)}`);
    // failed → 재검사
    await pg.waitForFunction(async (sid) => (await UI.api.install(sid)).scan.status === 'done', ids[0], { timeout: 5000, polling: 100 });
    const f = await pg.evaluate(async (sid) => { const s = await UI.api.install(sid); const sc = UI.state.scans.find((x) => x.id === s.scan.id); sc.status = 'failed'; sc.verdict = null; sc.error = '검사 컨테이너 시간 초과(300초)'; UI.emit(); return sc.id; }, ids[0]);
    await nav(pg, '#/installs', { status: 'all' });
    const fc = await pg.$eval(`${row(ids[0])} [data-static]`, (e) => [e.textContent.trim(), e.getAttribute('title'), e.dataset.static]);
    ok(fc[0] === '실패' && fc[1].includes('시간 초과') && fc[2] === 'failed', `실패 칸 ${JSON.stringify(fc)}`);
    const c = await runInstall(pg, { pkg: 'axios', manager: 'npm', exitCode: 0, events: [] });
    ok(c.scan.id && c.scan.id !== f && !c.scan.reused, `재검사 ${JSON.stringify(c.scan)} (실패 ${f})`);
    await pg.close();
  });

  // ---------------- 7. 375px · 다크 ----------------
  await T('7 375px · 다크: 정적 칸이 넘치지 않고 한 열', async () => {
    for (const [vp, extra, name] of [[{ width: 375, height: 812 }, '', '375'], [{ width: 1440, height: 900 }, '&theme=dark', 'dark']]) {
      const pg = await newPage(vp);
      await go(pg, '/installs', extra);
      const ben = await runInstall(pg, 'benign');
      await openSheet(pg, ben.id);
      await pg.waitForSelector(`${SHEET} [data-cell="static"]`, { timeout: 3000 });
      const o = await pg.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      ok(o <= 0, `${name} 가로 넘침 ${o}`);
      const box = await pg.$$eval(`${SHEET} [data-part="osv"] .cmp-cell`, (els) => els.map((e) => { const r = e.getBoundingClientRect(); return [Math.round(r.left), Math.round(r.top), Math.round(r.right), Math.round(r.bottom)]; }));
      if (name === '375') ok(box.length === 2 && box[1][1] >= box[0][3] - 1 && box.every((b) => b[2] <= 375), `한 열 아님 ${JSON.stringify(box)}`);
      else {
        ok(await pg.$eval('html', (e) => e.dataset.theme) === 'dark', '다크 아님');
        const bg = await pg.$eval(`${SHEET} [data-cell="static"] .badge`, (e) => getComputedStyle(e).backgroundColor);
        ok(bg !== 'rgba(0, 0, 0, 0)', `배지 배경 ${bg}`);
      }
      await shot(pg, name);
      await pg.close();
    }
  });

  await T('9 시트가 열리면 「걸린 시간」 열을 숨겨 표가 가로로 넘치지 않는다(11/04 결정)', async () => {
    const pg = await newPage({ width: 1440, height: 900 });
    await go(pg, '/installs'); await nav(pg, '#/installs', { status: 'all' });
    const visibleHead = () => pg.$$eval('table[data-table="installs"] thead th', (els) => els.filter((e) => !e.hidden && e.offsetParent !== null).map((e) => e.textContent.trim()));
    ok((await visibleHead()).includes('걸린 시간'), '시트 닫힘인데 걸린 시간 열 없음');
    const ben = await runInstall(pg, 'benign');
    await openSheet(pg, ben.id);
    const head = await visibleHead();
    ok(!head.includes('걸린 시간'), `시트 열림인데 걸린 시간 열 보임 ${JSON.stringify(head)}`);
    const shownDur = await pg.$$eval('table[data-table="installs"] td[data-col="duration"]', (els) => els.filter((e) => !e.hidden && e.offsetParent !== null).length);
    ok(shownDur === 0, `걸린 시간 칸 ${shownDur}개 보임`);
    const over = await pg.$eval('table[data-table="installs"]', (t) => t.parentElement.scrollWidth - t.parentElement.clientWidth);
    ok(over <= 0, `표 가로 넘침 ${over}px`);
    await pg.close();
  });

  await br.close();
  // 8 콘솔 오류 0
  results.push([!consoleErrors.length, '8 콘솔 오류 0', consoleErrors.length ? `${consoleErrors.length}건` : '']);
  const pass = results.filter((r) => r[0]).length;
  if (!process.env.VERBOSE) for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  for (const e of consoleErrors) console.log(`CONSOLE  ${e}`);
  console.log(`\n${pass}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  process.exit(pass === results.length && !consoleErrors.length ? 0 : 1);
})();
