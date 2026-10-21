/* 10/16 정책 설정 개편 회귀 — 처음 쓰는 사람도 정책을 세부적으로 고칠 수 있게
   1 정책을 열면 「쉬운 설정」이 기본: 단계 ①무엇을 ②어떤 값 ③걸리면 ④어디에 ⑤이름 + 한 줄 요약 문장. 「고급」(폼 · YAML)은 탭으로 남는다
   2 값은 칩으로 넣고 바로 형식 검사: 통신은 포트 · 대역 · 도메인을 알아서 나눈다, 틀린 값은 칩이 되지 않고 이유가 보인다. 고급 폼과 같은 값
   3 저장 전 확인: 요약 + 미리보기(최근 감사 로그 재평가) → 「저장 후 적용」 → 정책 반영 · 변경 이력
   4 새 정책은 목적별 템플릿에서 시작(빈 정책도 가능)
   5 이벤트 · 감사 행에서 시작: 「이 행동 막기」 = 값이 채워진 새 정책, 「이 행동 허용」 = 걸린 정책에 예외 칩이 더해진 편집
   6 서버 설정(자동 격리 · 감시 범위 · 제외)은 보기만 + 바꾸는 방법 안내
   7 무결성: 1440 · 1280 넘침 0 · 콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8766 → PLAYWRIGHT=<playwright 경로> node tests/policy-1016.cjs   (VERBOSE=1 · ONLY=정규식 · SHOTS=1) */
const fs = require('fs');
const path = require('path');
const PW = process.env.PLAYWRIGHT || 'playwright';
const { chromium } = require(PW);
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots', '1016-policy');
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
    await pg.route('https://api.osv.dev/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash) => { await pg.goto(`${BASE}?as=admin#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(400); }; // 10/20: 로그인 건너뜀(?as=admin)
  const shot = async (pg, name) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `${name}.png`) }); };
  const ED = '[data-view="rule-editor"]';
  const chips = (pg, group) => pg.$$eval(`${ED} [data-chips="${group}"] [data-chip]`, (els) => els.map((e) => `${e.dataset.type}:${e.dataset.value}`));
  const addChip = async (pg, group, value) => { const i = pg.locator(`${ED} [data-chips="${group}"] input`); await i.fill(value); await i.press('Enter'); await pg.waitForTimeout(100); };
  const rule = (pg, id) => pg.evaluate(async (rid) => (await UI.api.listRules()).find((r) => r.id === rid), id);

  // ---------------- 1. 쉬운 설정이 기본 ----------------
  await T('1 정책을 열면 쉬운 설정: 단계 5개 + 요약 문장, 고급(폼 · YAML)은 탭', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=sensitive-files');
    await pg.waitForSelector(ED);
    ok((await pg.getAttribute(`${ED} [data-mode="easy"]`, 'aria-pressed')) === 'true', '쉬운 설정이 기본이 아님');
    const steps = await pg.$$eval(`${ED} [data-step]`, (els) => els.map((e) => e.dataset.step));
    ok(JSON.stringify(steps) === JSON.stringify(['what', 'values', 'action', 'scope', 'name']), `단계 ${JSON.stringify(steps)}`);
    ok(await pg.isChecked(`${ED} [data-step="what"] input[value="open"]`), '무엇을: 파일 열기 선택 안 됨');
    const sum = await pg.textContent(`${ED} [data-summary]`);
    ok(sum.includes('/etc/shadow') && sum.includes('즉시 격리'), `요약 "${sum}"`);
    ok(!(await pg.textContent(ED)).match(/\bdenyPaths\b|\bkind\b|\baction\b/), '쉬운 설정에 내부 용어가 보임');
    const modes = await pg.$$eval(`${ED} [data-mode]`, (els) => els.map((e) => e.dataset.mode));
    ok(JSON.stringify(modes) === JSON.stringify(['easy', 'form', 'yaml']), `모드 ${JSON.stringify(modes)}`);
    await shot(pg, '01-easy-open');
    await pg.close();
  });

  // ---------------- 2. 칩 입력 · 형식 검사 ----------------
  await T('2 통신 정책: 칩이 포트 · 대역 · 도메인을 알아서 나누고, 틀린 값은 이유와 함께 거부', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=egress-allowlist');
    await pg.waitForSelector(ED);
    await addChip(pg, 'block', '4444');
    await addChip(pg, 'block', 'evil.example');
    await addChip(pg, 'allow', '10.1.0.0/16');
    await addChip(pg, 'allow', 'pypi.org');
    await addChip(pg, 'allow', '99999');
    const b = await chips(pg, 'block'), a = await chips(pg, 'allow');
    ok(b.includes('port:4444') && b.includes('host:evil.example'), `막을 곳 ${JSON.stringify(b)}`);
    ok(a.includes('cidr:10.1.0.0/16') && a.includes('host:pypi.org') && a.includes('port:443'), `허용할 곳 ${JSON.stringify(a)}`);
    ok(!a.some((x) => x.endsWith(':99999')), '틀린 포트가 칩이 됨');
    ok((await pg.textContent(`${ED} [data-chips="allow"] [data-chip-error]`)).includes('1~65535'), '틀린 값 이유 없음');
    const sum = await pg.textContent(`${ED} [data-summary]`);
    ok(sum.includes('4444') && sum.includes('pypi.org'), `요약 "${sum}"`);
    await pg.click(`${ED} [data-mode="form"]`);
    const deny = await pg.inputValue(`${ED} textarea[data-field="denyPorts"]`);
    ok(deny.split('\n').includes('4444'), `고급 폼 denyPorts "${deny}"`);
    await shot(pg, '02-easy-connect');
    await pg.close();
  });

  // ---------------- 3. 저장 전 확인 ----------------
  await T('3 저장 전 확인: 요약 + 미리보기 → 저장 후 적용 → 정책 · 변경 이력', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(400);
    await go(pg, '/policies?id=sensitive-files');
    await pg.waitForSelector(ED);
    await pg.check(`${ED} [data-step="action"] input[value="alert"]`);
    await pg.click(`${ED} button[aria-label="저장 전 확인"]`);
    await pg.waitForSelector(`${ED} [data-part="save-check"] [data-preview-count]`, { timeout: 3000 });
    const chk = await pg.textContent(`${ED} [data-part="save-check"]`);
    ok(chk.includes('알림') && /격리에서 알림으로 바뀜|바뀌는 과거 위반/.test(chk), `확인 칸 "${chk.slice(0, 200)}"`);
    ok((await rule(pg, 'sensitive-files')).action === 'kill', '확인만 했는데 저장됨');
    await shot(pg, '03-save-check');
    // 10/20: 관리자 토큰 칸 삭제 — 로그인(관리자)만으로 저장
    await pg.click(`${ED} [data-part="save-check"] button[aria-label="저장 후 적용"]`);
    await pg.waitForTimeout(400);
    ok((await rule(pg, 'sensitive-files')).action === 'alert', '저장 안 됨');
    const ch = (await pg.evaluate(async () => UI.api.changes({ limit: 1 })))[0];
    ok(ch.kind === 'policy_edit' && ch.summary.includes('sensitive-files'), `변경 이력 ${JSON.stringify(ch)}`);
    await pg.close();
  });

  // ---------------- 4. 템플릿 ----------------
  await T('4 새 정책: 목적별 템플릿 → 값이 채워진 쉬운 설정 → 저장', async () => {
    const pg = await newPage();
    await go(pg, '/policies');
    await pg.click('#page button:has-text("새 정책")');
    await pg.waitForSelector('[data-view="templates"]');
    const ids = await pg.$$eval('[data-view="templates"] [data-template]', (els) => els.map((e) => e.dataset.template));
    ok(ids.length >= 6 && ids.includes('blank') && ids.includes('reverse-shell'), `템플릿 ${JSON.stringify(ids)}`);
    await shot(pg, '04-templates');
    await pg.click('[data-view="templates"] [data-template="reverse-shell"]');
    await pg.waitForSelector(ED);
    ok(await pg.isChecked(`${ED} [data-step="what"] input[value="connect"]`), '통신 선택 안 됨');
    ok((await chips(pg, 'block')).includes('port:4444'), '템플릿 값 없음');
    const id = await pg.inputValue(`${ED} [data-step="name"] input[data-field="id"]`);
    ok(/^[a-z0-9-]+$/.test(id) && id.length > 3, `이름 "${id}"`);
    await pg.click(`${ED} button[aria-label="저장 전 확인"]`);
    await pg.waitForSelector(`${ED} [data-part="save-check"] [data-preview-count]`);
    // 10/20: 관리자 토큰 칸 삭제 — 로그인(관리자)만으로 저장
    await pg.click(`${ED} [data-part="save-check"] button[aria-label="저장 후 적용"]`);
    await pg.waitForTimeout(400);
    ok((await rule(pg, id)).denyPorts.includes(4444), '새 정책 저장 안 됨');
    await pg.close();
  });

  // ---------------- 5. 이벤트 · 감사 행에서 시작 ----------------
  await T('5 감사 행 「이 행동 막기」 → 값이 채워진 새 정책 · 「이 행동 허용」 → 걸린 정책에 예외 칩', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(400);
    const aid = await pg.evaluate(() => UI.state.audit.find((a) => a.ruleId === 'sensitive-files' && a.event.path === '/etc/shadow').id);
    await go(pg, `/audit?id=${aid}`);
    await pg.waitForSelector('.sheet[data-sheet="audit"]');
    await pg.click('.sheet [data-action="block-this"]');
    await pg.waitForSelector(ED);
    ok(await pg.isChecked(`${ED} [data-step="what"] input[value="open"]`), '파일 열기 아님');
    ok((await chips(pg, 'block')).includes('path:/etc/shadow'), `막을 값 ${JSON.stringify(await chips(pg, 'block'))}`);
    await go(pg, `/audit?id=${aid}`);
    await pg.waitForSelector('.sheet[data-sheet="audit"]');
    await pg.click('.sheet [data-action="allow-this"]');
    await pg.waitForSelector(ED);
    ok(pg.url().includes('id=sensitive-files'), `걸린 정책이 아님 ${pg.url()}`);
    const allow = await chips(pg, 'allow');
    ok(allow.includes('path:/etc/shadow'), `예외 칩 ${JSON.stringify(allow)}`);
    ok(await pg.locator(`${ED} [data-chips="allow"] [data-chip][data-new]`).count() === 1, '새로 더한 예외가 표시되지 않음');
    await shot(pg, '05-from-audit-allow');
    await pg.close();
  });

  // ---------------- 6. 서버 설정 ----------------
  await T('6 서버 설정: 자동 격리 · 감시 범위 · 제외를 쉬운 말로 보여 주고 바꾸는 방법만 안내', async () => {
    const pg = await newPage();
    await go(pg, '/settings'); // 10/20: 서버 설정은 「설정」 화면(첫 탭)으로 옮김
    await pg.waitForSelector('[data-part="server-settings"]');
    const t = await pg.textContent('[data-part="server-settings"]');
    ok(t.includes('자동 격리') && t.includes('켜짐') && t.includes('모든 컨테이너') && t.includes('supplyguard-*'), `서버 설정 "${t.slice(0, 160)}"`);
    ok(t.includes('ENFORCE_KILL') && t.includes('WATCH_CONTAINERS') && t.includes('다시 시작'), '바꾸는 방법 안내 없음');
    ok(await pg.locator('[data-part="server-settings"] input, [data-part="server-settings"] select').count() === 0, '서버 설정에 입력칸이 있음');
    await shot(pg, '06-server-settings');
    await pg.close();
  });

  // ---------------- 7. 무결성 ----------------
  await T('7 쉬운 설정 · 템플릿 · 고급 × 1440 · 1280: 페이지 넘침 0', async () => {
    for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) {
      const pg = await newPage(vp);
      for (const hsh of ['/policies?id=egress-allowlist', '/policies?id=__new__', '/policies?id=sandbox-egress']) {
        await go(pg, hsh);
        const o = await pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'); return [d.scrollHeight - innerHeight, d.scrollWidth - innerWidth, m.scrollHeight - m.clientHeight, m.scrollWidth - m.clientWidth]; });
        ok(o.every((x) => x <= 0), `${vp.width} ${hsh} 넘침 ${JSON.stringify(o)}`);
      }
      if (vp.width === 1280) { await go(pg, '/policies?id=egress-allowlist'); await shot(pg, '07-easy-1280'); }
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
