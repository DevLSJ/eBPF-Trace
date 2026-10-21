/* 10/20 2차 시안(W10) 회귀 — A 로그인 · B 확인 대화상자 · C 알림 센터 · D 목록 정리 · E 셸 · F 새 기본 규칙 · G 패키지 골라 차단 · H 서버 설정 보기 · I 직접 IP · 증거
   목업 전용 값(README 「2026-10-20 2차 시안」): 데모 계정 admin · viewer / 비밀번호 demo-pass-1234, 모의 OTP 는 000000 만 틀림, 복구 코드는 XXXX-XXXX 형식이면 한 번 통과
   주소 옵션: ?as=admin · ?as=viewer(로그인 건너뜀) · ?auth=fresh(첫 로그인부터) · ?latency=ms(모의 지연) · ?fail=audit,installs,scans,events(첫 조회 한 번 실패) · ?notify=fail · ?discovery=fanotify
   실행: (mock/ 에서) python3 -m http.server 8767 → BASE=http://127.0.0.1:8767/index.html PLAYWRIGHT=<playwright 경로> node tests/feedback-1020b.cjs   (VERBOSE=1 · ONLY · SHOTS=1) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
const PW = 'demo-pass-1234';
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const W = { timeout: 3000 };

(async () => {
  const br = await chromium.launch();
  const pages = [];
  const newPage = async (viewport = { width: 1440, height: 900 }) => {
    const pg = await br.newPage({ viewport, acceptDownloads: true });
    pages.push(pg);
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const closeAll = async () => { while (pages.length) { const p = pages.pop(); if (!p.isClosed()) await p.close(); } };
  // 로그인 화면 그대로(qs 에 as 없음)
  const raw = async (pg, qs = '', hash = '/') => { await pg.goto(`${BASE}?source=sim${qs}#${hash}`); await pg.waitForSelector('[data-part="auth"], .page-title', W); await pg.waitForTimeout(250); };
  // 관리자로 바로(?as=admin)
  const go = async (pg, hash, qs = '', as = 'admin') => { await pg.goto(`${BASE}?source=sim&as=${as}${qs}#${hash}`); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(400); };
  const shot = async (pg, n) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `w10-${n}.png`) }); };
  const step = (pg) => pg.$eval('[data-part="auth"]', (e) => e.dataset.step).catch(() => '');
  const authErr = (pg) => pg.$eval('[data-part="auth-error"]', (e) => (e.hidden ? '' : e.textContent)).catch(() => '');
  const submitLogin = async (pg, u, p) => { await pg.fill('input[name="username"]', u); await pg.fill('input[name="password"]', p); await pg.click('[data-action="login"]'); await pg.waitForTimeout(250); };
  const login = async (pg, u = 'admin', p = PW) => {
    await submitLogin(pg, u, p);
    await pg.waitForSelector('[data-part="auth"][data-step="otp"]', W);
    await pg.fill('input[name="code"]', '123456'); await pg.click('[data-action="otp"]');
    await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(300);
  };
  const confirmOk = async (pg, reason) => { await pg.waitForSelector('dialog[data-part="confirm"][open]', W); if (reason) await pg.fill('dialog[data-part="confirm"] textarea[name="reason"]', reason); await pg.click('dialog[data-part="confirm"] [data-confirm="ok"]'); await pg.waitForTimeout(350); };
  const runMalicious = async (pg) => {
    const id = await pg.evaluate(() => UI.runInstallDemo('malicious'));
    await pg.waitForFunction((id) => { const s = UI.state.installs.find((x) => x.id === id); return s && s.finishedAt; }, id, { timeout: 8000 });
    await pg.waitForTimeout(300);
    return pg.evaluate((id) => { const s = UI.state.installs.find((x) => x.id === id); return { id: s.id, caseId: s.caseId, container: s.container }; }, id);
  };
  const overflow = (pg) => pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'); return [d.scrollWidth - innerWidth, d.scrollHeight - innerHeight, m ? m.scrollWidth - m.clientWidth : 0]; });

  // ───────────── A. 로그인 · 역할 · 계정 ─────────────
  await T('A1 주소에 as 가 없으면 로그인 화면 — 셸 · 도우미 버튼 없음, 틀리면 아이디 존재 여부를 드러내지 않는 같은 문구', async () => {
    const pg = await newPage();
    await raw(pg);
    ok((await step(pg)) === 'login', `단계 ${await step(pg)}`);
    ok(await pg.locator('.page-title').count() === 0 && await pg.locator('.sidebar').count() === 0, '로그인 전에 셸이 보임');
    ok(await pg.locator('[data-part="assistant-fab"]').count() === 0, '로그인 전에 도우미 버튼');
    await shot(pg, 'login');
    await submitLogin(pg, 'admin', 'wrong-password-1');
    const e1 = await authErr(pg);
    await submitLogin(pg, 'nobody', 'wrong-password-1');
    const e2 = await authErr(pg);
    ok(e1 && e1 === e2, `문구가 다름 「${e1}」 / 「${e2}」`);
    ok(e1.includes('아이디 또는 비밀번호') && e1.includes('5분'), `문구 ${e1}`);
    await pg.close();
  });

  await T('A2 5번 틀리면 5분 잠금 — 맞는 비밀번호도 같은 문구로 거절', async () => {
    const pg = await newPage();
    await raw(pg);
    for (let i = 0; i < 5; i++) await submitLogin(pg, 'viewer', `wrong-pass-${i}xx`);
    await submitLogin(pg, 'viewer', PW);
    ok((await step(pg)) === 'login', `잠겼는데 다음 단계 ${await step(pg)}`);
    ok((await authErr(pg)).includes('5분'), `문구 ${await authErr(pg)}`);
    await pg.close();
  });

  await T('A3 로그인 → OTP 입력(000000 은 틀림) → 화면, 상단 라이선스 「평가판 · N일 남음」 · 계정 메뉴', async () => {
    const pg = await newPage();
    await raw(pg);
    await submitLogin(pg, 'admin', PW);
    ok((await step(pg)) === 'otp', `단계 ${await step(pg)}`);
    await pg.fill('input[name="code"]', '000000'); await pg.click('[data-action="otp"]'); await pg.waitForTimeout(250);
    ok((await authErr(pg)).includes('OTP'), `틀린 OTP 문구 ${await authErr(pg)}`);
    await shot(pg, 'otp');
    await pg.fill('input[name="code"]', '123456'); await pg.click('[data-action="otp"]');
    await pg.waitForSelector('.page-title', W);
    const lic = await pg.textContent('[data-part="license-chip"]');
    ok(/평가판 · \d+일 남음/.test(lic), `라이선스 ${lic}`);
    await pg.click('[data-part="account"]');
    const items = await pg.$$eval('[data-part="account-menu"] [data-menu]', (els) => els.map((e) => e.dataset.menu));
    ok(JSON.stringify(items) === JSON.stringify(['profile', 'password', 'logout']), `메뉴 ${JSON.stringify(items)}`);
    await pg.click('[data-menu="logout"]');
    await pg.waitForSelector('[data-part="auth"][data-step="login"]', W);
    await pg.close();
  });

  await T('A4 「복구 코드로 로그인」 전환 — 같은 코드는 한 번만', async () => {
    const pg = await newPage();
    await raw(pg);
    await submitLogin(pg, 'admin', PW);
    await pg.click('[data-action="use-recovery"]');
    await pg.fill('input[name="recovery"]', 'K7Q2-M9XD'); await pg.click('[data-action="otp"]');
    await pg.waitForSelector('.page-title', W);
    await pg.click('[data-part="account"]'); await pg.click('[data-menu="logout"]');
    await pg.waitForSelector('[data-part="auth"][data-step="login"]', W);
    await submitLogin(pg, 'admin', PW);
    await pg.click('[data-action="use-recovery"]');
    await pg.fill('input[name="recovery"]', 'K7Q2-M9XD'); await pg.click('[data-action="otp"]'); await pg.waitForTimeout(250);
    ok((await authErr(pg)).includes('복구 코드'), `재사용 문구 ${await authErr(pg)}`);
    await pg.close();
  });

  await T('A5 ?auth=fresh — 비밀번호 변경(10자 · 아이디와 다름) → 라이선스(4칸 붙여넣기 분배) → OTP 등록(QR · 수동 키 · 복구 코드 10개, 「저장했습니다」 뒤 진행)', async () => {
    const pg = await newPage();
    await raw(pg, '&auth=fresh');
    await submitLogin(pg, 'admin', PW);
    ok((await step(pg)) === 'password', `단계 ${await step(pg)}`);
    const tryPw = async (next, confirm) => { await pg.fill('input[name="current"]', PW); await pg.fill('input[name="next"]', next); await pg.fill('input[name="confirm"]', confirm); await pg.click('[data-action="password"]'); await pg.waitForTimeout(250); return authErr(pg); };
    ok((await tryPw('abcd', 'abcd')).includes('5자'), '5자 검사'); // 10/20: 최소 길이 10자 → 5자
    ok((await tryPw('admin', 'admin')).length > 0, '아이디와 같은 비밀번호 통과');
    ok((await pg.$eval('[data-part="auth"]', (e) => e.dataset.step)) === 'password', '틀린 비밀번호로 넘어감');
    ok((await tryPw('new-password-2026', 'new-password-2027')).includes('일치'), '확인 불일치 검사');
    await shot(pg, 'password');
    await tryPw('new-password-2026', 'new-password-2026');
    await pg.waitForSelector('[data-part="auth"][data-step="license"]', W);
    const boxes = pg.locator('[data-part="key-boxes"] input');
    ok(await boxes.count() === 4, `칸 ${await boxes.count()}`);
    await boxes.nth(0).focus();
    await pg.evaluate(() => { const el = document.querySelector('[data-part="key-boxes"] input'); const dt = new DataTransfer(); dt.setData('text/plain', '1234-5678-9012-3456'); el.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })); });
    const vals = await pg.$$eval('[data-part="key-boxes"] input', (els) => els.map((e) => e.value));
    ok(JSON.stringify(vals) === JSON.stringify(['1234', '5678', '9012', '3456']), `분배 ${JSON.stringify(vals)}`);
    await shot(pg, 'license');
    await pg.click('[data-action="license"]');
    await pg.waitForSelector('[data-part="auth"][data-step="otp-enroll"]', W);
    ok(await pg.locator('[data-part="qr"] svg').count() === 1, 'QR 없음');
    ok(/^[A-Z2-7]{16,}$/.test((await pg.textContent('[data-part="otp-secret"]')).replace(/\s/g, '')), '수동 키 형식');
    await shot(pg, 'otp-enroll');
    await pg.fill('input[name="code"]', '654321'); await pg.click('[data-action="otp-confirm"]');
    await pg.waitForSelector('[data-part="auth"][data-step="recovery-codes"]', W);
    ok(await pg.locator('[data-part="recovery-codes"] li').count() === 10, '복구 코드 10개 아님');
    ok(await pg.locator('[data-action="finish"]').count() === 0, '「저장했습니다」 전에 진행 버튼');
    await pg.check('input[name="saved"]');
    await pg.click('[data-action="finish"]');
    await pg.waitForSelector('.page-title', W);
    ok((await pg.textContent('[data-part="license-chip"]')).includes('평가판'), '라이선스 칩');
    await pg.close();
  });

  await T('A6 ?auth=fresh 조회자 — 「관리자가 먼저 라이선스를 등록해야 합니다」', async () => {
    const pg = await newPage();
    await raw(pg, '&auth=fresh');
    await submitLogin(pg, 'viewer', PW);
    ok((await step(pg)) === 'login', `단계 ${await step(pg)}`);
    ok((await authErr(pg)).includes('관리자가 먼저 라이선스를 등록해야 합니다'), `문구 ${await authErr(pg)}`);
    await pg.close();
  });

  await T('A7 ?as=viewer — 쓰기 버튼을 숨긴다(판정 · 새 정책 · 적용 · 검사 시작 · 계정 탭), 보이는데 못 누르는 버튼 0', async () => {
    const pg = await newPage();
    await go(pg, '/installs', '', 'viewer');
    const s = await runMalicious(pg);
    await pg.evaluate((id) => { location.hash = `#/installs?id=${id}`; }, s.id); await pg.waitForTimeout(400);
    await pg.waitForSelector('.sheet[data-sheet="install"]', W);
    ok(await pg.locator('.sheet button[aria-label="악성 확정"], .sheet button[aria-label="오탐"]').count() === 0, '조회자에게 판정 버튼');
    await pg.evaluate(async (cid) => { /* 관리자가 판정한 상태를 만든다 */ await UI.api.decide(cid, { decision: 'malicious', note: '' }); }, s.caseId).catch(() => {});
    await pg.evaluate(() => { location.hash = '#/policies'; }); await pg.waitForTimeout(500);
    ok(await pg.locator('#page button:has-text("새 정책")').count() === 0, '새 정책 버튼');
    ok(await pg.locator('[data-view="proposal"] button[aria-label="적용"]').count() === 0, '적용 버튼');
    ok(await pg.locator('[data-pol-tab="accounts"]').count() === 0, '계정 탭');
    ok(await pg.locator('#page button[disabled]').count() === 0, `꺼진 버튼 ${await pg.locator('#page button[disabled]').count()}`);
    await pg.evaluate(() => { location.hash = '#/scans'; }); await pg.waitForTimeout(400);
    ok(await pg.locator('button[aria-label="검사 시작"]').count() === 0, '검사 시작 버튼');
    ok((await pg.textContent('[data-part="account"]')).includes('조회자'), '계정 버튼에 역할 표시 없음');
    await pg.close();
  });

  await T('A8 계정 탭 — 목록 · 추가(임시 비밀번호 1회 표시) · 비밀번호 초기화 · 마지막 관리자 강등 금지 안내', async () => {
    const pg = await newPage();
    await go(pg, '/settings', ''); // 10/20: 계정 탭은 「설정」 화면으로 옮김
    await pg.click('[data-settings-tab="accounts"]');
    await pg.waitForSelector('[data-table="users"]', W);
    const users = await pg.$$eval('[data-table="users"] tr[data-user]', (els) => els.map((e) => e.dataset.user));
    ok(users.includes('admin') && users.includes('viewer'), `계정 ${JSON.stringify(users)}`);
    ok(await pg.locator('[data-part="last-admin"]').count() === 1, '마지막 관리자 안내 없음');
    ok(await pg.locator('tr[data-user="admin"] [data-action="demote"], tr[data-user="admin"] [data-action="disable"]').count() === 0, '마지막 관리자에 강등 · 비활성 버튼');
    await pg.click('[data-action="user-add"]');
    await pg.fill('input[name="new-username"]', 'analyst1'); await pg.fill('input[name="new-display"]', '분석 담당'); await pg.selectOption('select[name="new-role"]', 'viewer');
    await pg.click('[data-action="user-create"]');
    await pg.waitForSelector('[data-temp-password]', W);
    const tmp = (await pg.textContent('[data-temp-password]')).trim();
    ok(tmp.length >= 12, `임시 비밀번호 ${tmp.length}자`);
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(250);
    ok(await pg.locator('tr[data-user="analyst1"]').count() === 1, '새 계정 행 없음');
    ok(!(await pg.textContent('[data-table="users"]')).includes(tmp), '임시 비밀번호가 표에 남음');
    await pg.click('tr[data-user="analyst1"] [data-action="reset-pw"]');
    await confirmOk(pg);
    await pg.waitForSelector('[data-temp-password]', W);
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(200);
    await pg.close();
  });

  // ───────────── B. 확인 대화상자 ─────────────
  await T('B1 악성 확정 → 확인 대화상자(대상 · 함께 일어나는 일 · 사유 · 되돌리기), Esc 는 취소, 확인하면 사유가 메모로', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runMalicious(pg);
    await pg.evaluate((id) => { location.hash = `#/installs?id=${id}`; }, s.id); await pg.waitForTimeout(400);
    await pg.click('.sheet [data-part="decision"] button[aria-label="악성 확정"]');
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    const tgt = await pg.textContent('[data-part="confirm-target"]');
    ok(tgt.includes('pip ./reqeusts'), `대상 ${tgt}`);
    const eff = await pg.$$eval('[data-part="confirm-effects"] li', (els) => els.map((e) => e.textContent));
    ok(eff.some((t) => t.includes('차단') && t.includes('pip:reqeusts')), `효과 ${JSON.stringify(eff)}`);
    ok((await pg.textContent('[data-part="confirm-undo"]')).length > 5, '되돌리기 안내 없음');
    ok(await pg.locator('dialog[data-part="confirm"] textarea[name="reason"]').count() === 1, '사유 칸 없음');
    await shot(pg, 'confirm');
    await pg.keyboard.press('Escape'); await pg.waitForTimeout(250);
    ok(await pg.evaluate((id) => UI.state.cases.find((c) => c.id === id).state, s.caseId) === 'open', 'Esc 로 판정됨');
    await pg.click('.sheet [data-part="decision"] button[aria-label="악성 확정"]');
    await confirmOk(pg, '타이포스쿼팅 — 확인');
    const c = await pg.evaluate((id) => UI.state.cases.find((x) => x.id === id), s.caseId);
    ok(c.state === 'decided' && c.note === '타이포스쿼팅 — 확인', `건 ${c.state} 메모 ${c.note}`);
    await pg.close();
  });

  await T('B2 제안 「적용」 · 「버림」 · 차단 목록 「해제」도 확인 대화상자 — 두 번 누르기 없음, 사유는 변경 이력에', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runMalicious(pg);
    const pid = await pg.evaluate(async (cid) => (await UI.api.decide(cid, { decision: 'malicious', note: '' })).proposal.id, s.caseId);
    await pg.evaluate((p) => { location.hash = `#/policies?proposal=${p}`; }, pid); await pg.waitForTimeout(600);
    await pg.click('[data-view="proposal"] button[aria-label="적용"]');
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    const eff = await pg.$$eval('[data-part="confirm-effects"] li', (els) => els.map((e) => e.textContent));
    ok(eff.some((t) => /차단 목록 \+\d/.test(t)), `효과 ${JSON.stringify(eff)}`);
    await confirmOk(pg, '데모 적용');
    ok(await pg.evaluate((p) => UI.state.proposals.find((x) => x.id === p).state, pid) === 'applied', '적용 안 됨');
    ok(await pg.evaluate(() => UI.state.changes[0].reason) === '데모 적용', '변경 이력에 사유 없음');
    const btn = pg.locator('[data-section="blocklist"] [data-value="pip:reqeusts"] button');
    const before = await btn.textContent();
    await btn.click();
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    ok((await pg.$$eval('[data-part="confirm-effects"] li', (els) => els.map((e) => e.textContent))).some((t) => t.includes('다음 설치')), '해제 효과 문구');
    await confirmOk(pg);
    ok(await pg.evaluate(() => !UI.state.blocklist.packages.some((x) => x.value === 'pip:reqeusts')), '해제 안 됨');
    ok(before.trim() === '해제', `버튼 글 ${before}`);
    await pg.close();
  });

  await T('B3 런타임 이미지 차단 적용 — 「같은 이미지 컨테이너 N개 다음 시작 때 격리」 · 대화상자 안에서 Tab 이 돈다', async () => {
    const pg = await newPage();
    await go(pg, '/topology');
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(400);
    const pid = await pg.evaluate(async () => { const c = UI.state.cases.find((x) => x.source === 'runtime' && x.state === 'open'); return (await UI.api.decide(c.id, { decision: 'malicious', note: '' })).proposal.id; });
    await pg.evaluate((p) => { location.hash = `#/policies?proposal=${p}`; }, pid); await pg.waitForTimeout(600);
    await pg.click('[data-view="proposal"] button[aria-label="적용"]');
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    const eff = await pg.$$eval('[data-part="confirm-effects"] li', (els) => els.map((e) => e.textContent));
    ok(eff.some((t) => /같은 이미지 컨테이너 \d+개/.test(t) && t.includes('다음 시작')), `효과 ${JSON.stringify(eff)}`);
    for (let i = 0; i < 8; i++) await pg.keyboard.press('Tab');
    ok(await pg.evaluate(() => !!document.activeElement.closest('dialog[data-part="confirm"]')), '포커스가 대화상자 밖으로');
    await pg.keyboard.press('Escape');
    await pg.close();
  });

  // ───────────── C. 알림 센터 ─────────────
  await T('C1 상단 종 — 판정 대기 · 제안 대기 · 도메인 판단 꺼짐 · dry-run · 웹훅 실패를 데이터로, 모두 읽음(새로고침 뒤 유지), 누르면 그 화면', async () => {
    const pg = await newPage();
    await go(pg, '/events', '&dns=off&notify=fail');
    const s = await runMalicious(pg);
    const s2 = await runMalicious(pg);
    await pg.evaluate(async (cid) => { await UI.api.decide(cid, { decision: 'malicious', note: '' }); UI.state.info.enforceKill = false; UI.emit(); }, s2.caseId);
    await pg.click('[data-part="bell"]');
    await pg.waitForSelector('[data-part="notices"]:not([hidden])', W);
    const ids = await pg.$$eval('[data-part="notices"] [data-notice]', (els) => els.map((e) => e.dataset.notice));
    for (const k of ['pending', 'proposals', 'dns', 'dryrun', 'webhook']) ok(ids.includes(k), `${k} 없음 ${JSON.stringify(ids)}`);
    const badge = Number(await pg.$eval('[data-part="bell-badge"]', (e) => (e.hidden ? '0' : e.textContent)));
    ok(badge >= 5, `배지 ${badge}`);
    await shot(pg, 'notify');
    await pg.click('[data-action="read-all"]');
    ok(await pg.$eval('[data-part="bell-badge"]', (e) => e.hidden), '모두 읽음 뒤 배지');
    await pg.reload(); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(300);
    // 새로고침하면 시뮬 서버가 비지만, 같은 알림(dns · webhook)은 읽음으로 남는다
    await pg.click('[data-part="bell"]');
    const unread = await pg.$$eval('[data-part="notices"] [data-notice="dns"], [data-part="notices"] [data-notice="webhook"]', (els) => els.map((e) => e.dataset.unread));
    ok(unread.length === 2 && unread.every((x) => x === 'false'), `읽음 유지 ${JSON.stringify(unread)}`);
    await pg.click('[data-part="notices"] [data-notice="dns"]'); await pg.waitForTimeout(300);
    ok((await pg.evaluate(() => location.hash)).startsWith('#/settings'), `이동 ${await pg.evaluate(() => location.hash)}`); // 10/20: 서버 상태 알림은 설정 화면으로
    void s;
    await pg.close();
  });

  await T('C2 실시간 연결이 끊기면 알림 센터에 「실시간 연결 끊김」', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    await pg.evaluate(() => UI.disconnect(2500)); await pg.waitForTimeout(200);
    await pg.click('[data-part="bell"]');
    ok(await pg.locator('[data-part="notices"] [data-notice="conn"]').count() === 1, '연결 끊김 항목 없음');
    await pg.close();
  });

  // ───────────── D. 목록 정리 ─────────────
  await T('D1 첫 로드 스켈레톤(?latency=) — 감사 로그 · 설치 검사 · 공급망 검사 · 이벤트', async () => {
    for (const hash of ['/audit', '/installs', '/scans', '/events']) {
      const pg = await newPage();
      await pg.goto(`${BASE}?source=sim&as=admin&latency=1500#${hash}`);
      await pg.waitForSelector('.page-title', W);
      ok(await pg.locator('#page [data-part="skeleton"]').count() >= 1, `${hash} 스켈레톤 없음`);
      await pg.waitForTimeout(1900);
      ok(await pg.locator('#page [data-part="skeleton"]').count() === 0, `${hash} 스켈레톤이 남음`);
      await pg.close();
    }
  });

  await T('D2 오류 + 「다시 시도」(?fail=) · 아이콘 있는 빈 상태(?fresh=1)', async () => {
    for (const [hash, k] of [['/audit', 'audit'], ['/installs', 'installs'], ['/scans', 'scans'], ['/events', 'events']]) {
      const pg = await newPage();
      await go(pg, hash, `&fail=${k}`);
      await pg.waitForSelector('#page [data-part="error"]', W);
      await pg.click('#page [data-part="error"] [data-action="retry"]'); await pg.waitForTimeout(500);
      ok(await pg.locator('#page [data-part="error"]').count() === 0, `${hash} 다시 시도 뒤에도 오류`);
      await pg.close();
    }
    for (const hash of ['/audit', '/installs', '/scans']) {
      const pg = await newPage();
      await go(pg, hash, '&fresh=1');
      ok(await pg.locator('#page [data-part="empty"] .empty-icon').count() >= 1, `${hash} 아이콘 빈 상태 없음`);
      await pg.close();
    }
  });

  await T('D3 적용된 필터 칩 + 모두 해제 — 이벤트 · 감사 로그 · 설치 검사 · 공급망 검사', async () => {
    const cases = [['/events?kind=exec&container=web', 2], ['/audit?container=pkg&rule=sens', 2], ['/installs?status=all&manager=pip', 2], ['/scans?verdict=malicious', 1]];
    for (const [hash, n] of cases) {
      const pg = await newPage();
      await go(pg, hash);
      const chips = await pg.locator('#page [data-part="filter-chips"] [data-chip]').count();
      ok(chips === n, `${hash} 칩 ${chips}`);
      await pg.click('#page [data-part="filter-chips"] [data-action="clear-filters"]'); await pg.waitForTimeout(400);
      ok(await pg.locator('#page [data-part="filter-chips"] [data-chip]').count() === 0, `${hash} 해제 뒤 칩이 남음`);
      const q = await pg.evaluate(() => location.hash.split('?')[1] || '');
      ok(!/kind=|container=|rule=|manager=|verdict=/.test(q), `${hash} 주소에 필터가 남음 ${q}`);
      await pg.close();
    }
  });

  await T('D4 감사 로그 CSV 내보내기 — 기간이 없으면 안내, 있으면 .csv 내려받기(머리 줄)', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    await pg.click('[data-action="export-csv"]'); await pg.waitForTimeout(200);
    ok((await pg.textContent('[data-part="export-error"]')).includes('기간'), '기간 안내 없음');
    const d = new Date(Date.now() - 2 * 86400e3); const e = new Date(Date.now() + 3600e3);
    const loc = (x) => new Date(x.getTime() - x.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    await pg.fill('input[aria-label="시작"]', loc(d)); await pg.dispatchEvent('input[aria-label="시작"]', 'change');
    await pg.fill('input[aria-label="끝"]', loc(e)); await pg.dispatchEvent('input[aria-label="끝"]', 'change');
    await pg.waitForTimeout(400);
    const [dl] = await Promise.all([pg.waitForEvent('download', W), pg.click('[data-action="export-csv"]')]);
    ok(dl.suggestedFilename().endsWith('.csv'), `파일 ${dl.suggestedFilename()}`);
    const text = fs.readFileSync(await dl.path(), 'utf8').replace(/^﻿/, '');
    const lines = text.trim().split('\n');
    ok(lines[0].startsWith('id,시각,컨테이너') && lines.length > 5, `CSV ${lines[0]} · ${lines.length}줄`);
    await pg.close();
  });

  await T('D5 모든 행을 키보드(Enter/Space)로 연다 — 설치 검사 · 감사 로그 · 공급망 검사 · 이벤트', async () => {
    const pg = await newPage();
    await go(pg, '/installs?status=all');
    await pg.focus('[data-table="installs"] tbody tr'); await pg.keyboard.press('Enter'); await pg.waitForTimeout(300);
    ok(await pg.locator('.sheet[data-sheet="install"]').count() === 1, '설치 행 Enter');
    await pg.evaluate(() => { location.hash = '#/audit'; }); await pg.waitForTimeout(500);
    await pg.focus('[data-table="audit"] tbody tr'); await pg.keyboard.press(' '); await pg.waitForTimeout(300);
    ok(await pg.locator('.sheet[data-sheet="audit"]').count() === 1, '감사 행 Space');
    await pg.evaluate(async () => { const r = await UI.api.startScan({ kind: 'package', manager: 'pip', name: 'reqeusts' }); location.hash = '#/scans'; return r; });
    await pg.waitForTimeout(1600);
    await pg.focus('[data-table="scans"] tbody tr'); await pg.keyboard.press('Enter'); await pg.waitForTimeout(400);
    ok(await pg.locator('.sheet[data-sheet="scan"]').count() === 1, '검사 행 Enter');
    await pg.evaluate(() => { location.hash = '#/events?normal=1'; }); await pg.waitForTimeout(500);
    await pg.focus('.feed-row'); await pg.keyboard.press('Enter'); await pg.waitForTimeout(300);
    ok(await pg.locator('.sheet[data-sheet="event"]').count() === 1, '이벤트 행 Enter');
    await pg.close();
  });

  await T('D6 실시간 연결이 끊기면 상단 붉은 배너, 재연결 뒤 「끊긴 동안 N건을 채웠습니다」', async () => {
    const pg = await newPage();
    await go(pg, '/events', '&normal=1');
    await pg.evaluate(() => UI.disconnect(1500)); await pg.waitForTimeout(300);
    ok(await pg.$eval('[data-banner="conn"]', (e) => !e.hidden), '끊김 배너 없음');
    await pg.waitForTimeout(1700);
    ok(await pg.$eval('[data-banner="conn"]', (e) => e.hidden), '재연결 뒤 끊김 배너가 남음');
    const t = await pg.$eval('[data-banner="backfill"]', (e) => (e.hidden ? '' : e.textContent));
    const m = t.match(/끊긴 동안 (\d+)건을 채웠습니다/);
    ok(m && Number(m[1]) > 0, `채움 배너 「${t}」`);
    await pg.close();
  });

  // ───────────── E. 셸 ─────────────
  await T('E1 사이드바 통합 검색 — / 로 포커스, 패키지 · 규칙 id · 컨테이너 · 도메인 · 검사, 고르면 그 화면', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.keyboard.press('/');
    ok(await pg.evaluate(() => document.activeElement && document.activeElement.matches('[data-part="search"] input')), '/ 로 포커스 안 됨');
    await pg.keyboard.type('sandbox-eg'); await pg.waitForTimeout(250);
    const types = await pg.$$eval('[data-part="search-results"] [data-result]', (els) => els.map((e) => e.dataset.type));
    ok(types.includes('rule'), `결과 ${JSON.stringify(types)}`);
    await pg.keyboard.press('Enter'); await pg.waitForTimeout(400);
    ok((await pg.evaluate(() => location.hash)).includes('/policies?id=sandbox-egress'), `이동 ${await pg.evaluate(() => location.hash)}`);
    await pg.fill('[data-part="search"] input', 'colourama'); await pg.waitForTimeout(250);
    ok((await pg.$$eval('[data-part="search-results"] [data-result]', (els) => els.map((e) => e.dataset.type))).includes('package'), '패키지 결과 없음');
    await pg.fill('[data-part="search"] input', 'web-api'); await pg.waitForTimeout(250);
    ok((await pg.$$eval('[data-part="search-results"] [data-result]', (els) => els.map((e) => e.dataset.type))).includes('container'), '컨테이너 결과 없음');
    await pg.fill('[data-part="search"] input', 'pythonhosted'); await pg.waitForTimeout(250);
    ok((await pg.$$eval('[data-part="search-results"] [data-result]', (els) => els.map((e) => e.dataset.type))).includes('domain'), '도메인 결과 없음');
    await pg.evaluate(() => UI.api.startScan({ kind: 'package', manager: 'pip', name: 'reqeusts' })); await pg.waitForTimeout(300);
    await pg.fill('[data-part="search"] input', 'scan-0'); await pg.waitForTimeout(250);
    ok((await pg.$$eval('[data-part="search-results"] [data-result]', (els) => els.map((e) => e.dataset.type))).includes('scan'), '검사 결과 없음');
    await pg.close();
  });

  await T('E2 사이드바 접기(56px, 새로고침 뒤 유지) · 폭 1100px 이하 자동 접기 · ? 도움말에 단축키 목록', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.click('[data-action="collapse"]'); await pg.waitForTimeout(300);
    ok(Math.round(await pg.$eval('.sidebar', (e) => e.getBoundingClientRect().width)) === 56, '56px 아님');
    await shot(pg, 'sidebar-collapsed');
    await pg.reload(); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(300);
    ok(Math.round(await pg.$eval('.sidebar', (e) => e.getBoundingClientRect().width)) === 56, '새로고침 뒤 펼쳐짐');
    await pg.click('[data-action="collapse"]');
    await pg.close();
    const p2 = await newPage({ width: 1060, height: 800 });
    await go(p2, '/');
    ok(Math.round(await p2.$eval('.sidebar', (e) => e.getBoundingClientRect().width)) === 56, '1100px 이하인데 펼쳐짐');
    await p2.keyboard.press('?');
    await p2.waitForSelector('#help[open] [data-part="shortcuts"]', W);
    const keys = await p2.$$eval('#help [data-part="shortcuts"] kbd', (els) => els.map((e) => e.textContent));
    ok(keys.includes('/') && keys.includes('?') && keys.includes('Esc'), `단축키 ${JSON.stringify(keys)}`);
    ok(await p2.locator('#help ol.steps li').count() >= 6, '기존 사용 흐름이 사라짐');
    await p2.close();
  });

  // ───────────── F. 새 기본 규칙 ─────────────
  await T('F1 정책 맨 위 「기본 정책에 새 규칙 1개 · 바뀐 규칙 1개」 → 펼침 → 미리보기 후 추가(저장 전 확인) · 이번엔 숨기기(유지)', async () => {
    const pg = await newPage();
    await go(pg, '/policies');
    await pg.waitForSelector('[data-part="defaults-banner"]', W);
    const t = await pg.textContent('[data-part="defaults-banner"]');
    ok(t.includes('새 규칙 1개') && t.includes('바뀐 규칙 1개'), `띠 ${t}`);
    await pg.click('[data-action="defaults-toggle"]');
    ok(await pg.locator('[data-default="runtime-direct-ip"]').count() === 1 && await pg.locator('[data-default="sandbox-egress"]').count() === 1, '규칙 행');
    ok((await pg.textContent('[data-part="defaults-banner"]')).includes('덮어쓰지 않습니다'), '덮어쓰지 않음 문구');
    await shot(pg, 'policy-defaults');
    await pg.click('[data-default="runtime-direct-ip"] [data-action="default-preview"]');
    await pg.waitForSelector('[data-part="save-check"]', W);
    // 10/20: 관리자 토큰 칸 삭제 — 로그인(관리자)만으로 저장
    await pg.click('[data-part="save-check"] button[aria-label="저장 후 적용"]'); await pg.waitForTimeout(500);
    ok(await pg.evaluate(() => UI.state.rules.some((r) => r.id === 'runtime-direct-ip' && r.directIp === 'alert')), '규칙이 directIp 와 함께 저장되지 않음');
    const t2 = await pg.textContent('[data-part="defaults-banner"]');
    ok(!t2.includes('새 규칙') && t2.includes('바뀐 규칙 1개'), `저장 뒤 띠 ${t2}`);
    if (!(await pg.locator('[data-default="sandbox-egress"]').isVisible())) await pg.click('[data-action="defaults-toggle"]');
    await pg.click('[data-default="sandbox-egress"] [data-action="default-hide"]'); await pg.waitForTimeout(250);
    ok(await pg.locator('[data-part="defaults-banner"]').count() === 0, '숨기기 뒤 띠가 남음');
    await pg.reload(); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(500);
    ok((await pg.locator('[data-part="defaults-banner"]').count() === 0) || !(await pg.textContent('[data-part="defaults-banner"]')).includes('바뀐 규칙'), '숨김이 유지되지 않음');
    await pg.close();
  });

  // ───────────── G. 패키지 골라 차단 ─────────────
  await T('G1 저장소 검사 결과의 패키지 목록 — 여러 잠금 파일은 한 줄(출처 나열), 골라서 「선택한 N개 차단 목록에 올리기」 → 확인 → 제안', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    const id = await pg.evaluate(async () => (await UI.api.startScan({ kind: 'repo', url: 'https://github.com/psf/requests' })).id);
    await pg.waitForTimeout(1500);
    await pg.evaluate((i) => { location.hash = `#/scans?id=${i}`; }, id); await pg.waitForTimeout(500);
    await pg.waitForSelector('.sheet [data-part="packages"]', W);
    const rows = await pg.$$eval('.sheet [data-part="packages"] tr[data-pkg]', (els) => els.map((e) => [e.dataset.pkg, Number(e.dataset.sources)]));
    ok(new Set(rows.map((r) => r[0])).size === rows.length, `같은 패키지가 두 줄 ${JSON.stringify(rows)}`);
    ok(rows.some((r) => r[1] >= 2), `출처 2개 이상인 줄 없음 ${JSON.stringify(rows)}`);
    ok(await pg.locator('.sheet [data-action="block-selected"]').count() === 0, '고르기 전에 차단 버튼');
    await pg.check('.sheet tr[data-pkg="pip:urllib3@1.26.5"] input[data-pick]'); // 10/21: 행 키 = 매니저:이름@버전(React ScanPackages)
    await pg.check('.sheet tr[data-pkg="pip:idna@2.10"] input[data-pick]');
    ok((await pg.textContent('.sheet [data-action="block-selected"]')).includes('선택한 2개'), '버튼 글');
    await shot(pg, 'scan-packages');
    await pg.click('.sheet [data-action="block-selected"]');
    await confirmOk(pg, '취약 의존성 차단');
    await pg.waitForTimeout(500);
    const h = await pg.evaluate(() => location.hash);
    ok(h.includes('/policies?proposal='), `이동 ${h}`);
    const ch = await pg.$$eval('[data-view="proposal"] [data-change]', (els) => els.map((e) => e.dataset.change));
    ok(ch.includes('block:packages:pip:urllib3') && ch.includes('block:packages:pip:idna'), `변경 ${JSON.stringify(ch)}`);
    await pg.close();
  });

  // ───────────── H. 서버 설정 보기 ─────────────
  await T('H1 서버 설정에 알림(호스트 · 보낸/실패 · 마지막 오류 · 테스트 발송) · 컨테이너 발견 방식(docker-events 안내) · 도메인 판단', async () => {
    const pg = await newPage();
    await go(pg, '/settings', '&notify=fail'); // 10/20: 서버 설정은 「설정」 화면 첫 탭
    for (const k of ['notify', 'discovery', 'dns']) ok(await pg.locator(`[data-part="server-settings"] [data-ss="${k}"]`).count() === 1, `${k} 줄 없음`);
    const n = await pg.textContent('[data-ss="notify"]');
    ok(n.includes('hooks.example.test') && n.includes('실패') && n.includes('502'), `알림 ${n}`);
    ok((await pg.textContent('[data-ss="discovery"]')).includes('0.1초'), '발견 방식 안내');
    const before = Number(await pg.textContent('[data-notify-sent]'));
    await pg.click('[data-action="notify-test"]'); await pg.waitForTimeout(1800);
    const after = Number(await pg.textContent('[data-notify-sent]')) + Number(await pg.textContent('[data-notify-failed]'));
    ok(after > before, `테스트 발송 뒤 ${before} → ${after}`);
    await pg.close();
    const p2 = await newPage();
    await go(p2, '/settings', '&discovery=fanotify', 'viewer'); // 10/20
    ok(!(await p2.textContent('[data-ss="discovery"]')).includes('0.1초'), 'fanotify 인데 안내');
    ok(await p2.locator('[data-action="notify-test"]').count() === 0, '조회자에게 테스트 발송');
    await p2.close();
  });

  // ───────────── I. 직접 IP · 증거 ─────────────
  await T('I1 이벤트 상세 — 도메인 조회 여부(dnsTraced) · 「도메인 조회 없는 IP 직접 연결」', async () => {
    const pg = await newPage();
    await go(pg, '/events', '&normal=1');
    const key = await pg.evaluate(() => { UI.simEvent('web-api', { kind: 'connect', comm: 'node', dstIp: '203.0.113.9', dstPort: 443 }); const v = UI.state.verdicts.find((x) => x.event.dstIp === '203.0.113.9'); return v && v.key; });
    ok(key, '이벤트 없음');
    await pg.evaluate((k) => { location.hash = `#/events?normal=1&id=${k}`; }, key); await pg.waitForTimeout(500);
    await pg.waitForSelector('.sheet[data-sheet="event"] [data-dns]', W);
    ok(await pg.$eval('[data-dns]', (e) => e.dataset.dns) === 'direct', '직접 연결 표시 아님');
    ok((await pg.textContent('[data-dns]')).includes('도메인 조회 없는 IP 직접 연결'), '문구');
    const key2 = await pg.evaluate(() => { UI.simEvent('web-api', { kind: 'connect', comm: 'node', dstIp: '104.16.2.35', dstPort: 443, dstHost: 'api.github.com' }); return UI.state.verdicts.find((x) => x.event.dstHost === 'api.github.com').key; });
    await pg.evaluate((k) => { location.hash = `#/events?normal=1&id=${k}`; }, key2); await pg.waitForTimeout(500);
    ok(await pg.$eval('[data-dns]', (e) => e.dataset.dns) === 'traced', '도메인 확인 표시 아님');
    await pg.close();
  });

  await T('I2 감사 상세(격리된 건)에 「증거」 탭 — 로그 · 파일 변경 · 프로세스, 일부만 모았으면 「일부만 모음」', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    const s = await runMalicious(pg);
    const aid = await pg.evaluate((name) => UI.state.audit.find((a) => a.event.containerName === name && UI.levelOf(a) === 'killed').id, s.container);
    await pg.evaluate((a) => { location.hash = `#/audit?id=${a}`; }, aid); await pg.waitForTimeout(500);
    await pg.waitForSelector('.sheet[data-sheet="audit"] [data-tab="evidence"]', W);
    await pg.click('.sheet [data-tab="evidence"]'); await pg.waitForTimeout(300);
    await pg.waitForSelector('[data-part="evidence"]', W);
    ok((await pg.textContent('[data-part="evidence-logs"]')).length > 10, '로그 없음');
    ok(await pg.locator('[data-part="evidence-changes"] tbody tr').count() >= 1, '파일 변경 없음');
    ok(await pg.locator('[data-part="evidence-partial"]').count() === 1, '「일부만 모음」 없음(설치 컨테이너는 일부만)');
    await shot(pg, 'evidence');
    const normalId = await pg.evaluate(() => UI.state.audit.find((a) => UI.levelOf(a) === 'alert').id);
    await pg.evaluate((a) => { location.hash = `#/audit?id=${a}`; }, normalId); await pg.waitForTimeout(400);
    ok(await pg.locator('.sheet [data-tab="evidence"]').count() === 0, '격리 아닌 건에 증거 탭');
    await pg.close();
  });

  // ───────────── J. 공급망 검사 건의 출처 표기 · 링크 (코디네이터 추가 10/20) ─────────────
  await T('J1 공급망 검사 건 — 출처 「공급망 검사」, 링크 #/scans?id=<scanId> (대시보드 판정 대기 · 정책 제안 근거 · 감사 판정 이력 · 대응 가이드)', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    const sid = await pg.evaluate(async () => (await UI.api.startScan({ kind: 'package', manager: 'pip', name: 'reqeusts' })).id);
    await pg.waitForTimeout(1500);
    const r = await pg.evaluate(async (id) => UI.api.scanBlock(id), sid);
    const href = `#/scans?id=${sid}`;
    // 정책 제안 근거
    await pg.evaluate((p) => { location.hash = `#/policies?proposal=${p}`; }, r.proposalId); await pg.waitForTimeout(500);
    const basis = await pg.textContent('[data-view="proposal"] [data-part="basis"]');
    ok(basis.includes('공급망 검사') && await pg.locator(`[data-view="proposal"] [data-part="basis"] a[href="${href}"]`).count() === 1, `근거 ${basis}`);
    // 감사 › 판정 · 변경 이력: 대상은 패키지 이름, 건 링크는 검사 결과
    await pg.evaluate(() => { location.hash = '#/audit?view=history'; }); await pg.waitForTimeout(600);
    const row = pg.locator(`[data-table="history"] tr[data-case="${r.caseId}"]`).first();
    ok(await row.count() === 1, '이력에 그 건 행 없음');
    ok((await row.textContent()).includes('pip reqeusts') && (await row.getAttribute('data-source')) === 'scan', `이력 행 ${await row.textContent()}`);
    ok(await row.locator(`a[href="${href}"]`).count() >= 1, '이력 행에 검사 결과 링크 없음');
    // 대시보드 판정 대기(렌더 확인용으로 건을 다시 판정 대기로 둔다)
    await pg.evaluate((cid) => { const c = UI.state.cases.find((x) => x.id === cid); c.state = 'open'; c.decision = 'pending'; UI.emit(); location.hash = '#/'; }, r.caseId); await pg.waitForTimeout(600);
    const a = pg.locator(`[data-section="pending"] a[data-case="${r.caseId}"]`);
    ok(await a.getAttribute('href') === href, `판정 대기 링크 ${await a.getAttribute('href')}`);
    ok((await a.locator('.src-chip').textContent()).includes('공급망 검사'), `출처 칩 ${await a.locator('.src-chip').textContent()}`);
    // 대응 가이드: 출처 · 링크
    await pg.click('[data-part="assistant-fab"]'); await pg.waitForTimeout(300);
    await pg.evaluate((cid) => { const s = document.querySelector('[data-part="guide"] select'); if (s) { s.value = cid; s.dispatchEvent(new Event('change', { bubbles: true })); } }, r.caseId); await pg.waitForTimeout(300);
    ok((await pg.textContent('[data-part="guide"] .guide-head')).includes('공급망 검사'), '가이드 출처');
    ok(await pg.locator(`[data-part="guide"] a[href="${href}"]`).count() >= 1, '가이드 링크');
    await pg.close();
  });

  // ───────────── 넘침 · 콘솔 ─────────────
  await T('Z 새 상태 1440 · 1280 넘침 0(로그인 · 계정 탭 · 알림 센터 · 접힌 사이드바)', async () => {
    for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) {
      const pg = await newPage(vp);
      await raw(pg);
      ok((await overflow(pg)).every((x) => x <= 0), `${vp.width} 로그인 넘침 ${JSON.stringify(await overflow(pg))}`);
      await go(pg, '/settings?tab=accounts'); // 10/20: 계정 탭은 설정 화면
      ok((await overflow(pg)).every((x) => x <= 0), `${vp.width} 계정 넘침 ${JSON.stringify(await overflow(pg))}`);
      await pg.click('[data-part="bell"]');
      ok((await overflow(pg)).every((x) => x <= 0), `${vp.width} 알림 넘침 ${JSON.stringify(await overflow(pg))}`);
      await pg.close();
    }
  });

  await closeAll();
  await br.close();
  const pass = results.filter((r) => r[0]).length;
  if (!process.env.VERBOSE) for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  for (const e of consoleErrors) console.log(`CONSOLE  ${e}`);
  console.log(`\n${pass}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  process.exit(pass === results.length && !consoleErrors.length ? 0 : 1);
})();
