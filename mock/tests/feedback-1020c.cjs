/* 2026-10-20 결정 반영(W17) 회귀 — 사용자 10/20 확정 결정 1~8 + 비밀번호 5자(코디네이터 추가 9)
   1 정책 머리의 관리자 토큰 칸 삭제 — 쓰기는 로그인 역할만(조회자는 숨김)
   2 「설정」 화면(#/settings, 사이드바 「설정 · 기록」): 서버 설정 · 계정 · 라이선스 · 인증 감사 탭. 조회자는 계정 · 인증 감사 숨김. 정책 화면에서 서버 설정 · 계정 탭 삭제. 알림 센터 · 통합 검색도 새 경로
   3 라이선스 칩: 30일 이하 노랑 · 만료 빨강(?license=soon · ?license=expired)
   4 목록 오류: 「다시 시도」 + 30초마다 조용히 한 번 재시도(?retry=ms 로 줄여 확인, ?fail=이름:횟수)
   5 1100px 이하에서 펼친 사이드바는 그 화면 동안만(넓은 화면 접기 상태만 localStorage)
   6 증거: 감사 상세 「증거」 탭 + 설치 시트 · 토폴로지 판정 카드의 「증거 보기」 링크
   7 판정 대화상자의 「함께 일어나는 일」 = POST /api/cases/{id}/preview {decision} → {changes, effects:[{kind,text}]} (모의 서버). 적용 · 버림 · 해제의 {reason}
   8 정책 삭제 · 전체 교체 확인 대화상자(유지) · 기본 규칙 「미리보기 후 추가」는 빈 값만 채움(유지)
   9 비밀번호 최소 5자(「비밀번호는 5자 이상이어야 합니다」), 아이디와 같으면 안 됨은 그대로
   실행: (mock/ 에서) python3 -m http.server 8768 → BASE=http://127.0.0.1:8768/index.html PLAYWRIGHT=<playwright 경로> node tests/feedback-1020c.cjs   (VERBOSE=1 · ONLY · SHOTS=1) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const { splitHash, goState } = require('./nav-state.cjs'); // 10/21b: 필터는 주소 대신 상태로
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
    const pg = await br.newPage({ viewport });
    pages.push(pg);
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const closeAll = async () => { while (pages.length) { const p = pages.pop(); if (!p.isClosed()) await p.close(); } };
  const raw = async (pg, qs = '', hash = '/') => { await pg.goto(`${BASE}?source=sim${qs}#${hash}`); await pg.waitForSelector('[data-part="auth"], .page-title', W); await pg.waitForTimeout(250); };
  const go = async (pg, hash, qs = '', as = 'admin') => { await pg.goto(`${BASE}?source=sim&as=${as}${qs}#${splitHash(hash)[0]}`); await pg.waitForSelector('.page-title', W); if (splitHash(hash)[1]) await goState(pg, hash, 0); await pg.waitForTimeout(400); }; // 10/21b
  const nav = async (pg, hash) => goState(pg, hash); // 10/21b: 화면 안 링크처럼(필터는 상태로)
  const shot = async (pg, n) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `w17-${n}.png`) }); };
  const confirmOk = async (pg, reason) => { await pg.waitForSelector('dialog[data-part="confirm"][open]', W); if (reason) await pg.fill('dialog[data-part="confirm"] textarea[name="reason"]', reason); await pg.click('dialog[data-part="confirm"] [data-confirm="ok"]'); await pg.waitForTimeout(350); };
  const runMalicious = async (pg) => {
    const id = await pg.evaluate(() => UI.runInstallDemo('malicious'));
    await pg.waitForFunction((id) => { const s = UI.state.installs.find((x) => x.id === id); return s && s.finishedAt; }, id, { timeout: 8000 });
    await pg.waitForTimeout(300);
    return pg.evaluate((id) => { const s = UI.state.installs.find((x) => x.id === id); return { id: s.id, caseId: s.caseId, container: s.container }; }, id);
  };
  const width = (pg) => pg.$eval('.sidebar', (e) => Math.round(e.getBoundingClientRect().width));
  const overflow = (pg) => pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'); return [d.scrollWidth - innerWidth, d.scrollHeight - innerHeight, m ? m.scrollWidth - m.clientWidth : 0]; });
  const ED = '[data-view="rule-editor"]';

  // ───────────── 1. 관리자 토큰 칸 삭제 ─────────────
  await T('1 정책 머리에 관리자 토큰 칸 없음 — 관리자는 토큰 없이 저장, 조회자는 쓰기 버튼 없음', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=sensitive-files');
    ok(await pg.locator('input[aria-label="관리자 토큰"]').count() === 0, '토큰 칸이 남음');
    ok(await pg.locator('.topbar input[type="password"]').count() === 0, '머리에 비밀번호 입력');
    await pg.waitForSelector(ED, W);
    await pg.check(`${ED} [data-step="action"] input[value="alert"]`);
    await pg.click(`${ED} button[aria-label="저장 전 확인"]`);
    await pg.waitForSelector(`${ED} [data-part="save-check"] [data-preview-count]`, W);
    const save = pg.locator(`${ED} [data-part="save-check"] button[aria-label="저장 후 적용"]`);
    ok(!(await save.isDisabled()), '저장 버튼이 꺼져 있음');
    ok(!(await pg.textContent(`${ED} [data-part="save-check"]`)).includes('토큰'), '토큰 안내가 남음');
    await save.click(); await pg.waitForTimeout(400);
    ok(await pg.evaluate(() => UI.state.rules.find((r) => r.id === 'sensitive-files').action) === 'alert', '저장 안 됨');
    await pg.close();
    const p2 = await newPage();
    await go(p2, '/policies?id=sensitive-files', '', 'viewer');
    ok(await p2.locator('input[aria-label="관리자 토큰"]').count() === 0, '조회자에게 토큰 칸');
    ok(await p2.locator('button[aria-label="저장 전 확인"], #page button:has-text("새 정책")').count() === 0, '조회자에게 쓰기 버튼');
    await p2.close();
  });

  // ───────────── 2. 설정 화면 ─────────────
  await T('2a 사이드바 「설정 · 기록」 묶음 끝에 설정(#/settings) — 탭 4개: 서버 설정 · 계정 · 라이선스 · 인증 감사', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const order = await pg.$$eval('.nav-link', (els) => els.map((e) => e.dataset.to));
    ok(JSON.stringify(order.slice(-3)) === JSON.stringify(['/policies', '/audit', '/settings']), `순서 ${JSON.stringify(order)}`);
    await pg.click('.nav-link[data-to="/settings"]'); await pg.waitForTimeout(400);
    ok((await pg.textContent('.page-title')).trim() === '설정', `제목 ${await pg.textContent('.page-title')}`);
    const tabs = await pg.$$eval('[data-settings-tab]', (els) => els.map((e) => e.dataset.settingsTab));
    ok(JSON.stringify(tabs) === JSON.stringify(['server', 'accounts', 'license', 'auth-audit']), `탭 ${JSON.stringify(tabs)}`);
    // 서버 설정: 정책 화면에 있던 보기 + 알림 · 발견 방식 · 도메인 판단, 입력칸 없음(테스트 발송 버튼만)
    for (const k of ['enforce', 'watch', 'ignore', 'discovery', 'dns', 'notify']) ok(await pg.locator(`#page [data-part="server-settings"] [data-ss="${k}"]`).count() === 1, `서버 설정 ${k} 줄 없음`);
    ok(await pg.locator('#page [data-part="server-settings"] input, #page [data-part="server-settings"] select').count() === 0, '서버 설정에 입력칸');
    await shot(pg, 'settings-server');
    await pg.click('[data-settings-tab="accounts"]'); await pg.waitForTimeout(300);
    await pg.waitForSelector('#page [data-table="users"] tr[data-user="admin"]', W);
    ok(pg.url().includes('tab=accounts'), `주소 ${pg.url()}`);
    await shot(pg, 'settings-accounts');
    await pg.click('[data-settings-tab="license"]'); await pg.waitForTimeout(300);
    const lic = await pg.textContent('#page [data-part="license"]');
    ok(lic.includes('****-****-****') && /\d+일 남음/.test(lic) && lic.includes('만료'), `라이선스 ${lic.slice(0, 160)}`);
    await shot(pg, 'settings-license');
    await pg.click('[data-settings-tab="auth-audit"]'); await pg.waitForTimeout(300);
    await pg.waitForSelector('#page [data-table="auth-audit"] tbody tr', W);
    const n = await pg.locator('#page [data-table="auth-audit"] tbody tr').count();
    ok(n >= 6, `인증 감사 행 ${n}`);
    const t = await pg.textContent('#page [data-table="auth-audit"]');
    ok(t.includes('로그인') && t.includes('실패'), '인증 감사 내용'); // 10/21: 서버 이름 — 로그인 실패 = action login + 결과 「실패」 칸
    await shot(pg, 'settings-auth-audit');
    await pg.close();
  });

  await T('2b 정책 화면에서 서버 설정 · 계정 탭이 없어지고, 옛 주소(?tab=accounts · ?settings=1)는 설정으로', async () => {
    const pg = await newPage();
    await go(pg, '/policies');
    ok(await pg.locator('[data-server-settings]').count() === 0, '정책 머리에 서버 설정 버튼');
    ok(await pg.locator('[data-pol-tab]').count() === 0, '정책 화면에 탭');
    await nav(pg, '#/policies?tab=accounts');
    ok((await pg.evaluate(() => location.hash)).startsWith('#/settings?tab=accounts'), `옛 계정 주소 ${await pg.evaluate(() => location.hash)}`);
    await nav(pg, '#/policies?settings=1');
    ok((await pg.evaluate(() => location.hash)).startsWith('#/settings'), `옛 서버 설정 주소 ${await pg.evaluate(() => location.hash)}`);
    await pg.close();
  });

  await T('2c 조회자 — 설정 탭은 서버 설정 · 라이선스만, 계정 · 인증 감사 주소로 와도 서버 설정', async () => {
    const pg = await newPage();
    await go(pg, '/settings?tab=accounts', '', 'viewer');
    const tabs = await pg.$$eval('[data-settings-tab]', (els) => els.map((e) => e.dataset.settingsTab));
    ok(JSON.stringify(tabs) === JSON.stringify(['server', 'license']), `탭 ${JSON.stringify(tabs)}`);
    ok(await pg.locator('#page [data-table="users"]').count() === 0, '조회자에게 계정 표');
    ok(await pg.locator('#page [data-part="server-settings"]').count() === 1, '서버 설정이 안 보임');
    ok(await pg.locator('[data-action="notify-test"]').count() === 0, '조회자에게 테스트 발송');
    await nav(pg, '#/settings?tab=auth-audit');
    ok(await pg.locator('#page [data-table="auth-audit"]').count() === 0, '조회자에게 인증 감사');
    await pg.close();
  });

  await T('2d 알림 센터(도메인 판단 꺼짐 · dry-run · 웹훅 실패) · 통합 검색(설정 항목)이 #/settings 로', async () => {
    const pg = await newPage();
    await go(pg, '/events', '&dns=off&notify=fail');
    await pg.click('[data-part="bell"]');
    await pg.waitForSelector('[data-part="notices"]:not([hidden])', W);
    await pg.click('[data-part="notices"] [data-notice="webhook"]'); await pg.waitForTimeout(400);
    ok((await pg.evaluate(() => location.hash)).startsWith('#/settings'), `알림 이동 ${await pg.evaluate(() => location.hash)}`);
    ok(await pg.locator('#page [data-ss="notify"]').count() === 1, '알림 줄이 안 보임');
    await pg.click('[data-part="bell"]');
    await pg.click('[data-part="notices"] [data-notice="dns"]'); await pg.waitForTimeout(400);
    ok((await pg.evaluate(() => location.hash)).startsWith('#/settings'), `dns 알림 이동 ${await pg.evaluate(() => location.hash)}`);
    await pg.keyboard.press('/');
    await pg.keyboard.type('계정'); await pg.waitForTimeout(250);
    const r = await pg.$$eval('[data-part="search-results"] [data-result]', (els) => els.map((e) => [e.dataset.type, e.getAttribute('href')]));
    ok(r.some(([t, href]) => t === 'setting' && href === '#/settings?tab=accounts'), `검색 ${JSON.stringify(r)}`);
    await pg.fill('[data-part="search"] input', 'ENFORCE_KILL'); await pg.waitForTimeout(250);
    const r2 = await pg.$$eval('[data-part="search-results"] [data-result]', (els) => els.map((e) => [e.dataset.type, e.getAttribute('href')]));
    ok(r2.some(([t, href]) => t === 'setting' && href.startsWith('#/settings')), `검색 ${JSON.stringify(r2)}`);
    await pg.close();
  });

  // ───────────── 3. 라이선스 칩 ─────────────
  await T('3 라이선스 칩 — 30일 넘으면 기본, 30일 이하 노랑(?license=soon), 만료 빨강(?license=expired)', async () => {
    const chip = async (qs) => { const pg = await newPage(); await go(pg, '/', qs); const r = await pg.$eval('[data-part="license-chip"]', (e) => [e.textContent, e.className]); return [pg, r]; };
    const [p1, [t1, c1]] = await chip('');
    ok(/\d+일 남음/.test(t1) && !/\bwarn\b|\bdanger\b/.test(c1), `기본 ${t1} · ${c1}`);
    await p1.close();
    const [p2, [t2, c2]] = await chip('&license=soon');
    const d = Number((t2.match(/(\d+)일 남음/) || [])[1]);
    ok(d > 14 && d <= 30 && /\bwarn\b/.test(c2) && !/\bdanger\b/.test(c2), `30일 이하 ${t2} · ${c2}`);
    await shot(p2, 'license-soon');
    await nav(p2, '#/settings?tab=license');
    ok(await p2.locator('#page [data-part="license"] .lic-chip.warn').count() === 1, '설정 › 라이선스에 같은 노랑 칩 없음');
    await p2.close();
    const [p3, [t3, c3]] = await chip('&license=expired');
    ok(t3.includes('만료') && /\bdanger\b/.test(c3), `만료 ${t3} · ${c3}`);
    await shot(p3, 'license-expired');
    await p3.close();
  });

  // ───────────── 4. 목록 오류 · 자동 재시도 ─────────────
  await T('4a 목록 오류 — 「다시 시도」 + 「30초마다 자동으로 다시 시도」 안내', async () => {
    for (const [hash, k] of [['/audit', 'audit'], ['/installs', 'installs'], ['/scans', 'scans'], ['/events', 'events']]) {
      const pg = await newPage();
      await go(pg, hash, `&fail=${k}`);
      await pg.waitForSelector('#page [data-part="error"]', W);
      ok(await pg.locator('#page [data-part="error"] [data-action="retry"]').count() === 1, `${hash} 다시 시도 버튼 없음`);
      const t = await pg.textContent('#page [data-part="error"]');
      ok(t.includes('30초마다'), `${hash} 자동 재시도 안내 「${t}」`);
      await pg.close();
    }
  });

  await T('4b 오류가 이어지면 주기마다 조용히(스켈레톤 없이) 다시 불러, 성공하면 목록 — ?retry=1000&fail=이름:2', async () => {
    // 10/21b: 필터는 주소 대신 화면에서 건다 — 상태로 넘기면 다시 그리며 한 번 더 불러 fail 횟수를 쓰므로, 성공한 뒤 칩 · 토글로 목록을 넓힌다
    const widen = { installs: '[data-filter="status"] button[data-value="all"]', events: '#page [data-toggle="normal"] input' };
    for (const [hash, k, rowSel] of [['/audit', 'audit', '[data-table="audit"] tbody tr'], ['/installs', 'installs', '[data-table="installs"] tbody tr'], ['/events', 'events', '.feed-row']]) {
      const pg = await newPage();
      await go(pg, hash, `&fail=${k}:2&retry=1000`);
      await pg.waitForSelector('#page [data-part="error"]', W);
      await pg.evaluate(() => { window.__sk = 0; new MutationObserver(() => { if (document.querySelector('#page [data-part="skeleton"]')) window.__sk++; }).observe(document.getElementById('page'), { childList: true, subtree: true }); });
      await pg.waitForTimeout(1300);
      ok(await pg.locator('#page [data-part="error"]').count() === 1, `${hash} 두 번째 실패인데 오류가 사라짐`);
      await pg.waitForFunction(() => !document.querySelector('#page [data-part="error"]'), null, { timeout: 4000 }).catch(() => {});
      await pg.waitForTimeout(200);
      ok(await pg.locator('#page [data-part="error"]').count() === 0, `${hash} 자동 재시도 뒤에도 오류`);
      if (widen[k]) { await pg.click(widen[k]); await pg.waitForTimeout(300); }
      ok(await pg.locator(`#page ${rowSel}`).count() >= 1, `${hash} 목록이 비어 있음`);
      ok(await pg.evaluate(() => window.__sk) === 0, `${hash} 자동 재시도에 스켈레톤이 보임`);
      await pg.close();
    }
  });

  // ───────────── 5. 좁은 화면 사이드바 ─────────────
  await T('5 1100px 이하: 펼친 사이드바는 그 화면 동안만 — 화면을 옮기면 다시 접힘, 기억하지 않음 / 넓은 화면은 접기 상태를 기억', async () => {
    const pg = await newPage({ width: 1060, height: 800 });
    await go(pg, '/');
    ok(await width(pg) === 56, `처음 ${await width(pg)}`);
    await pg.click('[data-action="collapse"]'); await pg.waitForTimeout(300);
    ok(await width(pg) > 56, `펼치기 ${await width(pg)}`);
    await pg.click('.nav-link[data-to="/events"]'); await pg.waitForTimeout(500);
    ok(await width(pg) === 56, `화면을 옮겼는데 펼쳐져 있음 ${await width(pg)}`);
    ok(await pg.evaluate(() => localStorage.getItem('supplyguard.sidebar')) === null, '좁은 화면 펼침을 기억함');
    await pg.close();
    const p2 = await newPage();
    await go(p2, '/');
    await p2.click('[data-action="collapse"]'); await p2.waitForTimeout(300);
    ok(await p2.evaluate(() => localStorage.getItem('supplyguard.sidebar')) === '"collapsed"', '넓은 화면 접기를 기억하지 않음');
    await nav(p2, '#/events');
    ok(await width(p2) === 56, '넓은 화면 접기가 화면 이동으로 풀림');
    await p2.click('[data-action="collapse"]');
    await p2.close();
  });

  // ───────────── 6. 증거 링크 ─────────────
  await T('6a 설치 시트(격리) 「증거 보기」 → 감사 상세 증거 탭', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runMalicious(pg);
    await nav(pg, `#/installs?status=all&id=${s.id}`);
    await pg.waitForSelector('.sheet[data-sheet="install"] [data-action="evidence"][href]', W);
    const href = await pg.getAttribute('.sheet[data-sheet="install"] [data-action="evidence"]', 'href');
    ok(href.startsWith('#/audit?') && href.includes('tab=evidence') && href.includes('id='), `링크 ${href}`);
    await shot(pg, 'evidence-link-install');
    await pg.click('.sheet[data-sheet="install"] [data-action="evidence"]'); await pg.waitForTimeout(600);
    await pg.waitForSelector('.sheet[data-sheet="audit"] [data-part="evidence"] [data-part="evidence-logs"]', W);
    ok(await pg.$eval('.sheet[data-sheet="audit"] [data-tab="evidence"]', (e) => e.getAttribute('aria-selected')) === 'true', '증거 탭이 선택되지 않음');
    // 통과한 설치에는 링크 없음
    const passed = await pg.evaluate(() => UI.state.installs.find((x) => window.MOCK.statusOf(x) === 'passed').id);
    await nav(pg, `#/installs?status=all&id=${passed}`);
    await pg.waitForTimeout(300);
    ok(await pg.locator('.sheet[data-sheet="install"] [data-action="evidence"]').count() === 0, '통과한 설치에 증거 링크');
    await pg.close();
  });

  await T('6b 토폴로지 판정 카드(격리된 런타임 컨테이너) 「증거 보기」 → 감사 상세 증거 탭', async () => {
    const pg = await newPage();
    await go(pg, '/topology');
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(500);
    const name = await pg.evaluate(() => UI.state.cases.find((c) => c.source === 'runtime' && c.state === 'open').container);
    await nav(pg, `#/topology?container=${encodeURIComponent(name)}`);
    await pg.waitForTimeout(800);
    await pg.waitForSelector('.case-card [data-action="evidence"][href]', { timeout: 6000 });
    await shot(pg, 'evidence-link-topology');
    await pg.click('.case-card [data-action="evidence"]'); await pg.waitForTimeout(600);
    await pg.waitForSelector('.sheet[data-sheet="audit"] [data-part="evidence"] [data-part="evidence-logs"]', W);
    ok((await pg.textContent('.sheet[data-sheet="audit"]')).includes(name) || (await pg.textContent('[data-part="evidence"]')).length > 10, '다른 컨테이너의 증거');
    await pg.close();
  });

  // ───────────── 7. 판정 미리보기 API ─────────────
  await T('7a 판정 대화상자의 「함께 일어나는 일」은 모의 서버 POST /api/cases/{id}/preview {decision} → {changes, effects:[{kind,text}]}', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runMalicious(pg);
    const before = await pg.evaluate(() => [UI.state.proposals.length, JSON.stringify(UI.state.blocklist)]);
    const pv = await pg.evaluate(async (cid) => UI.api.casePreview(cid, { decision: 'malicious' }), s.caseId);
    ok(Array.isArray(pv.changes) && pv.changes.some((c) => c.op === 'block' && c.value === 'pip:reqeusts'), `changes ${JSON.stringify(pv.changes)}`);
    ok(Array.isArray(pv.effects) && pv.effects.length && pv.effects.every((e) => typeof e.kind === 'string' && typeof e.text === 'string'), `effects ${JSON.stringify(pv.effects)}`);
    const fp = await pg.evaluate(async (cid) => UI.api.casePreview(cid, { decision: 'false_positive' }), s.caseId);
    ok(fp.changes.every((c) => c.op === 'except'), `오탐 changes ${JSON.stringify(fp.changes)}`);
    const bad = await pg.evaluate(async (cid) => UI.api.casePreview(cid, { decision: 'nope' }).then(() => 'ok', (e) => e.status), s.caseId);
    ok(bad === 400, `잘못된 decision ${bad}`);
    const after = await pg.evaluate(() => [UI.state.proposals.length, JSON.stringify(UI.state.blocklist)]);
    ok(JSON.stringify(before) === JSON.stringify(after), '미리보기가 서버 상태를 바꿈');
    ok(await pg.evaluate(() => typeof UI.api.impactDecide) === 'undefined', '화면 쪽 계산(impactDecide)이 남음');
    await nav(pg, `#/installs?id=${s.id}`);
    await pg.click('.sheet [data-part="decision"] button[aria-label="악성 확정"]');
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    await pg.waitForFunction(() => !document.querySelector('[data-part="confirm-effects"]').textContent.includes('계산 중'), null, W);
    const shown = await pg.$$eval('[data-part="confirm-effects"] li', (els) => els.map((e) => e.textContent));
    ok(JSON.stringify(shown) === JSON.stringify(pv.effects.map((e) => e.text)), `대화상자 ${JSON.stringify(shown)} ≠ API ${JSON.stringify(pv.effects.map((e) => e.text))}`);
    const kinds = await pg.$$eval('[data-part="confirm-effects"] li', (els) => els.map((e) => e.dataset.kind || ''));
    ok(kinds.every(Boolean), `종류 표시 없음 ${JSON.stringify(kinds)}`);
    await pg.keyboard.press('Escape');
    await pg.close();
  });

  await T('7b 적용 · 버림 · 차단 해제의 사유는 본문 {reason} → 변경 이력 reason · 판정 · 변경 이력 표에 「사유」', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runMalicious(pg);
    const pid = await pg.evaluate(async (cid) => (await UI.api.decide(cid, { decision: 'malicious', note: '' })).proposal.id, s.caseId);
    await nav(pg, `#/policies?proposal=${pid}`);
    await pg.click('[data-view="proposal"] button[aria-label="적용"]');
    await confirmOk(pg, '적용 사유');
    ok(await pg.evaluate(() => UI.state.changes[0].kind === 'proposal_applied' && UI.state.changes[0].reason === '적용 사유'), '적용 reason');
    await pg.click('[data-section="blocklist"] [data-value="pip:reqeusts"] button');
    await confirmOk(pg, '해제 사유');
    ok(await pg.evaluate(() => UI.state.changes[0].kind === 'blocklist_remove' && UI.state.changes[0].reason === '해제 사유'), '해제 reason');
    const s2 = await runMalicious(pg);
    const pid2 = await pg.evaluate(async (cid) => (await UI.api.decide(cid, { decision: 'malicious', note: '' })).proposal.id, s2.caseId);
    await nav(pg, `#/policies?proposal=${pid2}`);
    await pg.click('[data-view="proposal"] button[aria-label="버림"]');
    await confirmOk(pg, '버림 사유');
    await nav(pg, '#/audit?view=changes'); // 10/21b
    await pg.waitForSelector('[data-table="history"]', W);
    const t = await pg.textContent('[data-table="history"]');
    for (const r of ['적용 사유', '해제 사유', '버림 사유']) ok(t.includes(`사유 「${r}」`), `이력에 ${r} 없음`);
    await pg.close();
  });

  // ───────────── 8. 정책 삭제 · 전체 교체 · 기본 규칙 ─────────────
  await T('8a 정책 삭제 · 전체 교체 — 확인 대화상자(취소하면 그대로)', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=pipe-to-shell');
    await pg.waitForSelector(ED, W);
    await pg.click(`${ED} button:has-text("삭제")`);
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    ok((await pg.textContent('[data-part="confirm-target"]')).includes('pipe-to-shell'), '삭제 대상');
    await pg.click('dialog[data-part="confirm"] [data-confirm="cancel"]'); await pg.waitForTimeout(250);
    ok(await pg.evaluate(() => UI.state.rules.some((r) => r.id === 'pipe-to-shell')), '취소했는데 지워짐');
    await pg.click(`${ED} button:has-text("삭제")`);
    await confirmOk(pg);
    ok(await pg.evaluate(() => !UI.state.rules.some((r) => r.id === 'pipe-to-shell')), '삭제 안 됨');
    await nav(pg, '#/policies?id=__yaml__');
    await pg.waitForFunction(() => { const b = [...document.querySelectorAll('#page button')].find((x) => x.textContent.includes('전체 교체')); return b && !b.disabled; }, null, W);
    await pg.click('#page button:has-text("전체 교체")');
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    ok((await pg.$$eval('[data-part="confirm-effects"] li', (els) => els.map((e) => e.textContent))).some((x) => x.includes('지워집니다')), '전체 교체 효과');
    await pg.keyboard.press('Escape');
    await pg.close();
  });

  await T('8b 기본 규칙 「미리보기 후 추가」 — 사용자가 바꾼 값은 그대로, 빈 값(directIp)만 채움', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(async () => { const r = JSON.parse(JSON.stringify(UI.state.rules.find((x) => x.id === 'sandbox-egress'))); r.action = 'alert'; r.allowHosts = [...(r.allowHosts || []), 'mirror.example.test']; await UI.api.saveRule(r); });
    const before = await pg.evaluate(() => JSON.parse(JSON.stringify(UI.state.rules.find((x) => x.id === 'sandbox-egress'))));
    await nav(pg, '#/policies');
    await pg.waitForSelector('[data-part="defaults-banner"]', W);
    await pg.click('[data-action="defaults-toggle"]');
    await pg.click('[data-default="sandbox-egress"] [data-action="default-preview"]');
    await pg.waitForSelector('[data-part="save-check"]', W);
    await pg.click('[data-part="save-check"] button[aria-label="저장 후 적용"]'); await pg.waitForTimeout(500);
    const after = await pg.evaluate(() => UI.state.rules.find((x) => x.id === 'sandbox-egress'));
    ok(after.action === 'alert', `대응을 덮어씀 ${after.action}`);
    ok((after.allowHosts || []).includes('mirror.example.test'), '사용자가 더한 허용 도메인이 사라짐');
    for (const [k, v] of Object.entries(before)) if (Array.isArray(v)) ok(v.every((x) => (after[k] || []).includes(x)), `${k} 값이 사라짐`);
    ok(after.directIp === 'kill', `빈 값 directIp 가 채워지지 않음 ${after.directIp}`);
    await pg.close();
  });

  // ───────────── 9. 비밀번호 5자 ─────────────
  await T('9 비밀번호 최소 5자 — 안내 · 오류 문구 「비밀번호는 5자 이상이어야 합니다」, 아이디와 같으면 거절, 5자는 통과', async () => {
    const pg = await newPage();
    await raw(pg, '&auth=fresh');
    await pg.fill('input[name="username"]', 'admin'); await pg.fill('input[name="password"]', PW); await pg.click('[data-action="login"]'); await pg.waitForTimeout(250);
    await pg.waitForSelector('[data-part="auth"][data-step="password"]', W);
    ok((await pg.textContent('[data-part="auth"]')).includes('5자 이상'), '안내 문구에 5자 없음');
    const err = () => pg.$eval('[data-part="auth-error"]', (e) => (e.hidden ? '' : e.textContent));
    const tryPw = async (next) => { await pg.fill('input[name="current"]', PW); await pg.fill('input[name="next"]', next); await pg.fill('input[name="confirm"]', next); await pg.click('[data-action="password"]'); await pg.waitForTimeout(250); return err(); };
    const e1 = await tryPw('abcd');
    ok(e1 === '비밀번호는 5자 이상이어야 합니다', `4자 문구 「${e1}」`);
    const e2 = await tryPw('admin');
    ok(e2.includes('아이디와'), `아이디와 같음 「${e2}」`);
    // 서버(모의)도 같은 규칙 — 화면 검사를 건너뛰고 바로 불러도 4자는 400
    const srv = await pg.evaluate(() => UI.auth.api.password({ current: 'demo-pass-1234', next: 'abcd' }).then(() => 'ok', (e) => e.message));
    ok(srv === '비밀번호는 5자 이상이어야 합니다', `모의 서버 ${srv}`);
    await tryPw('abcde');
    await pg.waitForSelector('[data-part="auth"][data-step="license"]', W);
    await pg.close();
    const p2 = await newPage();
    await go(p2, '/');
    await p2.click('[data-part="account"]'); await p2.click('[data-menu="password"]');
    await p2.waitForSelector('dialog[data-part="password"][open]', W);
    ok((await p2.textContent('dialog[data-part="password"]')).includes('5자 이상'), '비밀번호 변경 대화상자 안내');
    await p2.keyboard.press('Escape'); await p2.waitForTimeout(200);
    await nav(p2, '#/settings?tab=accounts');
    await p2.waitForSelector('[data-table="users"]', W);
    await p2.click('tr[data-user="viewer"] [data-action="reset-pw"]');
    await confirmOk(p2);
    await p2.waitForSelector('[data-temp-password]', W);
    ok((await p2.textContent('dialog[data-part="temp-password"]')).includes('5자 이상'), '임시 비밀번호 안내에 5자 없음');
    await p2.close();
  });

  // ───────────── 넘침 ─────────────
  await T('Z 설정 4탭 × 1440 · 1280 · 좁은 화면 1060 넘침 0', async () => {
    for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }, { width: 1060, height: 760 }]) {
      const pg = await newPage(vp);
      for (const t of ['server', 'accounts', 'license', 'auth-audit']) {
        await go(pg, `/settings?tab=${t}`, '&notify=fail');
        ok((await overflow(pg)).every((x) => x <= 0), `${vp.width} ${t} 넘침 ${JSON.stringify(await overflow(pg))}`);
      }
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
