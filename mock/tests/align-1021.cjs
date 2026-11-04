/* 2026-10-21 목업을 React 에 맞춤(W-A) 회귀 — React(frontend/src)가 기준
   1 live 가 실제 백엔드를 부른다: 설치 · 건 · 제안 · 차단 목록 · 변경 이력 · 공급망 검사 — 라우트가 없으면(404 텍스트) 그 영역만 「백엔드 미지원」(버튼 · 자동 재시도 없음)
     → API(기본 http://127.0.0.1:8011) 백엔드가 떠 있을 때만. 없으면 SKIP
   2 재시도(React ListStates · AuditPage · StreamBanners)
     ① 데이터가 있을 때 다시 부르기 실패: 설치 · 공급망은 목록 유지 + 표시 없음, 감사 로그 · 변경 이력은 작은 오류 띠
     ② 「다시 시도」: 오류 칸 유지 + 버튼 잠금 · 회전, 스켈레톤으로 바꾸지 않음
     ③ 제목 「{what}을(를) 불러오지 못했습니다」 · 「30초마다 한 번씩 저절로 다시 불러 봅니다」
     ④ 백엔드 미지원: 제목 「백엔드 미지원」 · 회색 아이콘 · 버튼 없음 · 자동 재시도 없음
     ⑤ 변경 이력 첫 로드 실패: 오류 칸 + 다시 시도 + 자동 재시도
     ⑦ 설정(인증 감사 · 라이선스 · 계정): 다시 시도 · 자동 재시도 없이 일반 오류 안내
     ⑧ 셸: 이벤트 불러오기 실패 붉은 배너 + 「다시 시도」(?fail=events). 이벤트 화면에서 목록 칸이 오류를 보이면 배너는 겹쳐 띄우지 않음
   3 패키지 묶기(ScanPackages.tsx): 키 매니저:이름@버전 · 버전 칸 하나 · 정렬 취약 → 이름 → 버전 · 「차단됨」은 매니저:이름(버전 무관) · 선택 수는 고를 수 있는 것만 · 확인 문구
   4 인증 감사 이름 = 서버(model.AuthAudit): action · actor · target · ok, 쿼리 action · failed=1 · before=<id>. 필터는 주소에 남기지 않는다(화면 상태만, 10/21 결정)
   실행: (mock/ 에서) python3 -m http.server 8767 --bind 127.0.0.1 → BASE=http://127.0.0.1:8767/index.html PLAYWRIGHT=<playwright 경로> [API=http://127.0.0.1:8011] node tests/align-1021.cjs   (VERBOSE=1 · ONLY · SHOTS=1)
   live 백엔드: backend 에서 EVENT_SOURCE=mock BACKEND_PORT=8011 ALLOWED_ORIGINS=http://127.0.0.1:8767 AUTH_OTP_REQUIRED=false AUTH_DEV_MODE=true ADMIN_INITIAL_PASSWORD=<Makefile DEV_ADMIN_PW> go run ./cmd/server */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const { splitHash, goState } = require('./nav-state.cjs'); // 10/21b: 필터는 주소 대신 상태로
const { liveLogin } = require('./live-login.cjs');
const BASE = process.env.BASE || 'http://127.0.0.1:8767/index.html';
const API = process.env.API || 'http://127.0.0.1:8011';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const W = { timeout: 4000 };
const ACTIONS = ['login', 'login_lock', 'logout', 'password_change', 'license_register', 'license_renew', 'otp_enroll', 'otp_verify', 'otp_recovery', 'user_create', 'user_update', 'user_reset_password', 'user_reset_otp'];

(async () => {
  const br = await chromium.launch();
  const pages = [];
  // 콘솔 오류: live 의 「백엔드 미지원」(404)은 브라우저가 네트워크 오류로 찍는다 — 의도한 응답이라 allow 로 거른다
  const newPage = async (allow) => {
    const pg = await br.newPage({ viewport: { width: 1440, height: 900 } });
    pages.push(pg);
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error' && !(allow && allow.test(m.text()))) consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const closeAll = async () => { while (pages.length) { const p = pages.pop(); if (!p.isClosed()) await p.close(); } };
  const go = async (pg, hash, qs = '', as = 'admin') => { await pg.goto(`${BASE}?source=sim&as=${as}${qs}#${splitHash(hash)[0]}`); await pg.waitForSelector('.page-title', W); if (splitHash(hash)[1]) await goState(pg, hash, 0); await pg.waitForTimeout(400); }; // 10/21b
  const nav = async (pg, hash) => goState(pg, hash); // 10/21b: 화면 안 링크처럼(필터는 상태로)
  const shot = async (pg, n) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `a1021-${n}.png`) }); };
  const confirmOk = async (pg, reason) => { await pg.waitForSelector('dialog[data-part="confirm"][open]', W); if (reason) await pg.fill('dialog[data-part="confirm"] textarea[name="reason"]', reason); await pg.click('dialog[data-part="confirm"] [data-confirm="ok"]'); await pg.waitForTimeout(350); };
  const ERR = '#page [data-part="error"]';

  // ───────────── 2. 재시도 ─────────────
  await T('2③ 오류 칸 문구 — 「{what}을(를) 불러오지 못했습니다」 + 「30초마다 한 번씩 저절로 다시 불러 봅니다」(설치 세션 · 감사 로그 · 공급망 검사 · 최근 이벤트)', async () => {
    for (const [hash, k, what] of [['/installs', 'installs', '설치 세션'], ['/audit', 'audit', '감사 로그'], ['/scans', 'scans', '공급망 검사'], ['/events', 'events', '최근 이벤트']]) {
      const pg = await newPage();
      await go(pg, hash, `&fail=${k}`);
      await pg.waitForSelector(ERR, W);
      const t = await pg.textContent(ERR);
      ok(t.includes(`${what}을(를) 불러오지 못했습니다`), `${hash} 제목 「${t}」`);
      ok(t.includes('30초마다 한 번씩 저절로 다시 불러 봅니다'), `${hash} 안내 「${t}」`);
      ok(!t.includes('목록을 불러오지 못했습니다'), `${hash} 옛 제목`);
      await pg.close();
    }
  });

  await T('2② 「다시 시도」 — 오류 칸 유지 + 버튼 잠금 · 회전, 스켈레톤 없음 → 다시 실패하면 새 오류 칸(버튼 풀림) → 성공하면 목록', async () => {
    // 10/21b: 필터는 주소 대신 화면에서 건다 — 상태로 넘기면 다시 그리며 한 번 더 불러 fail 횟수를 쓰므로, 성공한 뒤 칩 · 토글로 목록을 넓힌다
    const widen = { installs: '[data-filter="status"] button[data-value="all"]', events: '#page [data-toggle="normal"] input' };
    for (const [hash, k, rowSel] of [['/installs', 'installs', '[data-table="installs"] tbody tr'], ['/audit', 'audit', '[data-table="audit"] tbody tr'], ['/scans', 'scans', null], ['/events', 'events', '.feed-row']]) {
      const pg = await newPage();
      await go(pg, hash, `&fail=${k}:2&latency=900`);
      await pg.waitForSelector(ERR, { timeout: 5000 });
      await pg.evaluate(() => { window.__sk = 0; new MutationObserver(() => { if (document.querySelector('#page [data-part="skeleton"]')) window.__sk++; }).observe(document.getElementById('page'), { childList: true, subtree: true }); });
      await pg.click(`${ERR} [data-action="retry"]`);
      await pg.waitForTimeout(250);
      ok(await pg.locator(ERR).count() === 1, `${hash} 누른 뒤 오류 칸이 사라짐`);
      const st = await pg.$eval(`${ERR} [data-action="retry"]`, (b) => [b.disabled, b.classList.contains('retrying'), getComputedStyle(b.querySelector('.retry-icon')).animationName]);
      ok(st[0] && st[1] && st[2] === 'spin', `${hash} 버튼 상태 ${JSON.stringify(st)}`);
      await pg.waitForTimeout(1100); // 두 번째 실패
      ok(await pg.locator(ERR).count() === 1, `${hash} 두 번째 실패인데 오류 칸 없음`);
      ok(!(await pg.$eval(`${ERR} [data-action="retry"]`, (b) => b.disabled)), `${hash} 새 오류 칸의 버튼이 잠김`);
      await pg.click(`${ERR} [data-action="retry"]`);
      await pg.waitForFunction(() => !document.querySelector('#page [data-part="error"]'), null, { timeout: 4000 });
      if (widen[k]) { await pg.click(widen[k]); await pg.waitForTimeout(300); }
      if (rowSel) ok(await pg.locator(`#page ${rowSel}`).count() >= 1, `${hash} 목록 없음`);
      ok(await pg.evaluate(() => window.__sk) === 0, `${hash} 다시 시도에 스켈레톤이 보임`);
      await pg.close();
    }
  });

  await T('2① 데이터가 있을 때 다시 부르기 실패 — 설치 · 공급망은 목록 유지 + 표시 없음', async () => {
    const pg = await newPage();
    await go(pg, '/installs?status=all');
    const n0 = await pg.locator('#page [data-table="installs"] tbody tr').count();
    ok(n0 >= 1, '처음 목록 없음');
    await pg.evaluate(() => UI.simFailNext('installs', 3));
    await pg.waitForTimeout(1200); // 스트림 갱신이 다시 부른다 → 실패
    ok(await pg.evaluate(() => !UI.state.__never) && await pg.locator(ERR).count() === 0, '설치: 오류 칸이 보임');
    ok(await pg.locator('#page [data-part="load-error"]').count() === 0, '설치: 오류 띠가 보임(React 는 표시 없음)');
    ok(await pg.locator('#page [data-table="installs"] tbody tr').count() === n0, '설치: 목록이 바뀜');
    await nav(pg, '#/scans');
    await pg.evaluate(async () => { await UI.api.startScan({ kind: 'package', manager: 'pip', name: 'reqeusts' }); });
    await pg.waitForTimeout(1600);
    const s0 = await pg.locator('#page [data-table="scans"] tbody tr').count();
    ok(s0 >= 1, '공급망: 처음 목록 없음');
    await pg.evaluate(() => UI.simFailNext('scans', 3));
    await pg.waitForTimeout(1200);
    ok(await pg.locator(ERR).count() === 0 && await pg.locator('#page [data-part="load-error"]').count() === 0, '공급망: 오류 표시가 보임');
    ok(await pg.locator('#page [data-table="scans"] tbody tr').count() === s0, '공급망: 목록이 바뀜');
    await pg.close();
  });

  await T('2① 감사 로그 · 변경 이력은 목록 유지 + 위에 작은 오류 띠(React LoadError compact)', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    const n0 = await pg.locator('#page [data-table="audit"] tbody tr').count();
    ok(n0 >= 1, '감사 로그 없음');
    await pg.evaluate(() => UI.simFailNext('audit', 1));
    await pg.click('#page button:has-text("새로고침")'); await pg.waitForTimeout(500);
    ok(await pg.locator(ERR).count() === 0, '감사: 오류 칸으로 바뀜');
    const note = await pg.textContent('#page [data-part="load-error"]');
    ok(note.includes('감사 로그 불러오기 실패'), `감사: 띠 「${note}」`);
    ok(await pg.locator('#page [data-table="audit"] tbody tr').count() === n0, '감사: 목록이 바뀜');
    await shot(pg, 'audit-refresh-fail');
    await pg.click('#page button:has-text("새로고침")'); await pg.waitForTimeout(500);
    ok(await pg.locator('#page [data-part="load-error"]').count() === 0, '감사: 성공했는데 띠가 남음');
    // 변경 이력
    await pg.click('[data-view-btn="history"]'); await pg.waitForTimeout(500);
    await pg.waitForSelector('#page [data-table="history"] tbody tr', W);
    const h0 = await pg.locator('#page [data-table="history"] tbody tr').count();
    await pg.evaluate(() => UI.simFailNext('changes', 1));
    await pg.click('#page button:has-text("새로고침")'); await pg.waitForTimeout(500);
    const hn = await pg.textContent('#page [data-part="load-error"]');
    ok(hn.includes('변경 이력 불러오기 실패'), `이력: 띠 「${hn}」`);
    ok(await pg.locator('#page [data-table="history"] tbody tr').count() === h0, '이력: 목록이 바뀜');
    ok(await pg.locator(ERR).count() === 0, '이력: 오류 칸으로 바뀜');
    await pg.close();
  });

  await T('2⑤ 변경 이력 첫 로드 실패 — 오류 칸(「변경 이력을(를) 불러오지 못했습니다」) + 다시 시도 + 자동 재시도(?retry=1000)', async () => {
    const pg = await newPage();
    await go(pg, '/audit?view=changes', '&fail=changes');
    await pg.waitForSelector(ERR, W);
    const t = await pg.textContent(ERR);
    ok(t.includes('변경 이력을(를) 불러오지 못했습니다') && t.includes('30초마다'), `문구 「${t}」`);
    ok(!t.includes('조회 실패'), '옛 한 줄 문구');
    await pg.click(`${ERR} [data-action="retry"]`);
    await pg.waitForSelector('#page [data-table="history"]', W);
    await pg.close();
    const p2 = await newPage();
    await go(p2, '/audit?view=changes', '&fail=changes:2&retry=1000');
    await p2.waitForSelector(ERR, W);
    await p2.waitForSelector('#page [data-table="history"]', { timeout: 5000 });
    ok(await p2.locator(ERR).count() === 0, '자동 재시도 뒤에도 오류');
    await p2.close();
  });

  await T('2④ 백엔드 미지원 — 제목 「백엔드 미지원」 · 회색 아이콘 · 버튼 없음 · 자동 재시도 없음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const r = await pg.evaluate(() => {
      let calls = 0;
      const el = UI.errorState(Object.assign(new Error('백엔드 미지원 — 시험 API(GET /api/x)가 아직 백엔드에 없습니다'), { unsupported: true }), () => { calls++; }, { what: '시험' });
      document.body.append(el);
      return { title: el.querySelector('b').textContent, text: el.textContent, btn: !!el.querySelector('[data-action="retry"]'), auto: !!el.querySelector('[data-part="auto-retry"]'), danger: el.querySelector('.empty-icon').classList.contains('tone-danger'), unsupported: el.dataset.unsupported, calls };
    });
    ok(r.title === '백엔드 미지원' && r.unsupported === 'true', `제목 ${JSON.stringify(r)}`);
    ok(!r.btn && !r.auto && !r.danger, `버튼 · 자동 · 색 ${JSON.stringify(r)}`);
    ok(r.text.includes('시험 API(GET /api/x)가 아직 백엔드에 없습니다'), `안내 ${r.text}`);
    await pg.close();
  });

  await T('2⑦ 설정 — 인증 감사 오류는 다시 시도 · 자동 재시도 없이 일반 오류 안내(?fail=authAudit)', async () => {
    const pg = await newPage();
    await go(pg, '/settings?tab=auth-audit', '&fail=authAudit&retry=800');
    await pg.waitForSelector('#page [data-part="load-error"]', W);
    const t = await pg.textContent('#page [data-part="load-error"]');
    ok(t.includes('인증 감사 불러오기 실패'), `문구 「${t}」`);
    ok(await pg.locator('#page [data-action="retry"]').count() === 0, '다시 시도 버튼이 있음');
    ok(!(await pg.textContent('#page')).includes('30초마다'), '자동 재시도 안내가 있음');
    await pg.waitForTimeout(1200);
    ok(await pg.locator('#page [data-table="auth-audit"] tbody tr').count() === 0 || await pg.locator('#page [data-table="auth-audit"]').isHidden(), '저절로 다시 불러옴');
    await pg.close();
  });

  await T('2⑧ 셸 배너 — 이벤트를 불러오지 못하면 붉은 배너 + 「다시 시도」(?fail=events), 이벤트 화면의 빈 목록 오류와는 겹치지 않음', async () => {
    const pg = await newPage();
    await go(pg, '/', '&fail=events');
    await pg.waitForSelector('[data-banner="load"]:not([hidden])', W);
    const t = await pg.textContent('[data-banner="load"]');
    ok(t.includes('이벤트를 불러오지 못했습니다') && t.includes('실제와 다를 수 있습니다'), `문구 「${t}」`);
    ok(await pg.locator('[data-banner="conn"]:not([hidden])').count() === 0, '끊김 배너와 겹침');
    await shot(pg, 'load-banner');
    await nav(pg, '#/events');
    ok(await pg.locator('[data-banner="load"]:not([hidden])').count() === 0, '이벤트 화면에서 배너가 겹침');
    ok(await pg.locator(ERR).count() === 1, '이벤트 화면 오류 칸 없음');
    await nav(pg, '#/');
    await pg.click('[data-banner="load"] [data-action="retry-load"]'); await pg.waitForTimeout(500);
    ok(await pg.locator('[data-banner="load"]:not([hidden])').count() === 0, '다시 시도 뒤에도 배너');
    ok(await pg.evaluate(() => UI.state.eventsReady && UI.state.verdicts.length > 0), '이벤트가 차지 않음');
    await pg.close();
  });

  // ───────────── 3. 패키지 묶기 ─────────────
  const openRepoScan = async (pg) => {
    await go(pg, '/scans');
    const id = await pg.evaluate(async () => (await UI.api.startScan({ kind: 'repo', url: 'https://github.com/psf/requests' })).id);
    await pg.waitForTimeout(1500);
    await nav(pg, `#/scans?id=${id}`);
    await pg.waitForSelector('.sheet [data-part="packages"] tr[data-pkg]', W);
    return id;
  };
  await T('3 패키지 — 같은 이름 · 다른 버전은 두 줄(키 매니저:이름@버전), 버전 칸 하나, 정렬 취약 → 이름 → 버전, 제목 「같은 패키지 · 버전은 한 줄」', async () => {
    const pg = await newPage();
    await openRepoScan(pg);
    const rows = await pg.$$eval('.sheet [data-part="packages"] tr[data-pkg]', (els) => els.map((e) => [e.dataset.pkg, Number(e.dataset.sources), e.children[2].textContent, Number(e.children[3].textContent)]));
    const keys = rows.map((r) => r[0]);
    ok(keys.includes('pip:urllib3@1.26.5') && keys.includes('pip:urllib3@1.23.0'), `urllib3 두 줄 아님 ${JSON.stringify(keys)}`);
    ok(new Set(keys).size === keys.length, '같은 키가 두 줄');
    const u = rows.find((r) => r[0] === 'pip:urllib3@1.26.5');
    ok(u[1] === 2 && u[2] === '1.26.5', `1.26.5 줄 ${JSON.stringify(u)}`);
    ok(rows.find((r) => r[0] === 'pip:urllib3@1.23.0')[2] === '1.23.0', '버전 칸');
    ok(rows.every((r) => !r[2].includes(',')), '버전 칸에 여러 버전');
    for (let i = 1; i < rows.length; i++) ok(rows[i - 1][3] >= rows[i][3], `취약 수 정렬 ${keys[i - 1]} → ${keys[i]}`);
    ok(keys.indexOf('pip:urllib3@1.23.0') < keys.indexOf('pip:urllib3@1.26.5'), '취약이 많은 1.23.0 이 먼저');
    const head = await pg.textContent('.sheet [data-part="packages"] h3');
    ok(head.includes('같은 패키지 · 버전은 한 줄'), `제목 ${head}`);
    await pg.close();
  });

  await T('3 패키지 — 두 버전을 골라도 차단은 하나(확인 문구 「차단은 버전과 무관」), 적용 뒤 두 줄 모두 「차단됨」, 선택 수는 고를 수 있는 것만', async () => {
    const pg = await newPage();
    const id = await openRepoScan(pg);
    await pg.check('.sheet tr[data-pkg="pip:urllib3@1.26.5"] input[data-pick]');
    await pg.check('.sheet tr[data-pkg="pip:urllib3@1.23.0"] input[data-pick]');
    ok((await pg.textContent('.sheet [data-action="block-selected"]')).includes('선택한 2개'), '버튼 글');
    await pg.click('.sheet [data-action="block-selected"]');
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    const eff = await pg.textContent('dialog[data-part="confirm"]');
    ok(eff.includes('차단은 버전과 무관'), `확인 문구 ${eff.slice(0, 200)}`);
    ok((eff.match(/pip:urllib3/g) || []).length === 1, `같은 패키지가 여러 번 ${eff.slice(0, 200)}`);
    await confirmOk(pg, '정렬 시험');
    await pg.waitForTimeout(400);
    const ch = await pg.$$eval('[data-view="proposal"] [data-change]', (els) => els.map((e) => e.dataset.change));
    ok(ch.filter((x) => x === 'block:packages:pip:urllib3').length === 1 && ch.length === 1, `변경 ${JSON.stringify(ch)}`);
    // 적용 → 다시 열면 urllib3 두 줄 모두 차단됨(버전 무관), 모두 고르기는 나머지만
    await pg.evaluate(async () => { const ps = await UI.api.proposals({ state: 'draft' }); await UI.api.apply(ps[0].id, { reason: '' }); });
    await nav(pg, `#/scans?id=${id}`);
    await pg.waitForSelector('.sheet [data-part="packages"] tr[data-pkg]', W);
    for (const k of ['pip:urllib3@1.26.5', 'pip:urllib3@1.23.0']) {
      ok(await pg.locator(`.sheet tr[data-pkg="${k}"] input[data-pick]`).count() === 0, `${k} 체크 칸이 남음`);
      ok((await pg.textContent(`.sheet tr[data-pkg="${k}"] td:first-child`)).includes('차단됨'), `${k} 차단됨 아님`);
    }
    const pickable = await pg.locator('.sheet [data-part="packages"] input[data-pick]').count();
    await pg.check('.sheet [data-part="packages"] input[aria-label="모두 고르기"]');
    ok((await pg.textContent('.sheet [data-action="block-selected"]')).includes(`선택한 ${pickable}개`), `선택 수 ${await pg.textContent('.sheet [data-action="block-selected"]')} / ${pickable}`);
    await shot(pg, 'packages');
    await pg.close();
  });

  // ───────────── 4. 인증 감사 이름 ─────────────
  await T('4 인증 감사 — 행 = 서버 모양(id 숫자 · actor · action · target · ok · detail), action 은 13개 안, system 은 actor', async () => {
    const pg = await newPage();
    await go(pg, '/settings?tab=auth-audit');
    await pg.waitForSelector('#page [data-table="auth-audit"] tbody tr', W);
    const rows = await pg.evaluate(() => UI.auth.api.authAudit({ limit: 200 }));
    ok(rows.length >= 8, `행 ${rows.length}`);
    const keys = Object.keys(rows[0]).sort().join(',');
    ok(keys === 'action,actor,at,detail,id,ip,ok,target', `키 ${keys}`);
    ok(rows.every((r) => Number.isInteger(r.id) && ACTIONS.includes(r.action)), `action ${[...new Set(rows.map((r) => r.action))]}`);
    ok(rows.some((r) => r.actor === 'system' && r.action === 'user_create'), 'system actor 없음');
    ok(rows.some((r) => r.action === 'login' && !r.ok) && rows.some((r) => r.action === 'login' && r.ok), '로그인 성공 · 실패 = login + ok');
    const head = await pg.$$eval('#page [data-table="auth-audit"] th', (els) => els.map((e) => e.textContent));
    ok(head.join(',') === '시각,계정,동작,대상,IP,결과,내용', `머리(React 와 같은 순서) ${head}`);
    const acts = await pg.$$eval('#page [data-table="auth-audit"] tbody tr', (els) => els.map((e) => e.dataset.authAction));
    ok(acts.every((a) => ACTIONS.includes(a)), `화면 action ${acts}`);
    await pg.close();
  });

  await T('4 인증 감사 — 쿼리 action · failed=1 · before=<id>, 잘못된 값은 400', async () => {
    const pg = await newPage();
    await go(pg, '/settings?tab=auth-audit');
    const r = await pg.evaluate(async () => {
      const A = UI.auth.api;
      const all = await A.authAudit({ limit: 200 });
      const login = await A.authAudit({ action: 'login' });
      const failed = await A.authAudit({ failed: '1' });
      const p1 = await A.authAudit({ limit: 3 });
      const p2 = await A.authAudit({ limit: 3, before: p1[p1.length - 1].id });
      const bad = async (q) => { try { await A.authAudit(q); return 0; } catch (e) { return e.status; } };
      return { all: all.length, login: login.map((x) => x.action), failed: failed.map((x) => x.ok), p1: p1.map((x) => x.id), p2: p2.map((x) => x.id), badAction: await bad({ action: 'login_fail' }), badBefore: await bad({ before: 'auth-0003' }), badFailed: await bad({ failed: 'yes' }) };
    });
    ok(r.login.length >= 3 && r.login.every((a) => a === 'login'), `action ${r.login}`);
    ok(r.failed.length >= 3 && r.failed.every((x) => x === false), `failed ${r.failed}`);
    ok(r.p1.length === 3 && r.p2.length === 3 && Math.max(...r.p2) < Math.min(...r.p1), `before ${r.p1} / ${r.p2}`);
    ok(r.badAction === 400 && r.badBefore === 400 && r.badFailed === 400, `400 ${r.badAction} ${r.badBefore} ${r.badFailed}`);
    await pg.close();
  });

  await T('4 인증 감사 화면 — 고르기 · 실패만 · 칩은 그대로, 필터는 주소를 읽지도 쓰지도 않음(화면 상태만)', async () => {
    const pg = await newPage();
    await go(pg, '/settings?tab=auth-audit&event=login_fail&action=login_lock&failed=1');
    await pg.waitForSelector('#page [data-table="auth-audit"] tbody tr', W);
    ok(await pg.locator('#page .fchip').count() === 0, '주소의 값이 필터로 걸림');
    ok(await pg.$eval('#page select[aria-label="한 일"]', (e) => e.value) === '', '주소의 action 이 고르기에 들어감');
    await go(pg, '/settings?tab=auth-audit');
    await pg.waitForSelector('#page [data-table="auth-audit"] tbody tr', W);
    await pg.selectOption('#page select[aria-label="한 일"]', 'login'); await pg.waitForTimeout(400);
    ok(!/[?&](action|failed|event)=/.test(pg.url()), `주소에 필터 ${pg.url()}`);
    let acts = await pg.$$eval('#page [data-table="auth-audit"] tbody tr', (els) => els.map((e) => e.dataset.authAction));
    ok(acts.length >= 3 && acts.every((a) => a === 'login'), `고르기 ${acts}`);
    await pg.check('#page .filters input[type="checkbox"]'); await pg.waitForTimeout(400);
    ok(!/[?&](action|failed|event)=/.test(pg.url()), `주소에 필터 ${pg.url()}`);
    const oks = await pg.$$eval('#page [data-table="auth-audit"] tbody tr', (els) => els.map((e) => e.dataset.ok));
    ok(oks.length >= 1 && oks.every((x) => x === 'false'), `실패만 ${oks}`);
    const chips = await pg.textContent('#page [data-part="filter-chips"], #page .filter-chips');
    ok(chips.includes('한 일: 로그인') && chips.includes('실패만'), `칩 ${chips}`);
    await pg.click('[data-settings-tab="license"]'); await pg.waitForTimeout(300); await pg.click('[data-settings-tab="auth-audit"]'); await pg.waitForTimeout(400);
    ok(await pg.$eval('#page select[aria-label="한 일"]', (e) => e.value) === '' && await pg.locator('#page .fchip').count() === 0, '탭을 다시 열었는데 필터가 남음');
    await pg.close();
  });

  await T('4 인증 감사 「더 보기」 — 받은 수가 한 번에 읽는 수 이상이면 보이고, 마지막 행 id 를 before 로 붙인다(React 와 같음, ?auditPage=3)', async () => {
    const pg = await newPage();
    await go(pg, '/settings?tab=auth-audit', '&auditPage=3');
    await pg.waitForSelector('#page [data-table="auth-audit"] tbody tr', W);
    const ids = () => pg.$$eval('#page [data-table="auth-audit"] tbody tr', (els) => els.map((e) => Number(e.dataset.auditId)));
    const first = await ids();
    ok(first.length === 3, `첫 쪽 ${first.length}`);
    ok(await pg.locator('#page [data-action="more"]').isVisible(), '더 보기 없음');
    await pg.click('#page [data-action="more"]'); await pg.waitForTimeout(300);
    const after = await ids();
    // before=<마지막 id>: 붙은 행은 앞 쪽의 마지막 id 보다 작은 바로 다음 3건(서버 결과와 같아야 한다)
    const expect = (await pg.evaluate((b) => UI.auth.api.authAudit({ limit: 3, before: b }), first[2])).map((x) => x.id);
    ok(after.length === 6 && after.slice(0, 3).join() === first.join() && after.slice(3).join() === expect.join(), `붙인 행 ${after} / 기대 ${expect}`);
    // 끝까지 넘기면 버튼이 사라진다
    for (let i = 0; i < 20 && await pg.locator('#page [data-action="more"]').count(); i++) { await pg.click('#page [data-action="more"]'); await pg.waitForTimeout(200); }
    const total = (await pg.evaluate(() => UI.auth.api.authAudit({ limit: 200 }))).length;
    ok(await pg.locator('#page [data-action="more"]').count() === 0 && (await ids()).length === total, `끝 ${(await ids()).length}/${total}`);
    // 필터를 바꾸면 처음부터
    await pg.selectOption('#page select[aria-label="한 일"]', 'login'); await pg.waitForTimeout(400);
    const acts = await pg.$$eval('#page [data-table="auth-audit"] tbody tr', (els) => els.map((e) => e.dataset.authAction));
    ok(acts.length <= 3 && acts.every((a) => a === 'login'), `필터 뒤 ${acts}`);
    await pg.close();
  });

  // ───────────── 1. live 가 실제 백엔드를 부른다 ─────────────
  const backendUp = await fetch(`${API}/health`).then((r) => r.ok).catch(() => false);
  if (!backendUp) console.log(`SKIP  1 live — 백엔드(${API})가 떠 있지 않음`);
  else {
    const ALLOW = /status of 404 \(Not Found\)/; // 라우트 없는 API(백엔드 미지원)만 허용
    const livePage = async () => {
      const pg = await newPage(ALLOW);
      await pg.goto(`${BASE}?source=sim&as=admin#/`); await pg.waitForSelector('.page-title', W);
      await liveLogin(pg, API);
      return pg;
    };
    const goLive = async (pg, hash) => { await pg.goto(`${BASE}?source=live&api=${encodeURIComponent(API)}#${splitHash(hash)[0]}`); await pg.waitForSelector('.page-title', { timeout: 8000 }); if (splitHash(hash)[1]) await goState(pg, hash, 0); await pg.waitForTimeout(1200); }; // 10/21b
    const scansStatus = await (async () => { const p = await livePage(); const s = await p.evaluate(async (api) => (await fetch(`${api}/api/scans`, { credentials: 'include' })).status, API); await p.close(); return s; })();

    await T('1 live — 설치 검사 · 대시보드 판정 대기 · 정책 제안 · 차단 목록 · 변경 이력이 실제 API 로 뜬다(「백엔드 미지원」 없음)', async () => {
      const pg = await livePage();
      await goLive(pg, '/installs?status=all');
      const ins = await pg.textContent('#page');
      ok(!ins.includes('백엔드 미지원') && await pg.locator(ERR).count() === 0, `설치 ${ins.slice(0, 160)}`);
      ok(await pg.locator('#page [data-table="installs"]:not([hidden]) tbody tr, #page [data-part="empty"]').count() >= 1, '설치: 목록도 빈 상태도 없음');
      await goLive(pg, '/');
      ok(!(await pg.textContent('[data-section="pending"]')).includes('백엔드 미지원'), '대시보드 판정 대기에 미지원');
      await goLive(pg, '/policies');
      ok(!(await pg.textContent('[data-section="proposals"]')).includes('백엔드 미지원'), '정책 제안에 미지원');
      await goLive(pg, '/policies?id=__blocklist__');
      ok(!(await pg.textContent('#page')).includes('백엔드 미지원'), '차단 목록에 미지원');
      await goLive(pg, '/audit?view=changes');
      ok(await pg.locator('#page [data-table="history"], #page .empty').count() >= 1 && await pg.locator(ERR).count() === 0, '변경 이력이 뜨지 않음');
      await shot(pg, 'live-installs');
      await pg.close();
    });

    await T(`1 live — 공급망 검사: 백엔드 응답 ${scansStatus} 에 맞게(404 텍스트면 「백엔드 미지원」 · 버튼 · 자동 재시도 없음)`, async () => {
      const pg = await livePage();
      await goLive(pg, '/scans');
      if (scansStatus === 404) {
        await pg.waitForSelector(`${ERR}[data-unsupported="true"]`, W);
        const t = await pg.textContent(ERR);
        ok(t.includes('백엔드 미지원') && t.includes('GET /api/scans'), `문구 ${t}`);
        ok(await pg.locator(`${ERR} [data-action="retry"]`).count() === 0 && await pg.locator(`${ERR} [data-part="auto-retry"]`).count() === 0, '버튼 · 자동 재시도가 있음');
        await shot(pg, 'live-scans-unsupported');
      } else ok(!(await pg.textContent('#page')).includes('백엔드 미지원'), '공급망 검사에 미지원');
      await pg.close();
    });

    await T('1 live — 쓰기도 React 와 같은 경로: 판정(decide) → 제안 버림(discard, 사유) → 변경 이력 · 건 상태', async () => {
      const pg = await livePage();
      await goLive(pg, '/');
      // mock 소스는 20초마다 pkg-reqeusts 를 격리 → 런타임 건이 열린다. 없으면 기다린다(최대 25초)
      let open = null;
      for (let i = 0; i < 26 && !open; i++) { open = await pg.evaluate(async () => (await UI.api.cases({ state: 'open' }))[0] || null); if (!open) await pg.waitForTimeout(1000); }
      ok(open, '열린 건이 없음');
      const r = await pg.evaluate(async (id) => {
        const d = await UI.api.decide(id, { decision: 'false_positive', note: '목업 live 회귀' });
        const pid = d.proposal && d.proposal.id;
        const x = await UI.api.discard(pid, { reason: '목업 live 회귀 — 버림' });
        const c = await UI.api.case(id);
        const props = await UI.api.proposals({ state: 'discarded' });
        return { decided: d.case.state, pid, discarded: x.proposal.state, caseState: c.state, by: c.decidedBy, inList: props.some((p) => p.id === pid) };
      }, open.id);
      ok(r.decided === 'decided' && r.pid, `판정 ${JSON.stringify(r)}`);
      ok(r.discarded === 'discarded' && r.caseState === 'closed' && r.inList, `버림 ${JSON.stringify(r)}`);
      ok(r.by && r.by !== 'cli', `처리자 ${r.by}`);
      await pg.close();
    });

    await T('1 live — 인증 감사 행이 서버 이름(actor · action · target · ok)으로 보인다', async () => {
      const pg = await livePage();
      await goLive(pg, '/settings?tab=auth-audit');
      await pg.waitForSelector('#page [data-table="auth-audit"] tbody tr', W);
      const acts = await pg.$$eval('#page [data-table="auth-audit"] tbody tr', (els) => els.map((e) => e.dataset.authAction));
      ok(acts.length >= 1 && acts.every((a) => ACTIONS.includes(a)), `action ${acts}`);
      ok(acts.includes('login'), 'login 없음');
      await pg.close();
    });
  }

  await closeAll();
  await br.close();
  const pass = results.filter((r) => r[0]).length;
  if (!process.env.VERBOSE) for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  for (const e of consoleErrors) console.log(`CONSOLE  ${e}`);
  console.log(`\n${pass}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  process.exit(pass === results.length && !consoleErrors.length ? 0 : 1);
})();
