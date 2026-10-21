/* 10/20 도우미 회귀 — 우측 하단 플로팅 버튼 하나(🛡 도우미) → 패널 탭 2개(대응 가이드 · AI 도우미) + 도메인 판단 꺼짐 배너
   1 플로팅 버튼은 하나(🛡 도우미, 옛 💬 버튼 없음). 패널 탭 2개 「대응 가이드」 · 「AI 도우미」, Esc 로 닫히고 포커스는 버튼으로
   2 건이 없을 때(?fresh=1): 「처음이세요? 구축 순서」 3단계 — ① sg-install 명령 복사(토스트) ② 정책 확인(정책 화면을 열면 완료) ③ 런타임 컨테이너(데이터로 완료). 「그만 보기」 → 숨김(새로고침 뒤에도)
   3 악성 설치가 격리되면 패널이 대응 가이드 탭으로 자동 열리고 그 건이 선택된다. 1 탐지(규칙 · 시각) · 2 격리 확인(격리됨) 자동 완료, 진행 2/5, 버튼 배지 1
   4 3 공격 체인 링크를 누르면 완료 + 그 건의 시트로 이동. 4 판정(악성 확정) 뒤 완료. 5 후속 조치 체크 → 5/5 · 배지 0, 새로고침 뒤에도 유지(localStorage supplyguard.guide.<caseId>)
   5 dry-run(격리 모드 끔)이면 2 격리 확인에 「격리 대상」 — 컨테이너는 살아 있음
   6 후속 조치 문구는 규칙별: sandbox-secrets → 키 · 토큰 교체, sandbox-egress → 차단 목록. 공통 「웹훅 알림 발송됨」(sim 모의 값 state.server.notify)
   7 건이 여러 개면 상단 드롭다운(최근 5건) — 고르면 그 건의 가이드
   8 AI 도우미 탭: 기존 대화(질문 → 답 · 관련 화면 링크)가 그대로 동작
   9 토스트는 본문 왼쪽 아래(플로팅 버튼 · 시트와 겹치지 않음)
   10 ?dns=off 이면 상단에 「도메인 판단 꺼짐」 경고 배너(trace_dns 안내). 닫으면 세션 동안 숨김(새로고침 뒤에도). dns 옵션이 없으면 배너 없음
   11 대시보드 밖에서는 자동으로 열지 않는다(패널이 시트 판정 칸을 가림 — 실측) — 배지 + 토스트 「가이드 열기」, 화면을 옮기면 패널은 닫힌다
   12 패널을 연 채 1440 · 1280 넘침 0 · 콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8766 → PLAYWRIGHT=<playwright 경로> node tests/guide-1020.cjs   (VERBOSE=1 · ONLY · SHOTS=1) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
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
  const go = async (pg, hash, qs = '') => { await pg.goto(`${BASE}?source=sim&as=admin${qs}#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(400); }; // 10/20: 로그인 건너뜀(?as=admin)
  const shot = async (pg, n) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `guide-1020-${n}.png`) }); };
  const FAB = '[data-part="assistant-fab"]', PANEL = '[data-part="assistant"]', G = '[data-part="guide"]';
  const stepDone = (pg, n) => pg.$eval(`${G} [data-step="${n}"]`, (e) => e.dataset.done === 'true');
  const progress = (pg) => pg.$eval(`${G} [data-part="guide-progress"]`, (e) => e.dataset.value);
  const badge = (pg) => pg.$eval(`${FAB} [data-part="assistant-badge"]`, (e) => (e.hidden ? '' : e.textContent.trim()));
  const openPanel = async (pg) => { if (await pg.$eval(PANEL, (e) => e.hidden)) await pg.click(FAB); };
  // 악성 설치를 돌려 격리가 끝날 때까지 기다리고 그 건을 돌려준다
  const runMalicious = async (pg) => {
    const id = await pg.evaluate(() => UI.runInstallDemo('malicious'));
    await pg.waitForFunction((id) => { const s = UI.state.installs.find((x) => x.id === id); return s && s.finishedAt; }, id, { timeout: 8000 });
    await pg.waitForTimeout(300);
    return pg.evaluate((id) => { const c = UI.state.cases.find((x) => x.installId === id); return c && { id: c.id, installId: c.installId, level: c.level, ruleIds: c.ruleIds }; }, id);
  };

  await T('1 플로팅 버튼 하나(🛡 도우미) · 탭 2개 · Esc 닫힘 · 포커스 복귀', async () => {
    const pg = await newPage();
    await go(pg, '/');
    ok(await pg.locator(FAB).count() === 1, '도우미 버튼 없음');
    ok(await pg.locator('.chat-fab, [data-part="chat-fab"]').count() === 0, '옛 💬 버튼이 남아 있음');
    ok((await pg.getAttribute(FAB, 'aria-label') || '').includes('도우미'), '버튼 라벨');
    ok(await pg.$eval(PANEL, (e) => e.hidden), '처음부터 패널이 열려 있음');
    await pg.click(FAB);
    ok(await pg.$eval(PANEL, (e) => !e.hidden), '패널이 안 열림');
    const tabs = await pg.$$eval(`${PANEL} [role="tab"]`, (els) => els.map((e) => [e.dataset.tab, e.textContent.trim()]));
    ok(JSON.stringify(tabs.map((t) => t[0])) === JSON.stringify(['guide', 'chat']), `탭 ${JSON.stringify(tabs)}`);
    ok(tabs[0][1].includes('대응 가이드') && tabs[1][1].includes('AI 도우미'), `탭 이름 ${JSON.stringify(tabs)}`);
    await pg.keyboard.press('Escape');
    ok(await pg.$eval(PANEL, (e) => e.hidden), 'Esc 로 안 닫힘');
    ok(await pg.evaluate(() => document.activeElement && document.activeElement.matches('[data-part="assistant-fab"]')), '포커스가 버튼으로 안 돌아옴');
    await pg.close();
  });

  await T('2 건이 없을 때(?fresh=1): 구축 순서 3단계 · 명령 복사 · 정책 확인 완료 · 그만 보기 유지', async () => {
    const pg = await newPage();
    await go(pg, '/', '&fresh=1');
    await pg.click(FAB);
    const S = `${G} [data-part="setup-steps"]`;
    await pg.waitForSelector(S);
    const steps = await pg.$$eval(`${S} [data-setup]`, (els) => els.map((e) => [e.dataset.setup, e.dataset.done]));
    ok(steps.length === 3, `단계 ${JSON.stringify(steps)}`);
    ok(steps[0][1] === 'false', '설치 검사 단계가 벌써 완료');
    ok(steps[2][1] === 'true', '런타임 컨테이너 단계가 데이터로 완료되지 않음(시뮬에는 컨테이너 3개)');
    await pg.click(`${S} button[aria-label="sg-install 명령 복사"]`);
    await pg.waitForTimeout(200);
    ok((await pg.textContent('.toasts')).includes('sg-install pip'), '명령 복사 토스트');
    await shot(pg, 'setup');
    await go(pg, '/policies', '&fresh=1'); // 해시만 바뀌는 같은 문서 이동 — 패널은 열린 채
    await openPanel(pg);
    ok(await pg.$eval(`${S} [data-setup="policies"]`, (e) => e.dataset.done === 'true'), '정책 화면을 열었는데 ② 미완료');
    await pg.click(`${S} button[aria-label="구축 순서 그만 보기"]`);
    ok(await pg.locator(S).count() === 0, '그만 보기 뒤에도 보임');
    await pg.reload(); await pg.waitForSelector('.page-title'); await pg.waitForTimeout(400);
    await openPanel(pg);
    ok(await pg.locator(S).count() === 0, '새로고침 뒤 다시 보임');
    await pg.close();
  });

  await T('3 악성 설치 격리 → 가이드 탭 자동 열림 · 그 건 선택 · 1 · 2 자동 완료 · 2/5 · 배지 1', async () => {
    const pg = await newPage();
    await go(pg, '/');
    ok(await pg.$eval(PANEL, (e) => e.hidden), '시작부터 열려 있음');
    const c = await runMalicious(pg);
    ok(c && c.level === 'killed', `건 ${JSON.stringify(c)}`);
    ok(await pg.$eval(PANEL, (e) => !e.hidden), '자동으로 안 열림');
    ok(await pg.$eval(`${PANEL} [role="tab"][data-tab="guide"]`, (e) => e.getAttribute('aria-selected') === 'true'), '가이드 탭이 아님');
    ok(await pg.$eval(G, (e) => e.dataset.case) === c.id, '선택된 건이 다름');
    ok(await stepDone(pg, 1) && await stepDone(pg, 2), '1 · 2 자동 완료 아님');
    const t1 = await pg.textContent(`${G} [data-step="1"]`);
    ok(c.ruleIds.every((r) => t1.includes(r)), `1 탐지에 규칙 없음: ${t1}`);
    ok(/\d{2}:\d{2}/.test(t1), '1 탐지에 시각 없음');
    ok((await pg.textContent(`${G} [data-step="2"]`)).includes('격리됨'), '2 격리 확인 문구');
    ok(!(await stepDone(pg, 3)) && !(await stepDone(pg, 4)) && !(await stepDone(pg, 5)), '3 · 4 · 5 가 벌써 완료');
    ok((await progress(pg)) === '2/5', `진행 ${await progress(pg)}`);
    ok((await badge(pg)) === '1', `배지 ${await badge(pg)}`);
    await shot(pg, 'case');
    await pg.close();
  });

  await T('4 3 체인 링크 → 완료 · 이동 / 4 판정 뒤 완료 / 5 체크 → 5/5 · 배지 0 · 새로고침 유지', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const c = await runMalicious(pg);
    await pg.click(`${G} [data-step="3"] a[data-part="chain-link"]`);
    await pg.waitForURL(/#\/installs\?/, { timeout: 5000 });
    await pg.waitForSelector('.sheet[data-sheet="install"]');
    ok(await pg.$eval(PANEL, (e) => e.hidden), '링크로 이동했는데 패널이 열린 채(시트의 판정 버튼을 가린다)');
    await openPanel(pg);
    ok(await stepDone(pg, 3), '3 공격 체인 미완료');
    await pg.keyboard.press('Escape');
    await pg.click('.sheet button[aria-label="악성 확정"]');
    await pg.click('dialog[data-part="confirm"] [data-confirm="ok"]'); // 10/20: 판정은 확인 대화상자(B)
    await openPanel(pg);
    await pg.waitForFunction(() => document.querySelector('[data-part="guide"] [data-step="4"]')?.dataset.done === 'true', null, { timeout: 3000 });
    ok((await pg.textContent(`${G} [data-step="4"]`)).includes('악성'), '4 판정 결과 표시 없음');
    const boxes = pg.locator(`${G} [data-step="5"] input[type="checkbox"]`);
    const n = await boxes.count(); ok(n >= 2, `후속 조치 ${n}개`);
    for (let i = 0; i < n; i++) await boxes.nth(i).check();
    ok(await stepDone(pg, 5), '5 후속 조치 미완료');
    ok((await progress(pg)) === '5/5', `진행 ${await progress(pg)}`);
    ok((await badge(pg)) === '', `배지 ${await badge(pg)}`);
    const saved = await pg.evaluate((id) => JSON.parse(localStorage.getItem(`supplyguard.guide.${id}`) || 'null'), c.id);
    ok(saved && saved.chain === true && Object.values(saved.follow || {}).filter(Boolean).length === n, `저장값 ${JSON.stringify(saved)}`);
    await pg.reload(); await pg.waitForSelector('.page-title'); await pg.waitForTimeout(400);
    // 새로고침하면 시뮬 건은 사라지지만 저장값은 남는다 — 같은 id 의 건을 다시 만들면 체크가 유지된다
    const again = await pg.evaluate((id) => JSON.parse(localStorage.getItem(`supplyguard.guide.${id}`) || 'null'), c.id);
    ok(again && again.chain === true, '새로고침 뒤 저장값 없음');
    await pg.close();
  });

  await T('5 dry-run 이면 2 격리 확인에 「격리 대상」', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => { UI.state.info.enforceKill = false; UI.emit(); });
    const c = await runMalicious(pg);
    ok(c && c.level === 'held', `건 ${JSON.stringify(c)}`);
    const t = await pg.textContent(`${G} [data-step="2"]`);
    ok(t.includes('격리 대상') && t.includes('dry-run'), `2 격리 확인 문구: ${t}`);
    ok(await stepDone(pg, 2), '2 가 자동 완료되지 않음');
    await pg.close();
  });

  await T('6 후속 조치 문구는 규칙별(sensitive-files 키 교체 · sandbox-egress 차단 목록) + 웹훅 알림 발송됨', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const c = await runMalicious(pg);
    ok(c.ruleIds.includes('sensitive-files') && c.ruleIds.includes('sandbox-egress'), `규칙 ${JSON.stringify(c.ruleIds)}`);
    const items = await pg.$$eval(`${G} [data-step="5"] [data-follow]`, (els) => els.map((e) => [e.dataset.follow, e.textContent]));
    ok(items.some(([r, t]) => r.split(' ').includes('sensitive-files') && /키|토큰/.test(t) && t.includes('교체')), `키 교체 문구 없음 ${JSON.stringify(items)}`);
    ok(items.some(([r, t]) => r.split(' ').includes('sandbox-egress') && t.includes('차단 목록')), `차단 목록 문구 없음 ${JSON.stringify(items)}`);
    ok(items.some(([r, t]) => r.split(' ').includes('no-shell-download') && /출처|고정/.test(t)), `설치 스크립트 출처 문구 없음`);
    const notify = await pg.textContent(`${G} [data-step="5"] [data-part="notify"]`);
    ok(notify.includes('웹훅') && notify.includes('발송됨'), `웹훅 문구: ${notify}`);
    await pg.close();
  });

  await T('7 건이 여러 개면 드롭다운(최근 5건) — 고르면 그 건', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const a = await runMalicious(pg);
    await pg.evaluate(() => UI.runInstallDemo('warn'));
    await pg.waitForFunction((n) => UI.state.cases.length > n, await pg.evaluate(() => UI.state.cases.length), { timeout: 8000 });
    await pg.waitForTimeout(1500);
    const sel = `${G} select[data-part="guide-case"]`;
    const opts = await pg.$$eval(`${sel} option`, (els) => els.map((e) => e.value));
    ok(opts.length >= 3 && opts.length <= 5, `드롭다운 ${JSON.stringify(opts)}`);
    ok(opts[0] !== a.id, '최근 건(경고)이 맨 위가 아님');
    await pg.selectOption(sel, a.id);
    ok(await pg.$eval(G, (e) => e.dataset.case) === a.id, '고른 건으로 안 바뀜');
    ok((await pg.textContent(`${G} [data-step="2"]`)).includes('격리됨'), '고른 건(격리) 내용이 아님');
    await pg.close();
  });

  await T('8 AI 도우미 탭: 질문 → 답 · 관련 화면 링크', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.click(FAB);
    await pg.click(`${PANEL} [role="tab"][data-tab="chat"]`);
    await pg.waitForSelector('[data-part="chat-list"]');
    await pg.fill('.chat-input', '판정 대기 요약해 줘');
    await pg.keyboard.press('Enter');
    await pg.waitForSelector('[data-part="chat-list"] .chat-msg.assistant [data-part="chat-links"] a', { timeout: 8000 });
    const t = await pg.textContent('[data-part="chat-list"] .chat-msg.assistant');
    ok(t.includes('판정 대기'), `답 "${t.slice(0, 40)}"`);
    await pg.close();
  });

  await T('9 토스트는 본문 왼쪽 아래', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.toast('위치 확인'));
    const [r, fab] = await Promise.all([pg.$eval('#toasts', (e) => e.getBoundingClientRect().toJSON()), pg.$eval(FAB, (e) => e.getBoundingClientRect().toJSON())]);
    ok(r.left < 400 && r.right < fab.left, `토스트 ${JSON.stringify(r)} · 버튼 ${JSON.stringify(fab)}`);
    await pg.close();
  });

  await T('10 ?dns=off 배너(trace_dns 안내) · 닫으면 세션 동안 숨김 · 옵션 없으면 없음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    ok(await pg.locator('[data-banner="dns"]:visible').count() === 0, '옵션 없이 배너가 보임');
    await go(pg, '/', '&dns=off');
    const b = pg.locator('[data-banner="dns"]:visible');
    ok(await b.count() === 1, '배너 없음');
    const t = await b.textContent();
    ok(t.includes('trace_dns') && t.includes('도메인'), `배너 문구: ${t}`);
    await shot(pg, 'dns-off');
    await pg.click('[data-banner="dns"] button[aria-label="닫기"]');
    ok(await pg.locator('[data-banner="dns"]:visible').count() === 0, '닫아도 보임');
    await pg.reload(); await pg.waitForSelector('.page-title'); await pg.waitForTimeout(300);
    ok(await pg.locator('[data-banner="dns"]:visible').count() === 0, '새로고침 뒤 다시 보임(세션 동안 숨겨야 함)');
    await pg.close();
  });

  await T('11 대시보드 밖에서는 자동으로 열지 않고 토스트 「가이드 열기」 + 배지 · 화면 이동하면 닫힘', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const c = await runMalicious(pg);
    ok(await pg.$eval(PANEL, (e) => e.hidden), '설치 검사 화면에서 패널이 자동으로 열림(시트 판정 칸을 가린다)');
    ok((await badge(pg)) === '1', `배지 ${await badge(pg)}`);
    const t = await pg.textContent('.toasts');
    ok(t.includes('대응 가이드') && t.includes('pip ./reqeusts'), `토스트: ${t}`);
    await pg.click('.toasts button.toast-action:has-text("가이드 열기")');
    ok(await pg.$eval(PANEL, (e) => !e.hidden), '토스트로 안 열림');
    ok(await pg.$eval(G, (e) => e.dataset.case) === c.id, '그 건이 아님');
    await pg.click('.nav-link[data-to="/events"]');
    await pg.waitForTimeout(300);
    ok(await pg.$eval(PANEL, (e) => e.hidden), '화면을 옮겼는데 패널이 열린 채');
    await pg.close();
  });

  await T('12 패널 연 채 1440 · 1280 넘침 0', async () => {
    for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) {
      const pg = await newPage(vp);
      await go(pg, '/installs');
      await runMalicious(pg);
      await openPanel(pg);
      ok(await pg.$eval(PANEL, (e) => !e.hidden), '패널 안 열림');
      const o = await pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'), p = document.querySelector('[data-part="assistant"]').getBoundingClientRect(); return [d.scrollHeight - innerHeight, d.scrollWidth - innerWidth, m.scrollHeight - m.clientHeight, m.scrollWidth - m.clientWidth, p.bottom - innerHeight, p.right - innerWidth, -p.top]; });
      ok(o.every((x) => x <= 0), `${vp.width} 넘침 ${JSON.stringify(o)}`);
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
