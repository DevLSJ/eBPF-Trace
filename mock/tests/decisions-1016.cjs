/* 10/15 3차 결정 회귀(10/16 반영) — 목업을 React 모습에 맞춤 + 동작 규칙(백엔드 review 와 같은 규칙)
   화면
   A 대시보드: 판정 대기 전체 폭 + 행마다 걸린 규칙 한 줄, 아래 eBPF 수집 종합(10/16), 사이드바 배지 = 판정 대기
   B 표기: 목록 · 제목 · 토스트는 입력 그대로(「pip ./reqeusts」), 정규화 이름(pip:reqeusts)은 제안 변경 내용 · 차단 목록만
   C 설치 시트: 결과 → 정적 분석 → 공격 체인 → 활동 요약, 판정 칸은 아래 고정 + 메모(건 note 로 저장)
   D 정책: 제안을 열면 미리보기 자동, 왼쪽 제안 → 정책, 오른쪽 아래 차단 목록 · 변경 이력, ?id=__blocklist__ 는 아래 칸 강조
   동작 규칙
   E 악성: 허용 도메인(allowHosts)은 도메인 차단에서 빼고 notes, 여러 패키지 세션은 전부 차단, 미리보기 nextOnly
   F 오탐: 실행 규칙은 자동 예외 없이 notes, 규칙에 원래 allowHosts 가 없으면 allowCidrs IP/32
   G 경고는 열린 런타임 건에 묶임(경고만으로는 새 건 없음), 설치 목록 violationCount
   H 차단 이미지 재기동 = blocked-image 격리, 새 건 없음, 감사 행 caseId = 차단을 만든 건
   I 무결성: 바뀐 화면 × 1440 · 1280 페이지 넘침 0 · 콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8766 → PLAYWRIGHT=<playwright 경로> node tests/decisions-1016.cjs   (VERBOSE=1 · ONLY=정규식 · SHOTS=1) */
const fs = require('fs');
const path = require('path');
const PW = process.env.PLAYWRIGHT || 'playwright';
const { chromium } = require(PW);
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots', '1016');
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
  const go = async (pg, hash) => { await pg.goto(`${BASE}#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(400); };
  const shot = async (pg, name) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `${name}.png`) }); };
  const runInstall = async (pg, kind) => {
    const id = await pg.evaluate((k) => UI.runInstallDemo(typeof k === 'string' ? k : Object.assign({}, MOCK.demoSpecs[k.base], k.patch)), kind);
    await pg.waitForFunction((sid) => UI.state.installs.find((s) => s.id === sid && (s.finishedAt || s.refusedBy)), id, { timeout: 8000 });
    return pg.evaluate(async (sid) => UI.api.install(sid), id);
  };
  const decideApi = (pg, id, decision) => pg.evaluate(async ([cid, d]) => UI.api.decide(cid, { decision: d, note: '' }), [id, decision]);
  const runtimeCase = async (pg) => (await pg.evaluate(async () => UI.api.cases({ source: 'runtime', state: 'open' })))[0];
  const noOverflow = (pg) => pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'); return [d.scrollHeight - innerHeight, d.scrollWidth - innerWidth, m.scrollHeight - m.clientHeight, m.scrollWidth - m.clientWidth]; });

  // ---------------- A. 대시보드 ----------------
  await T('A 대시보드: 판정 대기 전체 폭 + 걸린 규칙 한 줄, 아래 요약 3칸 · 감시 중, 사이드바 배지', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await runInstall(pg, 'malicious');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(600);
    const [pend, main] = await Promise.all([pg.$eval('[data-section="pending"]', (e) => e.getBoundingClientRect().toJSON()), pg.$eval('#page', (e) => e.getBoundingClientRect().toJSON())]);
    ok(pend.width > main.width - 80, `판정 대기 폭 ${pend.width} / 본문 ${main.width}`);
    // 10/16: 아래 요약 3칸 · 감시 중 → 「eBPF 수집 종합」(tests/overview-1016.cjs)
    const ov = await pg.$eval('[data-section="overview"]', (e) => e.getBoundingClientRect().top);
    ok(ov > pend.top + 60, `종합 ${ov} 는 판정 대기 아래여야 함`);
    const keys = await pg.$$eval('[data-section="overview"] [data-kpi]', (els) => els.map((e) => e.dataset.kpi));
    ok(JSON.stringify(keys) === JSON.stringify(['collected', 'violations', 'isolated', 'installs', 'decided']), `종합 칸 ${JSON.stringify(keys)}`);
    const rules = await pg.textContent('[data-case][data-source="install"] [data-rules]');
    ok(rules.includes('pipe-to-shell') && rules.includes('reverse-shell-ports'), `걸린 규칙 "${rules}"`);
    const badge = await pg.textContent('[data-nav-badge]');
    ok(badge === '2' && await pg.locator('[data-nav-badge]').isVisible(), `사이드바 배지 "${badge}"`);
    await shot(pg, '01-dashboard');
    await pg.close();
  });

  // ---------------- B. 표기 ----------------
  await T('B 표기: 대시보드 · 시트 제목 · 토스트 · 제안 목록 · 근거는 「pip ./reqeusts」, 변경 내용 · 차단 목록만 「pip:reqeusts」', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    const c = await pg.evaluate(async (id) => UI.api.case(id), s.caseId);
    ok(c.label === 'pip ./reqeusts' && c.package === 'pip:reqeusts', `건 label/package ${c.label} / ${c.package}`);
    await go(pg, '/');
    const row = await pg.textContent(`[data-case="${s.caseId}"]`);
    ok(row.includes('pip ./reqeusts') && !row.includes('pip:reqeusts'), `대시보드 행 "${row}"`);
    await pg.click(`[data-case="${s.caseId}"]`);
    await pg.waitForSelector('.sheet[data-sheet="install"]');
    ok((await pg.getAttribute('.sheet[data-sheet="install"]', 'aria-label')) === 'pip ./reqeusts', '시트 제목');
    await pg.click('.sheet [data-part="decision"] button[aria-label="악성 확정"]');
    await pg.waitForTimeout(300);
    ok((await pg.textContent('.toasts')).includes('pip ./reqeusts 악성 확정'), '판정 토스트 표기');
    await pg.click('.toast-action:has-text("제안 보기")');
    await pg.waitForSelector('[data-view="proposal"]');
    ok((await pg.textContent('[data-section="proposals"] [data-proposal]')).includes('pip ./reqeusts'), '제안 목록 표기');
    ok((await pg.textContent('[data-view="proposal"] [data-part="basis"]')).includes('pip ./reqeusts'), '근거 표기');
    ok((await pg.textContent('[data-view="proposal"] [data-changes]')).includes('패키지 차단 pip:reqeusts'), '변경 내용은 정규화 이름');
    await pg.click('[data-view="proposal"] button[aria-label="적용"]');
    await pg.waitForTimeout(400);
    ok(await pg.locator('[data-view="blocklist"] [data-list="packages"] [data-value="pip:reqeusts"]').count() === 1, '차단 목록 정규화 이름');
    await pg.close();
  });

  // ---------------- C. 설치 시트 ----------------
  await T('C 설치 시트: 결과 → 정적 분석 → 공격 체인 → 활동 요약, 판정 칸 아래 고정 + 메모 저장', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    await go(pg, `/installs?id=${s.id}`);
    await pg.waitForSelector('.sheet [data-part="osv"] [data-osv-count]');
    const order = await pg.$$eval('.sheet .sheet-body > [data-part], .sheet .sheet-body > .sheet-section', (els) => els.map((e) => e.dataset.part || e.querySelector('h3')?.textContent));
    const idx = (k) => order.findIndex((x) => x && x.startsWith(k));
    ok(idx('result') === 0 && idx('result') < idx('osv') && idx('osv') < idx('공격 체인') && idx('공격 체인') < idx('활동 요약'), `순서 ${JSON.stringify(order)}`);
    ok(await pg.locator('.sheet .sheet-foot [data-part="decision"]').count() === 1, '판정 칸이 아래 고정 칸에 없음');
    const [foot, sheet] = await Promise.all([pg.$eval('.sheet .sheet-foot', (e) => e.getBoundingClientRect().bottom), pg.$eval('.sheet', (e) => e.getBoundingClientRect().bottom)]);
    ok(Math.abs(foot - sheet) < 2, `판정 칸이 시트 아래에 붙지 않음 ${foot} / ${sheet}`);
    await pg.fill('.sheet [data-memo]', '타이포스쿼팅 — 이름이 requests 와 한 글자 다름');
    await shot(pg, '02-install-sheet');
    await pg.click('.sheet [data-part="decision"] button[aria-label="악성 확정"]');
    await pg.waitForTimeout(300);
    const c = await pg.evaluate(async (id) => UI.api.case(id), s.caseId);
    ok(c.note.startsWith('타이포스쿼팅'), `메모 "${c.note}"`);
    await pg.close();
  });

  // ---------------- D. 정책 ----------------
  await T('D 정책: 제안을 열면 미리보기 자동 · 적용 바로 가능, 왼쪽 제안 → 정책, 오른쪽 아래 차단 목록 · 변경 이력', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    await decideApi(pg, s.caseId, 'malicious');
    await go(pg, '/policies');
    await pg.waitForSelector('[data-view="proposal"] [data-part="preview"] [data-preview-count]', { timeout: 3000 }); // 버튼을 누르지 않아도
    ok(await pg.locator('[data-view="proposal"] button[aria-label="적용"]').isEnabled(), '적용 버튼 꺼짐');
    const left = await pg.$$eval('.pol-left > [data-section]', (els) => els.map((e) => e.dataset.section));
    ok(JSON.stringify(left) === JSON.stringify(['proposals', 'rules']), `왼쪽 ${JSON.stringify(left)}`);
    const [ed, bl, ch] = await Promise.all(['[data-view="proposal"]', '[data-section="blocklist"]', '[data-section="changes"]'].map((q) => pg.$eval(q, (e) => e.getBoundingClientRect().toJSON())));
    ok(bl.top > ed.top + 100 && Math.abs(bl.top - ch.top) < 2 && ch.left > bl.left, `아래 칸 위치 편집 ${ed.top} · 차단 ${bl.top}/${bl.left} · 이력 ${ch.top}/${ch.left}`);
    ok(await pg.locator('[data-section="changes"] [data-change-id]').count() >= 1, '변경 이력 칸이 비어 있음(시드 1건 이상)');
    await shot(pg, '03-policy-proposal');
    await go(pg, '/policies?id=__blocklist__');
    await pg.waitForTimeout(200);
    ok(await pg.locator('[data-section="blocklist"].flash').count() === 1, '?id=__blocklist__ 가 차단 목록 칸을 강조하지 않음');
    ok(await pg.locator('[data-view="proposal"], [data-view="rule"], form, .col').count() >= 1, '편집 영역이 비어 있음');
    await pg.close();
  });

  // ---------------- E. 악성 규칙 ----------------
  await T('E 악성: 허용 도메인(github.com)은 도메인 차단에서 빼고 notes 안내', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'warn');
    const { proposal } = await decideApi(pg, s.caseId, 'malicious');
    ok(!proposal.changes.some((c) => c.list === 'hosts' && c.value === 'github.com'), `github.com 이 차단됨 ${JSON.stringify(proposal.changes)}`);
    ok(proposal.notes.some((n) => n.includes('github.com') && n.includes('허용 도메인')), `안내 ${JSON.stringify(proposal.notes)}`);
    await go(pg, `/policies?proposal=${proposal.id}`);
    ok((await pg.textContent('[data-view="proposal"] [data-notes]')).includes('github.com'), '화면에 안내 없음');
    await pg.close();
  });
  await T('E 악성: 여러 패키지 세션은 패키지 전부 차단 + 미리보기 nextOnly 에 전부', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, { base: 'malicious', patch: { packages: ['./reqeusts', 'six==1.16'] } }); // colourama 는 시드 차단 목록에 이미 있다
    const { proposal } = await decideApi(pg, s.caseId, 'malicious');
    const pk = proposal.changes.filter((c) => c.list === 'packages').map((c) => c.value);
    ok(JSON.stringify(pk) === JSON.stringify(['pip:reqeusts', 'pip:six']), `패키지 차단 ${JSON.stringify(pk)}`);
    const prev = await pg.evaluate(async (id) => UI.api.preview(id), proposal.id);
    ok(JSON.stringify(prev.nextOnly) === JSON.stringify([{ list: 'packages', value: 'pip:reqeusts' }, { list: 'packages', value: 'pip:six' }]), `nextOnly ${JSON.stringify(prev.nextOnly)}`);
    await go(pg, `/policies?proposal=${proposal.id}`);
    await pg.waitForSelector('[data-preview-next]');
    ok(await pg.locator('[data-preview-next] li').count() === 2, '「다음 설치 · 기동부터」 목록 2줄이 아님');
    await pg.close();
  });

  // ---------------- F. 오탐 규칙 ----------------
  await T('F 오탐: 실행 · 금지 포트 규칙은 notes 「정책 탭에서 직접 수정」, 통신은 allowHosts 없던 규칙이면 allowCidrs IP/32', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(400);
    const rc = await runtimeCase(pg);
    const { proposal } = await decideApi(pg, rc.id, 'false_positive');
    ok(proposal.notes.some((n) => n.includes('pipe-to-shell') && n.includes('정책 탭에서 직접 수정')), `안내 ${JSON.stringify(proposal.notes)}`);
    ok(proposal.changes.some((c) => c.ruleId === 'egress-allowlist' && c.field === 'allowCidrs' && c.value === '203.0.113.7/32'), `egress-allowlist 예외 ${JSON.stringify(proposal.changes)}`);
    ok(!proposal.changes.some((c) => c.field === 'allowHosts'), 'allowHosts 없던 규칙에 allowHosts');
    // 금지 포트(denyPorts)는 허용 대역보다 먼저 판정 — reverse-shell-ports 는 예외 대신 안내(백엔드 matchConnect 와 같음)
    ok(!proposal.changes.some((c) => c.ruleId === 'reverse-shell-ports') && proposal.notes.some((n) => n.includes('reverse-shell-ports') && n.includes('금지 목록')), `금지 포트 안내 ${JSON.stringify(proposal.notes)}`);
    await pg.close();
  });

  // ---------------- G. 경고 묶음 · violationCount ----------------
  await T('G 런타임 경고는 열린 건에 묶이고(규칙 · 감사 행 caseId), 경고만으로는 새 건 없음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(400);
    const rc = await runtimeCase(pg);
    ok(rc.ruleIds.includes('egress-allowlist'), `건 규칙 ${JSON.stringify(rc.ruleIds)}`);
    const alertRows = await pg.evaluate((cid) => UI.state.audit.filter((a) => a.ruleId === 'egress-allowlist' && a.event.containerName === 'pkg-reqeusts').map((a) => a.caseId), rc.id);
    ok(alertRows.length >= 1 && alertRows.every((x) => x === rc.id), `경고 행 caseId ${JSON.stringify(alertRows)}`);
    const before = (await pg.evaluate(async () => UI.api.cases({}))).length;
    await pg.evaluate(() => UI.simEvent('web-api', { kind: 'connect', comm: 'python', dstIp: '198.51.100.4', dstPort: 8443 }));
    await pg.waitForTimeout(200);
    ok((await pg.evaluate(async () => UI.api.cases({}))).length === before, '경고만으로 새 건이 열림');
    await pg.close();
  });
  await T('G 설치 목록 위반 수 = violationCount(같은 위반 묶음 count 합)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    const list = await pg.evaluate(async () => UI.api.installs());
    const row = list.find((x) => x.id === s.id);
    ok(row.violationCount === row.violations.reduce((n, v) => n + (v.count || 1), 0) && row.violationCount > 0, `violationCount ${row.violationCount}`);
    await go(pg, `/installs?status=all`);
    ok((await pg.textContent(`tr[data-id="${s.id}"] [data-col="violations"]`)).trim() === String(row.violationCount), '표의 위반 수');
    await pg.close();
  });

  // ---------------- H. 차단 이미지 재기동 ----------------
  await T('H 차단 이미지 재기동: blocked-image 격리, 새 건 없음, 감사 행 caseId = 차단을 만든 건', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(400);
    const rc = await runtimeCase(pg);
    const { proposal } = await decideApi(pg, rc.id, 'malicious');
    await pg.evaluate(async (id) => UI.api.apply(id), proposal.id);
    const before = (await pg.evaluate(async () => UI.api.cases({}))).length;
    await pg.evaluate(() => { UI.sim.restartIn = 0; });
    await pg.waitForFunction(() => UI.state.audit.some((a) => a.ruleId === 'blocked-image'), null, { timeout: 3000 });
    const row = await pg.evaluate(() => UI.state.audit.find((a) => a.ruleId === 'blocked-image'));
    ok(row.caseId === rc.id && row.event.containerName === 'pkg-reqeusts', `감사 행 ${row.caseId} / ${row.event.containerName}`);
    ok((await pg.evaluate(async () => UI.api.cases({}))).length === before, '재기동이 새 건을 열었음');
    const fp = await pg.evaluate(async () => { const c = (await UI.api.cases({ source: 'runtime' })).find((x) => x.container === 'pkg-reqeusts'); return c && c.state; });
    ok(fp === 'closed', `원래 건 상태 ${fp}`);
    await pg.close();
  });

  // ---------------- I. 무결성 ----------------
  await T('I 바뀐 화면 × 1440 · 1280: 페이지 넘침 0', async () => {
    for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) {
      const pg = await newPage(vp);
      await go(pg, '/');
      const s = await runInstall(pg, 'malicious');
      const { proposal } = await decideApi(pg, s.caseId, 'malicious');
      for (const hsh of ['/', `/installs?status=all&id=${s.id}`, `/policies?proposal=${proposal.id}`, '/policies?id=__blocklist__']) {
        await go(pg, hsh);
        const o = await noOverflow(pg);
        ok(o.every((x) => x <= 0), `${vp.width} ${hsh} 넘침 ${JSON.stringify(o)}`);
      }
      if (vp.width === 1280) await shot(pg, '04-policy-1280');
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
