/* 10/15 사용자 목표 회귀 — 목업 2차(판정 흐름). 기준: Claude Docs 「사용자 목표」 · 「API 계약」 탭
   1 대시보드 = 판정 대기 목록(설치 · 런타임 함께, 첫 줄) + 오늘 요약 + 작은 「감시 중」 분당 위반 막대 카드. 0건이면 「처리할 일 없음」. 최근 위반 피드 · 최근 설치 검사 목록 없음
   2 「확인함」 없음. 판정 2버튼 「악성 확정」 / 「오탐」 → 제안 초안 → 정책 맨 위 「제안된 변경」. 판정 뒤 결과 · 처리자(보안 담당자) · 시각. 이미 판정된 건은 409
   3 미리보기 = 감사 로그 재평가(바뀌는 건수 · 목록), 패키지 · 이미지 차단은 '다음 설치 · 기동부터'. 적용 → 건 종결 + 변경 이력. 버림 → 변경 없이 종결
   4 차단 목록(패키지 · 이미지 · 도메인). 차단 패키지 재설치 = 컨테이너 없이 「설치 전 거부」(refused). 차단 이미지 = 재기동 즉시 격리(blocked-image). 차단 도메인 = 시스템 규칙 blocklist-hosts(편집 불가 · 차단 목록에서 관리)
   5 오탐 예외는 가장 좁게: 파일 allowPaths · 도메인 있는 통신 allowHosts · 도메인 없는 통신 allowCidrs IP/32 · 실행 규칙은 자동 예외 없음 안내
   6 런타임 건: 격리됨 · 격리 대상에서만 열림(경고만으로는 안 열림), 컨테이너 이름당 열린 건 1개, 판정은 설치와 같음(악성 = 이미지 · 도메인 차단)
   7 이벤트: 실시간만(1h · 24h 기간 조회 없음), 기본 위반만, 행 상세에 「토폴로지에서 보기」
   8 토폴로지: 런타임만(sg-install-* 노드 없음), 격리 컨테이너를 고르면 판정 버튼, 공격 체인은 설치 검사 시트와 같은 부품
   9 감사 로그: 판정 결과 열(판정 대기 · 악성 · 오탐 · 건 없음), 판정 · 정책 변경 이력 보기, 기간 조회는 여기만
   10 용어: 엔진 결과 = 「탐지 결과」, 사람 결론 = 「판정」
   11 설치 검사: 기본 필터 「판정 대기」, 상세에 공격 체인 + 정적 분석 비교(OSV · 버전 무관 · 출처 osv.dev · 실패 시 「조회 실패」)
   12 모의 API = 계약 이름 · 모양(cases · decide · proposals · preview · apply · discard · blocklist · changes · installs/refused). 실제 백엔드 모드는 같은 경로를 부른다(10/21 React 맞춤 — 전: 「백엔드 미지원」)
   13 데모 대본: 5분 이야기 7단계를 처음부터 끝까지(시드 고정)
   14 무결성: 새 화면 상태(제안 · 차단 목록 · 변경 이력) × 1440 · 1280 넘침 0 · 콘솔 오류 0
   OSV 는 page.route 로 응답을 고정한다(reqeusts 0건 · requests 16건 — 2026-10-15 실측값). REAL_OSV=1 이면 실조회 1건을 더 돈다.
   SHOTS=1 이면 13번 데모 대본 단계마다 screenshots/1015-goals/ 에 찍는다.
   실행: (mock/ 에서) python3 -m http.server 8766 → PLAYWRIGHT=<playwright 경로> node tests/goals-1015.cjs   (VERBOSE=1 · ONLY=정규식 · BASE=주소) */
const PW = process.env.PLAYWRIGHT || 'playwright';
const { chromium } = require(PW);
const { splitHash, goState } = require('./nav-state.cjs'); // 10/21b: 필터는 주소 대신 상태로
const path = require('path');
const fs = require('fs');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const API = process.env.API || 'http://127.0.0.1:8000';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots', '1015-goals');
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const OSV_FIXED = { reqeusts: 0, requests: 16 };

(async () => {
  const br = await chromium.launch();
  const osvCalls = [];
  // osv: 'fixed'(기본 — 고정 응답) | 'fail'(네트워크 실패) | 'real'(실조회)
  const newPage = async (viewport = { width: 1440, height: 900 }, osv = 'fixed') => {
    const pg = await br.newPage({ viewport });
    pg.on('console', (m) => {
      if (m.type() !== 'error') return;
      if (osv === 'fail' && /Failed to load resource|ERR_FAILED/.test(m.text())) return; // 일부러 끊은 OSV 요청
      consoleErrors.push(`${pg.url()} ${m.text()}`);
    });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    if (osv !== 'real') await pg.route('https://api.osv.dev/**', (route) => {
      if (osv === 'fail') return route.abort('failed');
      let body = {}; try { body = JSON.parse(route.request().postData() || '{}'); } catch { /* 빈 본문 */ }
      osvCalls.push(body);
      const n = OSV_FIXED[(body.package || {}).name] || 0;
      const vulns = Array.from({ length: n }, (_, i) => ({ id: `GHSA-test-${i + 1}`, modified: '2026-01-01T00:00:00Z' }));
      return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: JSON.stringify(n ? { vulns } : {}) });
    });
    return pg;
  };
  const go = async (pg, hash, search = '') => { await pg.goto(`${BASE}${search ? search + '&' : '?'}as=admin#${splitHash(hash)[0]}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); if (splitHash(hash)[1]) await goState(pg, hash, 0); await pg.waitForTimeout(400); }; // 10/20: 로그인 건너뜀(?as=admin) // 10/21b
  const confirmOk = (pg) => pg.click('dialog[data-part="confirm"] [data-confirm="ok"]'); // 10/20: 판정 · 적용 · 버림은 확인 대화상자(B)
  const shot = async (pg, name) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `${name}.png`) }); };
  const pendingCount = (pg) => pg.$eval('[data-pending-count]', (el) => Number(el.textContent.replace(/[^\d]/g, '')));
  // 데모 제어 설치 실행 → 끝 보고까지 기다리고 새 세션을 돌려준다
  const runInstall = async (pg, kind) => {
    const id = await pg.evaluate((k) => UI.runInstallDemo(k), kind);
    await pg.waitForFunction((sid) => UI.state.installs.find((s) => s.id === sid && (s.finishedAt || s.refusedBy)), id, { timeout: 8000 });
    return pg.evaluate(async (sid) => UI.api.install(sid), id);
  };
  const caseOf = (pg, id) => pg.evaluate(async (cid) => UI.api.case(cid), id);
  const decideApi = (pg, id, decision) => pg.evaluate(async ([cid, d]) => UI.api.decide(cid, { decision: d, note: '' }), [id, decision]);

  // ---------------- 1. 대시보드 ----------------
  await T('1 대시보드: 첫 줄 「판정 대기 0」 + 「처리할 일 없음」(시드)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    ok(await pg.locator('[data-section="pending"]').count() === 1, '판정 대기 구역 없음');
    ok(await pendingCount(pg) === 0, `판정 대기 ${await pendingCount(pg)}`);
    ok((await pg.textContent('[data-section="pending"]')).includes('처리할 일 없음'), '「처리할 일 없음」 없음');
    const tops = await pg.$$eval('.dash > *', (els) => els.map((e) => [e.getAttribute('data-section') || e.querySelector('[data-section]')?.getAttribute('data-section'), e.getBoundingClientRect().top, e.getBoundingClientRect().left]));
    const pending = await pg.$eval('[data-section="pending"]', (el) => [el.getBoundingClientRect().top, el.getBoundingClientRect().left]);
    // 10/30: 판정 대기 위에는 상태 신호등 한 줄 · 시연 카드(관리자 · demo)만 — 그 밖(종합)은 아래(계약 §4 · §5)
    const others = await pg.$$eval('.dash [data-section]:not([data-section="pending"]):not([data-section="demo"]), .dash [data-card]', (els) => els.map((e) => e.getBoundingClientRect().top));
    ok(others.every((t) => t >= pending[0] - 1), `판정 대기가 첫 줄이 아님 ${JSON.stringify(tops)}`);
    const above = await pg.$$eval('.dash > *', (els) => els.map((e) => e.getAttribute('data-section') || e.getAttribute('data-part')));
    ok(JSON.stringify(above.slice(0, 3)) === JSON.stringify(['signals', 'demo', 'pending']), `위 순서 ${JSON.stringify(above)}`); // 10/30
    await pg.close();
  });
  await T('1 대시보드: 오늘 요약 + 「감시 중」 분당 위반 막대 카드', async () => {
    const pg = await newPage();
    await go(pg, '/');
    // 10/16: 오늘 요약 · 감시 중 카드 → 「eBPF 수집 종합」 숫자 칸 · 위반 추이(tests/overview-1016.cjs)
    for (const k of ['decided', 'installs', 'isolated']) ok(await pg.locator(`[data-section="overview"] [data-kpi="${k}"]`).count() === 1, `${k} 칸 없음`);
    ok((await pg.textContent('[data-section="overview"]')).includes('감시 중'), '「감시 중」 문구 없음');
    const bars = await pg.locator('[data-section="overview"] [data-chart="violations"] [data-bucket]').count();
    ok(bars >= 3, `막대 ${bars}개`);
    await pg.close();
  });
  await T('1 대시보드: 최근 위반 피드 · 최근 설치 검사 목록 없음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    ok(await pg.locator('#page .feed').count() === 0, '위반 피드 남음');
    ok(await pg.locator('#page .recent-list').count() === 0, '최근 설치 검사 목록 남음');
    await pg.close();
  });
  await T('1 대시보드: 판정 대기에 설치 · 런타임이 함께', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await runInstall(pg, 'malicious');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(600);
    ok(await pendingCount(pg) === 2, `판정 대기 ${await pendingCount(pg)}`);
    const src = await pg.$$eval('[data-section="pending"] [data-case]', (els) => els.map((e) => e.dataset.source).sort());
    ok(JSON.stringify(src) === JSON.stringify(['install', 'runtime']), `출처 ${JSON.stringify(src)}`);
    await pg.close();
  });

  // ---------------- 2. 판정 2버튼 · 확인함 없음 ----------------
  await T('2 「확인함」이 어디에도 없음(설치 시트 · 이벤트 시트 · API)', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runInstall(pg, 'malicious');
    await go(pg, `/installs?id=${s.id}`);
    await pg.waitForSelector('.sheet[data-sheet="install"]');
    ok(await pg.locator('#page button:has-text("확인함")').count() === 0, '설치 시트에 확인함');
    await pg.evaluate(() => UI.runAttackNow());
    await go(pg, '/events?verdict=kill');
    await pg.click('.feed-row');
    await pg.waitForSelector('.sheet[data-sheet="event"]');
    ok(await pg.locator('#page button:has-text("확인함")').count() === 0, '이벤트 시트에 확인함');
    ok(await pg.evaluate(() => typeof UI.api.ackInstall === 'undefined' && typeof UI.ackContainer === 'undefined'), '확인함 API 남음');
    await pg.close();
  });
  await T('2 설치 상세: 판정 버튼 2개(악성 확정 · 오탐)', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runInstall(pg, 'malicious');
    await go(pg, `/installs?id=${s.id}`);
    const labels = await pg.$$eval('.sheet [data-part="decision"] button', (els) => els.map((e) => e.getAttribute('aria-label')));
    ok(JSON.stringify(labels) === JSON.stringify(['악성 확정', '오탐']), `버튼 ${JSON.stringify(labels)}`);
    await pg.close();
  });
  await T('2 판정 → 제안 초안 → 정책 맨 위 「제안된 변경」 · 판정 뒤 결과 · 처리자 · 시각', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runInstall(pg, 'malicious');
    await go(pg, `/installs?id=${s.id}`);
    await pg.click('.sheet [data-part="decision"] button[aria-label="악성 확정"]');
    await confirmOk(pg); // 10/20
    await pg.waitForTimeout(300);
    const c = await caseOf(pg, s.caseId);
    ok(c.state === 'decided' && c.decision === 'malicious' && c.decidedBy === '보안 담당자' && c.decidedAt && c.proposalId, `건 ${JSON.stringify(c)}`);
    const caseTxt = await pg.textContent('.sheet [data-part="decision"]');
    ok(caseTxt.includes('악성') && caseTxt.includes('보안 담당자') && /\d{2}:\d{2}/.test(caseTxt), `판정 뒤 표시 "${caseTxt}"`);
    const drafts = await pg.evaluate(async () => UI.api.proposals({ state: 'draft' }));
    ok(drafts.length === 1 && drafts[0].caseId === s.caseId, `초안 ${drafts.length}`);
    await go(pg, '/policies');
    const first = await pg.$eval('.policy-nav > [data-section]', (el) => el.dataset.section);
    ok(first === 'proposals', `맨 위 구역 ${first}`);
    ok(await pg.locator('[data-section="proposals"] [data-proposal]').count() === 1, '제안 항목 없음');
    ok(pg.url().includes(`proposal=${drafts[0].id}`), `초안이 자동 선택되지 않음 ${pg.url()}`);
    await pg.close();
  });
  await T('2 이미 판정된 건은 409', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    await decideApi(pg, s.caseId, 'malicious');
    const err = await pg.evaluate(async (cid) => UI.api.decide(cid, { decision: 'false_positive' }).then(() => 'ok', (e) => e.message), s.caseId);
    ok(err.startsWith('409'), `두 번째 판정 결과 ${err}`);
    await pg.close();
  });

  // ---------------- 3. 미리보기 · 적용 · 버림 ----------------
  await T('3 미리보기(악성): 감사 로그 재평가 건수 + 「다음 설치 · 기동부터」 패키지 차단', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    const { proposal } = await decideApi(pg, s.caseId, 'malicious');
    await go(pg, `/policies?proposal=${proposal.id}`);
    await pg.waitForSelector('[data-view="proposal"] [data-part="preview"] [data-preview-count]');
    const prev = await pg.evaluate(async (pid) => UI.api.preview(pid), proposal.id);
    ok(typeof prev.evaluated === 'number' && Array.isArray(prev.changed) && prev.counts && 'toNormal' in prev.counts && 'toBlocked' in prev.counts, `미리보기 모양 ${JSON.stringify(prev).slice(0, 120)}`);
    const next = await pg.textContent('[data-part="preview"] [data-preview-next]');
    ok(next.includes('다음 설치') && next.includes('pip:reqeusts'), `다음 설치부터 "${next}"`);
    await pg.close();
  });
  await T('3 적용 → 건 종결 · 차단 목록 · 변경 이력(보안 담당자 · 어느 판정)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    const { proposal } = await decideApi(pg, s.caseId, 'malicious');
    await go(pg, `/policies?proposal=${proposal.id}`);
    await pg.click('[data-view="proposal"] button[aria-label="적용"]');
    await confirmOk(pg); // 10/20
    await pg.waitForTimeout(400);
    const c = await caseOf(pg, s.caseId);
    ok(c.state === 'closed' && c.closedAt, `건 상태 ${c.state}`);
    const bl = await pg.evaluate(async () => UI.api.blocklist());
    ok(bl.packages.some((x) => x.value === 'pip:reqeusts' && x.caseId === s.caseId && x.by === '보안 담당자'), '패키지 차단 없음');
    ok(bl.hosts.some((x) => x.value === 'cdn.reqeusts-update.test'), '도메인 차단 없음');
    const ch = (await pg.evaluate(async () => UI.api.changes({ limit: 5 })))[0];
    ok(ch.kind === 'proposal_applied' && ch.by === '보안 담당자' && ch.caseId === s.caseId && ch.proposalId === proposal.id, `변경 이력 ${JSON.stringify(ch)}`);
    const txt = await pg.textContent('[data-view="proposal"]');
    ok(txt.includes('적용됨') && txt.includes('보안 담당자') && txt.includes(s.caseId), `적용 뒤 표시 "${txt.slice(0, 160)}"`);
    await pg.close();
  });
  await T('3 버림 → 변경 없이 건 종결', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'warn');
    const { proposal } = await decideApi(pg, s.caseId, 'false_positive');
    const before = await pg.evaluate(async () => [(await UI.api.changes({})).length, JSON.stringify(UI.state.rules)]);
    await go(pg, `/policies?proposal=${proposal.id}`);
    await pg.click('[data-view="proposal"] button[aria-label="버림"]');
    await confirmOk(pg); // 10/20: 두 번 누르기 → 확인 대화상자
    await pg.waitForTimeout(300);
    const c = await caseOf(pg, s.caseId);
    const p = (await pg.evaluate(async () => UI.api.proposals({}))).find((x) => x.id === proposal.id);
    const after = await pg.evaluate(async () => [(await UI.api.changes({})).length, JSON.stringify(UI.state.rules)]);
    ok(c.state === 'closed' && p.state === 'discarded', `건 ${c.state} · 제안 ${p.state}`);
    ok(after[0] === before[0] && after[1] === before[1], '버렸는데 정책 · 변경 이력이 바뀜');
    await pg.close();
  });

  // ---------------- 4. 차단 목록 ----------------
  await T('4 차단 패키지 재설치 → 컨테이너 없이 「설치 전 거부」, 새 건 없음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    const { proposal } = await decideApi(pg, s.caseId, 'malicious');
    await pg.evaluate(async (pid) => UI.api.apply(pid), proposal.id);
    const nCases = (await pg.evaluate(async () => UI.api.cases({}))).length;
    const r = await runInstall(pg, 'malicious');
    ok(r.status === 'refused' && !r.container && r.refusedBy && r.refusedBy.value === 'pip:reqeusts' && r.caseId === null, `재설치 ${JSON.stringify({ st: r.status, c: r.container, by: r.refusedBy })}`);
    ok((await pg.evaluate(async () => UI.api.cases({}))).length === nCases, '거부 세션에 건이 열림');
    await go(pg, '/installs?status=refused');
    const label = await pg.textContent(`tr[data-id="${r.id}"] [data-status]`);
    ok(label.includes('설치 전 거부'), `라벨 "${label}"`);
    const chk = await pg.evaluate(async () => UI.api.blocklistCheck({ manager: 'pip', package: './reqeusts' }));
    ok(chk.blocked === true && chk.value === 'pip:reqeusts' && chk.caseId === s.caseId, `차단 확인 ${JSON.stringify(chk)}`);
    await pg.close();
  });
  await T('4 정책 › 차단 목록: 패키지 · 이미지 · 도메인 세 묶음', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=__blocklist__');
    await pg.waitForSelector('[data-view="blocklist"]');
    for (const l of ['packages', 'images', 'hosts']) ok(await pg.locator(`[data-view="blocklist"] [data-list="${l}"]`).count() === 1, `${l} 묶음 없음`);
    ok(await pg.locator('[data-view="blocklist"] [data-list="packages"] [data-value]').count() >= 1, '시드 차단 패키지 없음');
    await pg.close();
  });
  await T('4 차단 도메인 = 시스템 규칙 blocklist-hosts(차단 목록에서 관리 · 편집 불가)', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=blocklist-hosts');
    const chip = await pg.textContent('.rule-row:has-text("blocklist-hosts") .scope-chip');
    ok(chip.includes('차단 목록에서 관리'), `칩 "${chip}"`);
    ok(await pg.locator('[data-readonly="blocklist-hosts"]').count() === 1, '읽기 전용 안내 없음');
    ok(await pg.locator('#page button:has-text("저장 후 적용")').count() === 0, '저장 버튼이 있음');
    const s = await runInstall(pg, 'malicious');
    const { proposal } = await decideApi(pg, s.caseId, 'malicious');
    await pg.evaluate(async (pid) => UI.api.apply(pid), proposal.id);
    const v = await pg.evaluate(() => MOCK.evaluate(UI.state.rules, { kind: 'connect', comm: 'node', containerName: 'web-api', imageName: 'node:22-alpine', dstIp: '203.0.113.7', dstPort: 443, dstHost: 'cdn.reqeusts-update.test' }));
    ok(v.matched && v.ruleId === 'blocklist-hosts' && v.action === 'kill', `평가 ${v.ruleId}`);
    const err = await pg.evaluate(async () => UI.api.saveRule(Object.assign({}, UI.state.rules.find((r) => r.id === 'blocklist-hosts'), { denyHosts: [] })).then(() => 'ok', (e) => e.message));
    ok(err.startsWith('403'), `직접 편집 결과 ${err}`);
    await pg.close();
  });
  await T('4 차단 이미지: 재기동 즉시 격리(blocked-image), 새 건 없음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(300);
    const rc = (await pg.evaluate(async () => UI.api.cases({ source: 'runtime', state: 'open' })))[0];
    ok(rc && rc.container === 'pkg-reqeusts', '런타임 건 없음');
    const { proposal } = await decideApi(pg, rc.id, 'malicious');
    ok(proposal.changes.some((c) => c.op === 'block' && c.list === 'images' && c.value === 'demo/reqeusts:1.0.2'), `이미지 차단 제안 없음 ${JSON.stringify(proposal.changes)}`);
    await pg.evaluate(async (pid) => UI.api.apply(pid), proposal.id);
    const n = (await pg.evaluate(async () => UI.api.cases({}))).length;
    await pg.evaluate(() => { document.getElementById('toasts').replaceChildren(); UI.runAttackNow(); });
    await pg.waitForTimeout(400);
    const k = await pg.evaluate(() => UI.state.stats.killed[0]);
    ok(k.name === 'pkg-reqeusts' && k.reason === 'blocked-image', `격리 기록 ${JSON.stringify(k)}`);
    ok((await pg.evaluate(async () => UI.api.cases({}))).length === n, '차단 이미지 격리로 새 건이 열림');
    ok(await pg.locator('.toast:has-text("차단된 이미지")').count() >= 1, '차단 이미지 토스트 없음');
    await pg.close();
  });

  // ---------------- 5. 오탐 예외는 가장 좁게 ----------------
  // 10/16 갱신 — 3차 결정 3: 규칙에 원래 allowHosts 가 없으면 allowCidrs IP/32 (DNS 미확인 fail-open 방지)
  await T('5 오탐(통신, 규칙에 allowHosts 없음) → egress-allowlist allowCidrs 140.82.112.3/32', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'warn');
    ok(s.status === 'warned', `tiny-git-dep 결과 ${s.status}`);
    const { proposal } = await decideApi(pg, s.caseId, 'false_positive');
    ok(JSON.stringify(proposal.changes) === JSON.stringify([{ op: 'except', ruleId: 'egress-allowlist', field: 'allowCidrs', value: '140.82.112.3/32' }]), `변경 ${JSON.stringify(proposal.changes)}`);
    await pg.close();
  });
  await T('5 오탐(파일 · 실행) → allowPaths 경로, 실행 규칙은 자동 예외 없음 안내', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(300);
    const rc = (await pg.evaluate(async () => UI.api.cases({ source: 'runtime', state: 'open' })))[0];
    const { proposal } = await decideApi(pg, rc.id, 'false_positive');
    const paths = proposal.changes.filter((c) => c.ruleId === 'sensitive-files' && c.field === 'allowPaths').map((c) => c.value).sort();
    ok(JSON.stringify(paths) === JSON.stringify(['/etc/shadow', '/root/.ssh/id_rsa']), `allowPaths ${JSON.stringify(paths)}`);
    ok(!proposal.changes.some((c) => ['no-shell-download', 'pipe-to-shell'].includes(c.ruleId)), '실행 규칙에 자동 예외');
    await go(pg, `/policies?proposal=${proposal.id}`);
    const note = await pg.textContent('[data-view="proposal"] [data-exec-note]');
    ok(note.includes('자동 예외') && note.includes('no-shell-download'), `안내 "${note}"`);
    await pg.close();
  });
  await T('5 오탐(도메인 없는 통신) → allowCidrs IP/32', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const id = await pg.evaluate(() => UI.runInstallDemo({ pkg: 'netcheck', manager: 'pip', exitCode: 0, events: [[{ kind: 'connect', comm: 'python3', dstIp: '203.0.113.50', dstPort: 443 }, 1]] }));
    await pg.waitForFunction((sid) => UI.state.installs.find((s) => s.id === sid && s.finishedAt), id, { timeout: 8000 });
    const s = await pg.evaluate(async (sid) => UI.api.install(sid), id);
    const { proposal } = await decideApi(pg, s.caseId, 'false_positive');
    ok(JSON.stringify(proposal.changes) === JSON.stringify([{ op: 'except', ruleId: 'sandbox-egress', field: 'allowCidrs', value: '203.0.113.50/32' }]), `변경 ${JSON.stringify(proposal.changes)}`);
    await pg.close();
  });

  // ---------------- 6. 런타임 건 ----------------
  // 11/04: 연쇄 규칙 시드 행에 종결된 과거 런타임 건이 붙어서, 이 시험에서 새로 열린(종결 아닌) 건만 센다
  await T('6 런타임: 격리 → 건 1개, 다시 격리돼도 같은 건(위반 수만 증가)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(300);
    const a = await pg.evaluate(async () => (await UI.api.cases({ source: 'runtime' })).filter((c) => c.state !== 'closed'));
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(300);
    const b = await pg.evaluate(async () => (await UI.api.cases({ source: 'runtime' })).filter((c) => c.state !== 'closed'));
    ok(a.length === 1 && b.length === 1 && a[0].id === b[0].id, `건 ${a.length} → ${b.length}`);
    ok(b[0].violations > a[0].violations, `위반 수 ${a[0].violations} → ${b[0].violations}`);
    ok(b[0].state === 'open' && b[0].decision === 'pending' && !b[0].package, `건 모양 ${JSON.stringify(b[0])}`);
    await pg.close();
  });
  await T('6 런타임: 경고만으로는 건이 열리지 않음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.evaluate(() => UI.simEvent('worker', { kind: 'connect', comm: 'python3', dstIp: '203.0.113.42', dstPort: 8443 }));
    await pg.waitForTimeout(200);
    const lv = await pg.evaluate(() => UI.levelOf(UI.state.audit[0]));
    ok(lv === 'alert', `주입 이벤트 ${lv}`);
    ok((await pg.evaluate(async () => (await UI.api.cases({ source: 'runtime' })).filter((c) => c.state !== 'closed'))).length === 0, '경고로 건이 열림');
    await pg.close();
  });

  // ---------------- 7. 이벤트 ----------------
  await T('7 이벤트: 기간 조회(1h · 24h) 없음 · 기본 위반만', async () => {
    const pg = await newPage();
    await go(pg, '/events?period=24h');
    const segs = await pg.$$eval('#page .seg-btn', (els) => els.map((e) => e.textContent.trim()));
    ok(!segs.some((t) => /1h|24h|실시간/.test(t)), `기간 버튼 ${JSON.stringify(segs)}`);
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(500);
    ok(await pg.locator('.feed-row').count() > 0, '위반 행 없음');
    ok(await pg.locator('.feed-row .badge-level-normal').count() === 0, '정상 행 보임');
    await pg.close();
  });
  await T('7 이벤트: 행 상세에 「토폴로지에서 보기」', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(500);
    await pg.click('.feed-row');
    await pg.waitForSelector('.sheet[data-sheet="event"]');
    const href = await pg.getAttribute('.sheet a:has-text("토폴로지에서 보기")', 'href');
    ok(href === '#/topology?node=c%3Apkg-reqeusts', `링크 ${href}`); // 10/21b: 주소에는 컨테이너 노드(c:)만, 컨테이너 필터는 상태(data-nav)로
    ok(JSON.parse(await pg.getAttribute('.sheet a:has-text("토폴로지에서 보기")', 'data-nav')).container === 'pkg-reqeusts', '컨테이너 필터를 상태로 넘기지 않음');
    await pg.close();
  });

  // ---------------- 8. 토폴로지 ----------------
  await T('8 토폴로지: 설치 검사 컨테이너(sg-install-*) 노드 없음', async () => {
    const pg = await newPage();
    await go(pg, '/topology');
    await runInstall(pg, 'malicious');
    await pg.waitForTimeout(1200);
    const opts = await pg.$$eval('#page select option', (els) => els.map((e) => e.value));
    ok(!opts.some((v) => v.startsWith('sg-install-')), `선택지 ${JSON.stringify(opts)}`);
    const labels = await pg.$$eval('.topo-svg .node title', (els) => els.map((e) => e.textContent));
    ok(!labels.some((t) => t.startsWith('sg-install-')), '설치 검사 노드가 그려짐');
    await pg.close();
  });
  await T('8 토폴로지: 격리 컨테이너를 고르면 판정 버튼', async () => {
    const pg = await newPage();
    await go(pg, '/topology');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(1300);
    ok(await pg.locator('.topo-side [data-part="decision"]').count() === 0, '고르기 전에 판정 버튼');
    await pg.click('.topo-side .chain-head:has-text("pkg-reqeusts")');
    const labels = await pg.$$eval('.topo-side [data-part="decision"] button', (els) => els.map((e) => e.getAttribute('aria-label')));
    ok(JSON.stringify(labels) === JSON.stringify(['악성 확정', '오탐']), `버튼 ${JSON.stringify(labels)}`);
    await pg.close();
  });
  await T('8 공격 체인: 설치 검사 시트와 토폴로지가 같은 부품', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    await go(pg, `/installs?id=${s.id}`);
    const a = await pg.$eval('.sheet [data-part="attack-chain"]', (el) => [el.tagName, el.className, [...new Set([...el.querySelectorAll('.step-no')].map((x) => x.textContent))].join()]);
    await pg.evaluate(() => UI.runAttackNow());
    await go(pg, '/topology');
    await pg.waitForTimeout(1200);
    const b = await pg.$eval('.topo-side [data-part="attack-chain"]', (el) => [el.tagName, el.className, [...new Set([...el.querySelectorAll('.step-no')].map((x) => x.textContent))].join()]);
    ok(a[0] === b[0] && a[1] === b[1], `부품 다름 ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
    ok(a[2] === '1 실행,2 파일,3 통신' && b[2] === '1 실행,2 파일,3 통신', `단계 ${a[2]} / ${b[2]}`);
    ok(await pg.evaluate(() => typeof UI.attackChain === 'function'), 'UI.attackChain 없음');
    await pg.close();
  });

  // ---------------- 9. 감사 로그 ----------------
  await T('9 감사 로그: 판정 결과 열(악성 · 건 없음 시드, 대기 · 오탐 실시간)', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    const ths = await pg.$$eval('table[data-table="audit"] th', (els) => els.map((e) => e.textContent.trim()));
    ok(ths.includes('판정') && ths.includes('탐지 결과'), `열 ${JSON.stringify(ths)}`);
    let vals = await pg.$$eval('table[data-table="audit"] [data-decision]', (els) => [...new Set(els.map((e) => e.textContent.trim()))]);
    ok(vals.includes('악성') && vals.includes('건 없음'), `시드 판정 값 ${JSON.stringify(vals)}`);
    const s = await runInstall(pg, 'warn');
    await pg.click('#page button:has-text("새로고침")'); // 같은 주소로 다시 가면 화면이 다시 그려지지 않는다
    await pg.waitForTimeout(400);
    vals = await pg.$$eval('table[data-table="audit"] [data-decision]', (els) => [...new Set(els.map((e) => e.textContent.trim()))]);
    ok(vals.includes('판정 대기'), `대기 값 없음 ${JSON.stringify(vals)}`);
    await decideApi(pg, s.caseId, 'false_positive');
    await pg.click('#page button:has-text("새로고침")');
    await pg.waitForTimeout(400);
    vals = await pg.$$eval('table[data-table="audit"] [data-decision]', (els) => [...new Set(els.map((e) => e.textContent.trim()))]);
    ok(vals.includes('오탐'), `오탐 값 없음 ${JSON.stringify(vals)}`);
    await pg.close();
  });
  await T('9 감사 로그: 판정 · 정책 변경 이력 보기(시드 판정 2건 · 처리자)', async () => {
    const pg = await newPage();
    await go(pg, '/audit?view=changes');
    await pg.waitForSelector('table[data-table="history"]');
    const rows = await pg.$$eval('table[data-table="history"] tbody tr', (els) => els.map((e) => e.textContent));
    ok(rows.filter((t) => t.includes('악성 확정')).length >= 2, `판정 이력 ${rows.length}행`);
    ok(rows.some((t) => t.includes('제안 적용')) && rows.every((t) => t.includes('보안 담당자')), '적용 이력 · 처리자 없음');
    await pg.close();
  });
  await T('9 감사 로그: 기간 조회는 여기에 있음', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    ok(await pg.locator('#page input[type="datetime-local"]').count() === 2, '기간 입력 없음');
    await pg.close();
  });

  // ---------------- 10. 용어 ----------------
  await T('10 용어: 엔진 결과는 「탐지 결과」(이벤트 머리 · 필터 · 시트, 토폴로지 노드)', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    const head = await pg.textContent('.feed-head');
    ok(head.includes('탐지 결과') && !head.includes('판정'), `이벤트 머리 "${head}"`);
    const filters = await pg.textContent('.filters');
    ok(filters.includes('탐지 결과') && !filters.includes('판정'), `필터 "${filters}"`);
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(500);
    await pg.click('.feed-row');
    const dts = await pg.$$eval('.sheet[data-sheet="event"] dt', (els) => els.map((e) => e.textContent));
    ok(dts.includes('탐지 결과') && !dts.includes('판정'), `시트 ${JSON.stringify(dts)}`);
    await go(pg, '/topology');
    await pg.waitForTimeout(1200);
    await pg.click('.topo-side .chain-step');
    const tdts = await pg.$$eval('.topo-side dt', (els) => els.map((e) => e.textContent));
    ok(tdts.includes('탐지 결과') && !tdts.includes('판정'), `노드 카드 ${JSON.stringify(tdts)}`);
    await pg.close();
  });

  // ---------------- 11. 설치 검사 ----------------
  await T('11 설치 검사: 기본 필터 「판정 대기」(진행 중 포함)', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const on = await pg.$eval('[data-filter="status"] button[aria-pressed="true"]', (el) => el.dataset.value);
    ok(on === 'pending', `기본 필터 ${on}`);
    ok(await pg.locator('table[data-table="installs"] tbody tr[data-id]').count() === 0, '시드에 판정 대기 세션');
    await pg.evaluate(() => UI.runInstallDemo('malicious'));
    await pg.waitForTimeout(250);
    ok(await pg.locator('table[data-table="installs"] tbody tr[data-id] [data-status="running"]').count() === 1, '진행 중 세션이 안 보임');
    await pg.waitForFunction(() => document.querySelector('table[data-table="installs"] tbody tr[data-id] [data-status]')?.dataset.status === 'isolated', null, { timeout: 4000 });
    const dec = await pg.textContent('table[data-table="installs"] tbody tr[data-id] [data-decision]');
    ok(dec.includes('판정 대기'), `판정 칸 "${dec}"`);
    await pg.close();
  });
  await T('11 정적 분석 비교: OSV 0건 · 버전 무관 · 출처 osv.dev(요청 = PyPI reqeusts)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    osvCalls.length = 0;
    await go(pg, `/installs?id=${s.id}`);
    await pg.waitForSelector('.sheet [data-part="osv"] [data-osv-count]', { timeout: 5000 });
    const t = await pg.textContent('.sheet [data-part="osv"]');
    ok(t.includes('0건') && t.includes('버전 무관') && t.includes('osv.dev'), `OSV 칸 "${t}"`);
    ok(osvCalls.some((b) => b.package && b.package.name === 'reqeusts' && b.package.ecosystem === 'PyPI' && !b.version), `요청 ${JSON.stringify(osvCalls)}`);
    ok(await pg.locator('.sheet [data-part="attack-chain"] .chain-step').count() >= 3, '체인 없음');
    await pg.close();
  });
  await T('11 정적 분석 비교: requests 는 16건', async () => {
    const pg = await newPage();
    await go(pg, '/installs?status=passed');
    await pg.click('table[data-table="installs"] tbody tr[data-id]:has-text("requests")');
    await pg.waitForSelector('.sheet [data-part="osv"] [data-osv-count]', { timeout: 5000 });
    const n = await pg.textContent('.sheet [data-part="osv"] [data-osv-count]');
    ok(n.includes('16'), `건수 "${n}"`);
    await pg.close();
  });
  await T('11 OSV 이름 정규화(로컬 디렉터리 · 버전 · npm 스코프 · 생태계)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const q = await pg.evaluate(() => [UI.osvQuery('pip', './reqeusts'), UI.osvQuery('pip', 'numpy==1.21.0'), UI.osvQuery('npm', 'lodash@4'), UI.osvQuery('npm', '@babel/core@7.1.0'), UI.osvQuery('cargo', 'ripgrep')]);
    const want = [['PyPI', 'reqeusts'], ['PyPI', 'numpy'], ['npm', 'lodash'], ['npm', '@babel/core'], ['crates.io', 'ripgrep']];
    ok(JSON.stringify(q.map((x) => [x.ecosystem, x.name])) === JSON.stringify(want), `정규화 ${JSON.stringify(q)}`);
    await pg.close();
  });
  await T('11 OSV 실패 → 「조회 실패」, 시트는 그대로', async () => {
    const pg = await newPage({ width: 1440, height: 900 }, 'fail');
    await go(pg, '/');
    const s = await runInstall(pg, 'malicious');
    await go(pg, `/installs?id=${s.id}`);
    await pg.waitForFunction(() => (document.querySelector('.sheet [data-part="osv"]') || {}).textContent?.includes('조회 실패'), null, { timeout: 8000 });
    ok(await pg.locator('.sheet [data-part="attack-chain"] .chain-step').count() >= 3, '실패 뒤 체인이 사라짐');
    ok(await pg.locator('.sheet [data-part="decision"] button').count() === 2, '실패 뒤 판정 버튼이 사라짐');
    await pg.close();
  });
  if (process.env.REAL_OSV) await T('11 OSV 실조회: reqeusts 0건', async () => {
    const pg = await newPage({ width: 1440, height: 900 }, 'real');
    await go(pg, '/');
    const r = await pg.evaluate(async () => UI.api.osv({ ecosystem: 'PyPI', name: 'reqeusts' }));
    ok(r.error === null && r.vulns === 0 && r.source === 'osv.dev', `실조회 ${JSON.stringify(r)}`);
    await pg.close();
  });

  // ---------------- 12. API 계약 ----------------
  await T('12 모의 API: 계약 이름과 모양', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const names = ['installs', 'install', 'installsRefused', 'blocklistCheck', 'cases', 'case', 'decide', 'proposals', 'preview', 'apply', 'discard', 'blocklist', 'unblock', 'changes', 'osv', 'audit'];
    const missing = await pg.evaluate((ns) => ns.filter((n) => typeof UI.api[n] !== 'function'), names);
    ok(!missing.length, `없는 API ${missing.join(',')}`);
    const s = await runInstall(pg, 'malicious');
    const shape = await pg.evaluate(async ([sid]) => {
      const ins = await UI.api.install(sid); const c = await UI.api.case(ins.caseId);
      const { case: c2, proposal } = await UI.api.decide(c.id, { decision: 'malicious', note: '' });
      const bl = await UI.api.blocklist();
      const audit = await UI.api.audit({ limit: 3 });
      return { ins: Object.keys(ins), c: Object.keys(c), c2: c2.state, p: Object.keys(proposal), bl: Object.keys(bl), a: Object.keys(audit[0]) };
    }, [s.id]);
    const need = (have, keys, what) => { const miss = keys.filter((k) => !have.includes(k)); ok(!miss.length, `${what}에 ${miss.join(',')} 없음`); };
    need(shape.ins, ['id', 'manager', 'packages', 'container', 'containerId', 'image', 'startedAt', 'finishedAt', 'exitCode', 'containerExitedAt', 'status', 'refusedBy', 'caseId', 'violations', 'activity'], 'InstallSession');
    need(shape.c, ['id', 'source', 'installId', 'container', 'image', 'package', 'openedAt', 'level', 'violations', 'ruleIds', 'state', 'decision', 'decidedAt', 'decidedBy', 'note', 'proposalId', 'closedAt'], 'Case');
    need(shape.p, ['id', 'caseId', 'decision', 'state', 'createdAt', 'createdBy', 'appliedAt', 'appliedBy', 'changes'], 'Proposal');
    need(shape.bl, ['packages', 'images', 'hosts'], 'Blocklist');
    need(shape.a, ['caseId', 'install'], '감사 로그 행');
    ok(shape.c2 === 'decided', `decide 뒤 ${shape.c2}`);
    await pg.close();
  });
  const backendUp = await fetch(`${API}/health`).then((r) => r.ok).catch(() => false);
  if (backendUp) await T('12 실제 백엔드: 판정 대기 · 제안된 변경이 실제 API 로 뜬다(10/21 — 「백엔드 미지원」 아님)', async () => {
    const pg = await newPage();
    await go(pg, '/', '?source=sim'); await require('./live-login.cjs').liveLogin(pg, API); // 10/21: live 는 쿠키 세션 로그인 뒤
    await go(pg, '/', `?source=live&api=${encodeURIComponent(API)}`);
    await pg.waitForTimeout(800);
    ok(!(await pg.textContent('[data-section="pending"]')).includes('백엔드 미지원'), '대시보드에 미지원 안내');
    await go(pg, '/policies', `?source=live&api=${encodeURIComponent(API)}`);
    await pg.waitForTimeout(800);
    ok(!(await pg.textContent('[data-section="proposals"]')).includes('백엔드 미지원'), '정책 제안에 미지원 안내');
    await pg.close();
  });
  else console.log('SKIP  12 실제 백엔드 — 백엔드가 떠 있지 않음');

  // ---------------- 13. 데모 대본 (5분 이야기) ----------------
  {
    const pg = await newPage();
    let mal = null, warn = null;
    const step = async (name, fn) => T(`13 대본 ${name}`, fn);
    await step('0:00 대시보드 — 판정 대기 0 · 처리할 일 없음', async () => {
      await go(pg, '/');
      ok(await pendingCount(pg) === 0, '판정 대기가 0이 아님');
      ok((await pg.textContent('[data-section="pending"]')).includes('처리할 일 없음'), '처리할 일 없음 없음');
      await shot(pg, '01-dashboard-idle');
    });
    await step('0:30 데모 제어 악성 설치 → 2초 안에 격리 · 대시보드 판정 대기 1', async () => {
      await go(pg, '/installs');
      await pg.click('.topbar button:has-text("데모 제어")');
      await pg.click('[data-demo="install-malicious"]');
      await pg.waitForSelector('table[data-table="installs"] tbody tr[data-id] [data-status="running"]', { timeout: 1000 });
      await pg.waitForSelector('table[data-table="installs"] tbody tr[data-id] [data-status="isolated"]', { timeout: 2000 });
      await pg.click('#demo .drawer-x');
      await pg.waitForTimeout(1800);
      mal = (await pg.evaluate(async () => UI.api.installs({})))[0];
      ok(mal.status === 'isolated' && mal.caseId, `세션 ${mal.status}`);
      await shot(pg, '02-installs-isolated');
      await go(pg, '/');
      ok(await pendingCount(pg) === 1, `판정 대기 ${await pendingCount(pg)}`);
      await shot(pg, '03-dashboard-pending');
    });
    await step('1:15 상세 — 공격 체인 1실행 → 2파일 → 3통신 + 정적 분석 0건', async () => {
      await pg.click('[data-section="pending"] [data-case][data-source="install"]');
      await pg.waitForSelector('.sheet[data-sheet="install"] [data-part="osv"] [data-osv-count]', { timeout: 5000 });
      const steps = await pg.$$eval('.sheet [data-part="attack-chain"] .step-no', (els) => [...new Set(els.map((e) => e.textContent))]);
      ok(steps.join() === '1 실행,2 파일,3 통신', `체인 ${steps}`);
      const chain = await pg.textContent('.sheet [data-part="attack-chain"]');
      ok(chain.includes('| sh') && chain.includes('/root/.ssh/') && chain.includes(':4444'), '체인에 curl|sh · ~/.ssh · :4444 없음');
      ok((await pg.textContent('.sheet [data-part="osv"]')).includes('0건'), 'OSV 0건 아님');
      await shot(pg, '04-install-detail-chain-osv');
    });
    await step('2:15 악성 확정 → 미리보기(패키지 + 도메인 차단) → 적용', async () => {
      await pg.click('.sheet [data-part="decision"] button[aria-label="악성 확정"]');
      await confirmOk(pg); // 10/20
      await pg.waitForTimeout(300);
      await pg.click('.toast-action:has-text("제안 보기")'); // 10/16: React 와 같은 문구
      await pg.waitForSelector('[data-view="proposal"] [data-part="preview"] [data-preview-count]');
      const changes = await pg.$$eval('[data-view="proposal"] [data-change]', (els) => els.map((e) => e.dataset.change));
      ok(changes.includes('block:packages:pip:reqeusts') && changes.includes('block:hosts:cdn.reqeusts-update.test'), `변경 ${JSON.stringify(changes)}`);
      await shot(pg, '05-policy-proposal-malicious');
      await pg.click('[data-view="proposal"] button[aria-label="적용"]');
      await confirmOk(pg); // 10/20
      await pg.waitForTimeout(400);
      ok((await caseOf(pg, mal.caseId)).state === 'closed', '건이 종결되지 않음');
      await shot(pg, '06-policy-applied');
    });
    await step('2:45 다시 설치 → 컨테이너 없이 「설치 전 거부」', async () => {
      await go(pg, '/installs');
      await pg.click('.topbar button:has-text("데모 제어")');
      await pg.click('[data-demo="install-malicious"]');
      await pg.click('#demo .drawer-x');
      await pg.waitForTimeout(400);
      const r = (await pg.evaluate(async () => UI.api.installs({})))[0];
      ok(r.status === 'refused' && !r.container, `재설치 ${r.status}`);
      await pg.click('.toast:has-text("설치 전 거부") .toast-action');
      await pg.waitForSelector('.sheet[data-sheet="install"]');
      ok((await pg.textContent('.sheet[data-sheet="install"]')).includes('설치 전 거부'), '시트에 설치 전 거부 없음');
      await shot(pg, '07-installs-refused');
    });
    await step('3:00 tiny-git-dep 경고 → 오탐 → 미리보기 「과거 2건 통과로」 → 적용 → 재시도 통과', async () => {
      await pg.click('.topbar button:has-text("데모 제어")');
      await pg.click('[data-demo="install-warn"]');
      await pg.click('#demo .drawer-x');
      await pg.waitForFunction(() => UI.state.installs[0].finishedAt, null, { timeout: 6000 });
      warn = (await pg.evaluate(async () => UI.api.installs({})))[0];
      ok(warn.status === 'warned' && warn.packages[0] === 'tiny-git-dep', `세션 ${warn.status}`);
      await go(pg, `/installs?id=${warn.id}`);
      await pg.click('.sheet [data-part="decision"] button[aria-label="오탐"]');
      await confirmOk(pg); // 10/20
      await pg.waitForTimeout(300);
      await pg.click('.toast-action:has-text("제안 보기")'); // 10/16: React 와 같은 문구
      await pg.waitForSelector('[data-view="proposal"] [data-preview-count]');
      const cnt = await pg.textContent('[data-view="proposal"] [data-preview-count]');
      ok(cnt.includes('2건') && cnt.includes('통과'), `미리보기 "${cnt}"`);
      ok(await pg.locator('[data-view="proposal"] [data-part="preview"] tbody tr').count() === 2, '바뀌는 목록 2행 아님');
      await shot(pg, '08-policy-proposal-false-positive');
      await pg.click('[data-view="proposal"] button[aria-label="적용"]');
      await confirmOk(pg); // 10/20
      await pg.waitForTimeout(400);
      const again = await runInstall(pg, 'warn');
      ok(again.status === 'passed', `재시도 ${again.status}`);
    });
    await step('4:00 이벤트 — 런타임 공격이 실시간 위반으로', async () => {
      await go(pg, '/events');
      await pg.click('.topbar button:has-text("데모 제어")');
      await pg.click('[data-demo="attack"]');
      await pg.click('#demo .drawer-x');
      await pg.waitForTimeout(600);
      const names = await pg.$$eval('.feed-row .c-name', (els) => [...new Set(els.map((e) => e.textContent))]);
      ok(names.includes('pkg-reqeusts'), `행 ${JSON.stringify(names)}`);
      await pg.click('.feed-row');
      await pg.waitForSelector('.sheet[data-sheet="event"]');
      await shot(pg, '09-events-live');
    });
    await step('4:20 토폴로지 — 같은 공격 체인 · 판정 버튼', async () => {
      await pg.click('.sheet a:has-text("토폴로지에서 보기")');
      await pg.waitForTimeout(1300);
      const steps = await pg.$$eval('.topo-side [data-part="attack-chain"] .step-no', (els) => [...new Set(els.map((e) => e.textContent))]);
      ok(steps.join() === '1 실행,2 파일,3 통신', `체인 ${steps}`);
      ok(await pg.locator('.topo-side [data-part="decision"] button').count() === 2, '판정 버튼 없음');
      await shot(pg, '10-topology-chain');
    });
    await step('4:40 감사 로그 — 판정 이력 악성 1 · 오탐 1 · 처리자 · 시각', async () => {
      await go(pg, '/audit');
      await shot(pg, '11-audit-violations');
      await pg.click('[data-view-btn="history"]');
      await pg.waitForSelector('table[data-table="history"]');
      const rows = await pg.$$eval('table[data-table="history"] tbody tr', (els) => els.map((e) => e.textContent));
      const mine = rows.filter((t) => t.includes(mal.caseId) || t.includes(warn.caseId));
      ok(mine.some((t) => t.includes('악성 확정')) && mine.some((t) => t.includes('오탐')), `판정 이력 ${JSON.stringify(mine).slice(0, 200)}`);
      ok(mine.every((t) => t.includes('보안 담당자') && /\d{2}:\d{2}:\d{2}/.test(t)), '처리자 · 시각 없음');
      await shot(pg, '12-audit-history');
    });
    await pg.close();
  }

  // ---------------- 14. 무결성 ----------------
  for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) {
    await T(`14 새 화면 상태 ${vp.width}: 넘침 0`, async () => {
      const pg = await newPage(vp);
      await go(pg, '/');
      const s = await runInstall(pg, 'malicious');
      await pg.evaluate(() => UI.runAttackNow());
      const { proposal } = await decideApi(pg, s.caseId, 'malicious');
      const bad = [];
      for (const h of ['/', `/installs?id=${s.id}`, `/policies?proposal=${proposal.id}`, '/policies?id=__blocklist__', '/policies?id=blocklist-hosts', '/audit?view=changes', '/topology?container=pkg-reqeusts']) {
        await go(pg, h);
        const [sh, ch, sw, cw] = await pg.$eval('#page', (el) => [el.scrollHeight, el.clientHeight, el.scrollWidth, el.clientWidth]);
        if (sh > ch + 1 || sw > cw + 1) bad.push(`${h} ${sw}x${sh} > ${cw}x${ch}`);
      }
      ok(!bad.length, bad.join(' · '));
      await pg.close();
    });
  }

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
