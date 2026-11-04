/* 2026-10-30 시연 패널 · 격리 타임라인 · 신호등 · 보고서 — 계약 §2 · §3 · §4 · §5(공통 계약 contract-1030.md)
   ① 카드 조건: 관리자 + /api/info.demo 일 때만(조회자 · ?demo=off 면 없음) · 대시보드 맨 위(판정 대기 위) · 시나리오 6개(기본 all, 한 줄 설명)
   ② 시연 시작(shell) → 단계 레일 6단계 · 경과 · 첫 위반에 설치 시트 자동 열림(#/installs?id=) · 결과 「격리됨 — 규칙 N개 · 0.xx초」 · 다시 실행
   ③ 모의 API: GET /api/demo(scenarios · running · last) · POST 400 · 409 · 거부(차단 목록 → refused) · 변경 이력 demo_run
   ④ 타임라인: 설치 시트 결과 칸 · 토폴로지 판정 카드 막대(구간 4 + ms + 「격리까지 N.NN초」) · Verdict.timeline · InstallSession.isolation · Case.isolation
   ⑤ 종합 「격리 지연 중앙값」: 기간 안 격리 없으면 「—」 · 있으면 N ms(p95 · 최대 · 건수)
   ⑥ 신호등 5개(가젯 · 도메인 판단 · 자동 격리 · 알림 · 라이선스) 색 · 문구 · 누르면 #/settings(라이선스 탭) · 키보드
   ⑦ 보고서 #/report?install= · ?case= · 내용 순서 고정 · 인쇄 · Markdown 복사 · 조회자도 읽기 · 진입 3곳(설치 시트 · 토폴로지 판정 카드 · 판정 대기 행 메뉴)
   실행: BASE=http://127.0.0.1:8767 PLAYWRIGHT=<playwright 경로> node tests/demo-1030.cjs   (VERBOSE=1 · ONLY) */
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = (process.env.BASE || 'http://127.0.0.1:8767').replace(/\/index\.html$/, '').replace(/\/$/, '') + '/index.html';
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const W = { timeout: 6000 };
const DEMO = '[data-section="demo"]';
const SECTIONS = ['summary', 'timeline', 'violations', 'evidence', 'decision', 'changes', 'meta'];

(async () => {
  const br = await chromium.launch();
  const newPage = async (vp) => {
    const pg = await br.newPage({ viewport: vp || { width: 1440, height: 900 } });
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash, extra, as) => { await pg.goto(`${BASE}?source=sim&as=${as || 'admin'}${extra || ''}#${hash}`); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(450); };
  const hash = (pg) => pg.evaluate(() => location.hash);
  const runMalicious = async (pg) => { const id = await pg.evaluate(() => UI.runInstallDemo('malicious')); await pg.waitForTimeout(2600); return pg.evaluate((x) => UI.state.installs.find((s) => s.id === x), id); };
  const confirmOk = async (pg) => { await pg.waitForSelector('dialog[data-part="confirm"] [data-confirm="ok"]', W); await pg.waitForTimeout(150); await pg.click('dialog[data-part="confirm"] [data-confirm="ok"]'); await pg.waitForTimeout(300); };

  // ① 카드 조건 · 자리 · 시나리오
  await T('① 시연 카드: 관리자 + demo 일 때 대시보드 맨 위(판정 대기 위) · 조회자 · ?demo=off 면 없음 · 시나리오 6개(기본 all) 설명 한 줄 · 신호등은 카드 위 한 줄', async () => {
    const pg = await newPage();
    await go(pg, '/');
    ok(await pg.locator(DEMO).count() === 1, '카드 없음');
    const [d, p, s] = await Promise.all([pg.$eval(DEMO, (e) => e.getBoundingClientRect().top), pg.$eval('[data-section="pending"]', (e) => e.getBoundingClientRect().top), pg.$eval('[data-part="signals"]', (e) => e.getBoundingClientRect().top)]);
    ok(d < s && s < p, `자리 시연 ${d} < 신호등 ${s} < 판정 대기 ${p}`); // 11/04e 대시보드 재배치: 신호등은 종합 머리 줄(KPI 위), 판정 대기는 아래 3칸 — 시연 카드는 그 위(B 커밋에서 시연 페이지로 옮김)
    ok((await pg.textContent(`${DEMO} .panel-head h2`)).trim() === '시연', '제목');
    const opts = await pg.$$eval(`${DEMO} [data-part="demo-scenario"] option`, (els) => els.map((e) => [e.value, e.textContent, e.selected]));
    ok(JSON.stringify(opts.map((o) => o[0])) === JSON.stringify(['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil']), `시나리오 ${JSON.stringify(opts)}`);
    ok(opts[0][2] === true, '기본 all 아님');
    const want = { shell: '외부 스크립트 실행 + 비밀 파일 접근', revshell: '리버스 셸 포트 4444', 'direct-ip': 'DNS 없이 공인 IP 접속', domain: '예약 도메인 example.com 접속', 'dns-exfil': 'DNS 질의로 데이터 실어 보내기', all: '전부 순서대로' };
    for (const [k, t] of opts) ok(t.includes(want[k]), `설명 ${k}: ${t}`);
    ok(await pg.locator(`${DEMO} [data-action="demo-start"]`).count() === 1 && (await pg.textContent(`${DEMO} [data-action="demo-start"]`)).includes('시연 시작'), '시작 버튼');
    // 11/02 React 맞춤: 「시나리오」 라벨 · 선택 옆 설명 · 버튼은 줄 오른쪽 끝
    ok((await pg.textContent(`${DEMO} label[data-part="demo-label"]`)).includes('시나리오') && (await pg.textContent(`${DEMO} [data-part="demo-desc"]`)).trim() === '전부 순서대로', '라벨 · 설명');
    await pg.selectOption(`${DEMO} [data-part="demo-scenario"]`, 'revshell'); ok((await pg.textContent(`${DEMO} [data-part="demo-desc"]`)).trim() === '리버스 셸 포트 4444', '설명이 선택을 따라가지 않음'); await pg.selectOption(`${DEMO} [data-part="demo-scenario"]`, 'all');
    { const [btn, head] = await Promise.all([pg.$eval(`${DEMO} [data-action="demo-start"]`, (e) => e.getBoundingClientRect().right), pg.$eval(`${DEMO} .panel-head`, (e) => e.getBoundingClientRect().right)]); ok(head - btn <= 24, `버튼이 오른쪽 끝이 아님 ${btn} / ${head}`); }
    ok(await pg.$eval(`${DEMO} .demo-body`, (e) => e.hidden), '실행 전인데 본문이 보임');
    const p2 = await newPage(); await go(p2, '/', '&demo=off'); ok(await p2.locator(DEMO).count() === 0, '?demo=off 인데 카드'); await p2.close();
    const p3 = await newPage(); await go(p3, '/', '', 'viewer'); ok(await p3.locator(DEMO).count() === 0, '조회자인데 카드'); ok(await p3.locator('[data-part="signals"]').count() === 1, '조회자 신호등 없음'); await p3.close();
    const o = await pg.evaluate(() => { const p = document.querySelector('#page'); return [p.scrollHeight - p.clientHeight, p.scrollWidth - p.clientWidth]; });
    ok(o.every((x) => x <= 1), `1440 대시보드 넘침 ${JSON.stringify(o)}`);
    await pg.close();
  });

  // ② 시연 실행 흐름
  await T('② 시연 시작(shell): 레일 6단계 · 경과 · 첫 위반에 설치 시트 자동 열림 · 돌아오면 결과 「격리됨 — 규칙 N개 · 0.xx초」 + 타임라인 + 「다시 실행」 · 설치 세션 라벨 pip ./reqeusts · 컨테이너 sg-install-demo-*', async () => {
    const pg = await newPage();
    await go(pg, '/');
    await pg.selectOption(`${DEMO} [data-part="demo-scenario"]`, 'shell');
    await pg.click(`${DEMO} [data-action="demo-start"]`); await pg.waitForTimeout(300);
    ok(await pg.$eval(`${DEMO} [data-action="demo-start"]`, (e) => e.disabled), '실행 중인데 시작 버튼 활성');
    const rail = await pg.$$eval(`${DEMO} [data-part="demo-rail"] li`, (els) => els.map((e) => [e.dataset.step, e.querySelector('.rail-label').textContent, e.dataset.state]));
    ok(rail.length === 6 && JSON.stringify(rail.map((r) => r[1])) === JSON.stringify(['컨테이너 시작', '설치 진행', '커널 이벤트 수집', '규칙 위반', '격리 · 증거', '판정 대기']), `레일 ${JSON.stringify(rail)}`);
    ok(rail[0][2] === 'done' && rail.some((r) => r[2] === 'active'), `단계 상태 ${JSON.stringify(rail.map((r) => r[2]))}`);
    ok(/^실행 중 · \d+초 경과$/.test((await pg.textContent(`${DEMO} [data-part="demo-elapsed"]`)).trim()), '경과'); // 11/02 React 문구
    ok((await pg.textContent(`${DEMO} [data-action="demo-start"]`)).includes('실행 중…'), '실행 중 버튼 문구');
    ok((await pg.textContent(`${DEMO} .demo-meta`)).includes('sg-install-demo-'), '컨테이너 이름');
    // 첫 위반 → 설치 시트 자동 열림
    await pg.waitForFunction(() => /^#\/installs\?id=ins-/.test(location.hash), null, W);
    await pg.waitForSelector('.sheet[data-sheet="install"]', W);
    ok((await pg.textContent('.sheet[data-sheet="install"] .panel-head h2')).trim() === 'pip ./reqeusts', '시트 제목');
    await pg.waitForTimeout(1500);
    await pg.waitForSelector('.sheet [data-part="timeline"]', W);
    ok(await pg.$eval('.sheet [data-part="result"] [data-status]', (e) => e.dataset.status) === 'isolated', '세션 격리 아님');
    // 대시보드로 돌아오면 결과
    await pg.evaluate(() => UI.go('#/')); await pg.waitForTimeout(600);
    await pg.waitForSelector(`${DEMO} [data-part="demo-result"]`, W);
    const res = await pg.$eval(`${DEMO} [data-part="demo-result"]`, (e) => [e.dataset.outcome, e.textContent.trim()]); // 11/02: React 처럼 결과는 한 줄 문구
    ok(res[0] === 'isolated' && /^격리됨 — 규칙 \d+개 · \d+\.\d{2}초$/.test(res[1]), `결과 ${JSON.stringify(res)}`);
    const states = await pg.$$eval(`${DEMO} [data-part="demo-rail"] li`, (els) => els.map((e) => e.dataset.state));
    ok(states.every((s) => s === 'done'), `끝난 뒤 레일 ${JSON.stringify(states)}`);
    ok(await pg.locator(`${DEMO} [data-part="timeline"]`).count() === 1, '⑤ 타임라인 막대 없음');
    ok((await pg.textContent(`${DEMO} [data-action="demo-start"]`)).includes('다시 실행') && !(await pg.$eval(`${DEMO} [data-action="demo-start"]`, (e) => e.disabled)) && await pg.locator(`${DEMO} [data-action="demo-again"]`).count() === 0, '다시 실행은 시작 버튼 자리'); // 11/02 React 맞춤
    ok(/^\d+초 걸림$/.test((await pg.textContent(`${DEMO} [data-part="demo-elapsed"]`)).trim()), '걸린 시간');
    ok((await pg.$eval(`${DEMO} [data-action="demo-install"]`, (e) => e.getAttribute('href'))).startsWith('#/installs?id=ins-'), '설치 검사에서 보기 링크');
    const run = await pg.evaluate(async () => (await UI.api.demo()).last);
    ok(run && run.status === 'finished' && run.exitCode === 137 && run.simulated === true && run.scenario === 'shell' && /^demo-\d+$/.test(run.id) && run.container === `sg-install-${run.id}` && run.installId && run.finishedAt, `Run ${JSON.stringify(run)}`);
    ok(await pg.textContent('[data-pending-count]') === '1', '판정 대기 1 아님');
    await pg.close();
  });

  // ③ 모의 API
  await T('③ 모의 API: GET /api/demo 모양 · POST 400(scenario 문구) · 409(실행 중) · 차단 목록이면 refused + 안내 · 변경 이력 demo_run 「시연 실행: <scenario>」 · dns-exfil 은 격리(11/03 sandbox-dns dryRun 해제)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const d = await pg.evaluate(() => UI.api.demo());
    ok(d.enabled === true && JSON.stringify(d.scenarios) === JSON.stringify(['all', 'shell', 'revshell', 'direct-ip', 'domain', 'dns-exfil']) && d.running === null && d.last === null, `GET ${JSON.stringify(d)}`);
    const e400 = await pg.evaluate(() => UI.api.demoRun({ scenario: 'nope' }).then(() => null, (e) => [e.status, e.message]));
    ok(e400 && e400[0] === 400 && e400[1].includes('scenario: all | shell | revshell | direct-ip | domain | dns-exfil'), `400 ${JSON.stringify(e400)}`);
    const first = await pg.evaluate(() => UI.api.demoRun({ scenario: 'dns-exfil' }));
    ok(first.status === 'running' && first.installId, `202 ${JSON.stringify(first)}`);
    const e409 = await pg.evaluate(() => UI.api.demoRun({ scenario: 'shell' }).then(() => null, (e) => [e.status, e.message, !!e.running]));
    ok(e409 && e409[0] === 409 && e409[1].includes('시연이 이미 실행 중입니다') && e409[2], `409 ${JSON.stringify(e409)}`);
    await pg.waitForFunction(() => !UI.srv.demo.running, null, W); // Playwright 의 waitForFunction 은 Promise 를 기다리지 않는다 — 모의 서버 상태를 바로 본다
    const after = await pg.evaluate(async () => { const x = await UI.api.demo(); const s = await UI.api.install(x.last.installId); return { status: x.last.status, exit: x.last.exitCode, session: s.status, viol: s.violations.map((v) => [v.ruleId, v.dryRun]), chg: (await UI.api.changes({ limit: 20 })).filter((c) => c.kind === 'demo_run').map((c) => c.summary) }; });
    ok(after.status === 'finished' && after.exit === 137 && after.session === 'isolated' && after.viol.length === 1 && after.viol.every(([r, dry]) => r === 'sandbox-dns' && !dry), `dns-exfil ${JSON.stringify(after)}`); // 11/04: sandbox-dns dryRun 해제 — 첫 질의에서 격리
    ok(after.chg.includes('시연 실행: dns-exfil'), `변경 이력 ${JSON.stringify(after.chg)}`);
    // 차단 목록 → refused
    const s = await runMalicious(pg);
    await pg.evaluate(async (cid) => { const { proposal } = await UI.api.decide(cid, { decision: 'malicious', note: '' }); await UI.api.apply(proposal.id, { reason: '' }); }, s.caseId);
    await pg.waitForTimeout(300);
    const refused = await pg.evaluate(() => UI.api.demoRun({ scenario: 'all' }));
    ok(refused.status === 'refused' && refused.exitCode === 3 && refused.installId, `refused ${JSON.stringify(refused)}`);
    await pg.evaluate(() => UI.go('#/')); await pg.waitForTimeout(700);
    const res = await pg.$eval(`${DEMO} [data-part="demo-result"]`, (e) => [e.dataset.outcome, e.textContent]);
    ok(res[0] === 'refused' && res[1].includes('거부됨(차단 목록)') && res[1].includes('차단 목록에 있어 설치 전 거부됨, 차단 해제 후 다시'), `거부 안내 ${JSON.stringify(res)}`);
    await pg.close();
  });

  // ④ 타임라인
  await T('④ 타임라인: Verdict.timeline · 세션 isolation{auditId, timeline} · 설치 시트 막대(구간 4 · ms 라벨 · 합계) · 런타임 건 isolation + 토폴로지 판정 카드 막대 · 감사 행 timeline', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runMalicious(pg);
    ok(s.isolation && s.isolation.auditId && s.isolation.timeline && s.isolation.timeline.detectedAt && s.isolation.timeline.killedAt, `isolation ${JSON.stringify(s.isolation)}`);
    const tl = s.isolation.timeline;
    const total = Date.parse(tl.killedAt) - Date.parse(tl.detectedAt);
    ok(total > 0 && Date.parse(tl.matchedAt) >= Date.parse(tl.detectedAt) && Date.parse(tl.evidenceDoneAt) >= Date.parse(tl.evidenceStartedAt) && Date.parse(tl.notifiedAt) >= Date.parse(tl.killedAt), '시각 순서');
    const row = await pg.evaluate((id) => UI.state.audit.find((a) => a.id === id), s.isolation.auditId);
    ok(row && row.timeline && row.timeline.killedAt === tl.killedAt && row.enforced, '감사 행 timeline');
    await pg.evaluate((x) => UI.go(`#/installs?id=${x}`, { status: 'all' }), s.id); await pg.waitForSelector('.sheet [data-part="timeline"]', W);
    const bar = await pg.$eval('.sheet [data-part="result"] [data-part="timeline"]', (e) => ({ total: e.dataset.totalMs, segs: [...e.querySelectorAll('.tl-legend [data-seg]')].map((x) => [x.dataset.seg, x.textContent.trim()]), bars: [...e.querySelectorAll('.tl-bar [data-seg]')].length, totalText: e.querySelector('[data-part="timeline-total"]').textContent }));
    ok(Number(bar.total) === total && bar.bars === 4, `막대 ${JSON.stringify(bar)}`);
    ok(JSON.stringify(bar.segs.map((x) => x[0])) === JSON.stringify(['match', 'evidence', 'kill', 'notify']) && bar.segs.every((x) => /\d+ ms$/.test(x[1])), `구간 ${JSON.stringify(bar.segs)}`);
    ok(bar.totalText === `격리까지 ${(total / 1000).toFixed(2)}초`, `합계 ${bar.totalText}`);
    ok(bar.segs[0][1].startsWith('탐지→판정') && bar.segs[1][1].startsWith('증거') && bar.segs[2][1].startsWith('격리') && bar.segs[3][1].startsWith('알림'), '구간 이름');
    // 런타임 건
    await go(pg, '/topology');
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(1200);
    const c = await pg.evaluate(() => UI.state.cases.find((x) => x.source === 'runtime' && x.container === 'pkg-reqeusts'));
    ok(c && c.isolation && c.isolation.timeline && c.isolation.auditId, `런타임 건 isolation ${JSON.stringify(c && c.isolation)}`);
    await pg.click('.topo-side .chain-head'); await pg.waitForTimeout(400);
    ok(await pg.locator('.topo-side .case-card [data-part="timeline"]').count() === 1, '판정 카드 막대 없음');
    ok(/격리까지 \d+\.\d{2}초/.test(await pg.textContent('.topo-side .case-card [data-part="timeline-total"]')), '판정 카드 합계');
    // 없는 구간은 「—」
    const dash = await pg.evaluate(() => { const el = UI.timelineBar({ detectedAt: '2026-10-30T00:00:00.000Z', matchedAt: '2026-10-30T00:00:00.004Z', killedAt: '2026-10-30T00:00:00.050Z' }); return [...el.querySelectorAll('.tl-legend [data-seg]')].map((x) => x.textContent.trim()); });
    ok(dash[1].endsWith('—') && dash[3].endsWith('—') && dash[2].endsWith('46 ms'), `없는 구간 ${JSON.stringify(dash)}`);
    await pg.close();
  });

  // ⑤ 종합 중앙값
  await T('⑤ 종합 「격리 지연 중앙값」: 격리 없으면 「—」(?fresh=1) · 24시간 안 격리가 생기면 N ms(p95 · 최대 · 건수) · 7일엔 시드 격리 2건', async () => {
    const pg = await newPage();
    await go(pg, '/', '&fresh=1');
    // 11/04e KPI 카드: 단위(ms)는 값과 따로(.kpi-unit) — 값 + 단위를 이어 읽는다
    const k = (p) => p.$eval('[data-section="overview"] [data-kpi="isolation"]', (e) => [e.querySelector('[data-value]').textContent + (e.querySelector('.kpi-unit') ? ` ${e.querySelector('.kpi-unit').textContent}` : ''), e.dataset.count, e.querySelector('span:last-child').textContent]);
    const a = await k(pg);
    ok(a[0] === '—' && a[1] === '0', `빈 서버 ${JSON.stringify(a)}`);
    ok((await pg.textContent('[data-section="overview"] [data-kpi="isolation"] span')).includes('격리 지연 중앙값'), '라벨');
    await pg.close();
    const p2 = await newPage();
    await go(p2, '/');
    const b = await k(p2);
    ok(b[0] === '—' && b[1] === '0', `24시간(시드 격리는 어제) ${JSON.stringify(b)}`);
    await p2.click('[data-section="overview"] [data-range="7d"]'); await p2.waitForTimeout(400);
    const c = await k(p2);
    ok(/^\d+ ms$/.test(c[0]) && c[1] === '2' && /p95 \d+ ms · 최대 \d+ ms · 격리 2건/.test(c[2]), `7일 ${JSON.stringify(c)}`);
    await p2.click('[data-section="overview"] [data-range="24h"]'); await p2.waitForTimeout(300);
    await p2.evaluate(() => UI.runAttackNow()); await p2.waitForTimeout(1500);
    const d = await k(p2);
    ok(/^\d+ ms$/.test(d[0]) && Number(d[1]) >= 1, `격리 뒤 ${JSON.stringify(d)}`);
    const sum = await p2.evaluate(() => UI.api.summary('24h'));
    ok(sum.isolation && sum.isolation.count >= 1 && sum.isolation.medianMs > 0 && sum.isolation.p95Ms >= sum.isolation.medianMs && sum.isolation.maxMs >= sum.isolation.p95Ms, `summary.isolation ${JSON.stringify(sum.isolation)}`);
    await p2.close();
  });

  // ⑥ 신호등
  await T('⑥ 신호등 5개: 기본(모의 이벤트 노랑 · 나머지 초록) · ?dns=off&notify=fail&license=soon(노랑 · 빨강 · 노랑) · ?notify=off(미설정) · ?license=expired(만료 빨강) · 누르면 설정(라이선스 탭) · 키보드', async () => {
    const pg = await newPage();
    // 11/02 React 맞춤: 알약 하나에 「이름 · 값」 한 문구(SignalPills.tsx 와 같은 글자)
    const read = (p) => p.$$eval('[data-part="signals"] [data-signal]', (els) => els.map((e) => [e.dataset.signal, e.dataset.tone, e.textContent.trim(), e.tagName]));
    await go(pg, '/'); await pg.waitForTimeout(300);
    const a = await read(pg);
    ok(JSON.stringify(a.map((x) => x[0])) === JSON.stringify(['gadget', 'dns', 'kill', 'notify', 'license']), `순서 ${JSON.stringify(a)}`);
    ok(a[0][1] === 'warn' && a[0][2] === '가젯 · 모의 이벤트' && a[1][1] === 'ok' && a[1][2] === '도메인 판단 켜짐' && a[2][1] === 'ok' && a[2][2] === '자동 격리 켜짐' && a[3][1] === 'ok' && /^알림 · 채널 \d+$/.test(a[3][2]) && a[4][1] === 'ok' && /^라이선스 · \d+일 남음$/.test(a[4][2]), `기본 ${JSON.stringify(a)}`);
    ok(a.every((x) => x[3] === 'BUTTON'), '키보드로 못 누름');
    const p2 = await newPage(); await go(p2, '/', '&dns=off&notify=fail&license=soon'); await p2.waitForTimeout(300);
    const b = await read(p2);
    ok(b[1][1] === 'warn' && b[1][2] === '도메인 판단 · 통과 처리' && b[3][1] === 'danger' && b[3][2] === '알림 · 실패 3건' && b[4][1] === 'warn' && /^라이선스 · 2\d일 남음$/.test(b[4][2]), `경고 ${JSON.stringify(b)}`);
    await p2.close();
    const p3 = await newPage(); await go(p3, '/', '&notify=off&license=expired'); await p3.waitForTimeout(300);
    const c = await read(p3);
    ok(c[3][1] === 'warn' && c[3][2] === '알림 · 미설정' && c[4][1] === 'danger' && c[4][2] === '라이선스 만료', `미설정 · 만료 ${JSON.stringify(c)}`);
    // 자동 격리 끄면 노랑 「알림만」
    await p3.evaluate(() => { UI.state.info.enforceKill = false; UI.emit(); }); await p3.waitForTimeout(400);
    ok((await read(p3))[2].slice(1, 3).join('|') === 'warn|자동 격리 · 알림만', '자동 격리 꺼짐');
    await p3.close();
    await pg.focus('[data-signal="license"]'); await pg.keyboard.press('Enter'); await pg.waitForTimeout(400);
    ok(await hash(pg) === '#/settings?tab=license', `라이선스 → ${await hash(pg)}`);
    await go(pg, '/'); await pg.click('[data-signal="dns"]'); await pg.waitForTimeout(300);
    ok(await hash(pg) === '#/settings', `도메인 판단 → ${await hash(pg)}`);
    await pg.close();
  });

  // ⑦ 보고서
  await T('⑦ 보고서: #/report?install= · ?case= 내용 순서 고정 · 인쇄 · Markdown 복사(제목 · 7절) · 조회자도 읽기 · 진입 3곳(설치 시트 · 토폴로지 판정 카드 · 판정 대기 행 메뉴)', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const s = await runMalicious(pg);
    await pg.evaluate((x) => UI.go(`#/installs?id=${x}`, { status: 'all' }), s.id); await pg.waitForSelector('.sheet[data-sheet="install"]', W);
    const href = await pg.getAttribute('.sheet [data-action="report"]', 'href');
    ok(href === `#/report?install=${s.id}`, `설치 시트 진입 ${href}`);
    await pg.click('.sheet [data-action="report"]'); await pg.waitForSelector('[data-part="report"]', W);
    ok(await hash(pg) === `#/report?install=${s.id}`, `주소 ${await hash(pg)}`);
    ok(await pg.textContent('.page-title') === '보고서', '화면 이름');
    const secs = await pg.$$eval('[data-part="report"] [data-sec]', (els) => els.map((e) => e.dataset.sec));
    ok(JSON.stringify(secs) === JSON.stringify(SECTIONS), `순서 ${JSON.stringify(secs)}`);
    const heads = await pg.$$eval('[data-part="report"] h2', (els) => els.map((e) => e.textContent));
    ok(heads[0] === '요약' && heads[1] === '격리 타임라인' && /^위반 \d+건$/.test(heads[2]) && heads[3] === '증거 요약' && heads[4] === '판정' && heads[5] === '정책 변경 · 차단 목록', `절 제목 ${JSON.stringify(heads)}`);
    ok((await pg.textContent('[data-part="report"] h1')) === 'pip ./reqeusts', '제목');
    ok(await pg.locator('[data-part="report"] .report-chips .src-chip').count() === 1 && await pg.locator('[data-part="report"] .report-chips [data-status="isolated"]').count() === 1, '출처 칩 · 상태');
    const sum = await pg.$$eval('[data-part="report"] [data-sec="summary"] li', (els) => els.map((e) => e.children[0].textContent));
    ok(JSON.stringify(sum) === JSON.stringify(['무엇이', '언제', '어떤 규칙']), `요약 3줄 ${JSON.stringify(sum)}`);
    ok(await pg.locator('[data-part="report"] [data-sec="timeline"] [data-part="timeline"]').count() === 1, '타임라인 막대');
    const cols = await pg.$$eval('[data-part="report"] [data-sec="violations"] th', (els) => els.map((e) => e.textContent));
    ok(JSON.stringify(cols) === JSON.stringify(['시각', '종류', '규칙', '상세', '판정']) && (await pg.locator('[data-part="report"] [data-sec="violations"] tbody tr').count()) >= 5, `위반 표 ${JSON.stringify(cols)}`);
    ok(/로그 \d+줄 · 파일 변경 \d+ · 프로세스 \d+/.test(await pg.textContent('[data-part="report"] [data-sec="evidence"]')) && (await pg.locator('[data-part="report"] [data-part="evidence-partial"]').count()) === 1, '증거 요약 · partial');
    ok((await pg.textContent('[data-part="report"] [data-sec="decision"]')).includes('판정 대기'), '판정 대기');
    ok(/작성 \d{2}\. \d{2}\. \d{2}:\d{2}:\d{2}/.test(await pg.textContent('[data-part="report"] [data-sec="meta"]')) && (await pg.textContent('[data-part="report"] [data-sec="meta"]')).includes('작성자 보안 담당자'), '작성 시각 · 작성자');
    ok(await pg.locator('.page-actions [data-action="print"]').count() === 1 && await pg.locator('.page-actions [data-action="copy-md"]').count() === 1, '인쇄 · 복사 버튼');
    await pg.evaluate(() => { window.__printed = 0; window.print = () => { window.__printed++; }; });
    await pg.click('.page-actions [data-action="print"]');
    ok(await pg.evaluate(() => window.__printed) === 1, 'window.print 호출 안 됨');
    const md = await pg.$eval('.report-wrap', (e) => e.dataset.markdown);
    ok(md.startsWith('# pip ./reqeusts — 설치 검사 · 격리') && ['## 요약', '## 격리 타임라인', /## 위반 \d+건/, '## 증거 요약', '## 판정', '## 정책 변경 · 차단 목록', '작성 '].every((k) => (k instanceof RegExp ? k.test(md) : md.includes(k))), `Markdown\n${md.slice(0, 400)}`);
    ok(md.indexOf('## 요약') < md.indexOf('## 격리 타임라인') && md.indexOf('## 격리 타임라인') < md.indexOf('## 위반') && md.indexOf('## 위반') < md.indexOf('## 증거 요약') && md.indexOf('## 증거 요약') < md.indexOf('## 판정') && md.indexOf('## 판정') < md.indexOf('## 정책 변경'), 'Markdown 순서');
    ok(/\| 시각 \| 종류 \| 규칙 \| 상세 \| 판정 \|/.test(md) && /격리까지: \d+\.\d{2}초/.test(md), 'Markdown 표 · 타임라인');
    await pg.evaluate(() => { window.__copied = ''; navigator.clipboard.writeText = (t) => { window.__copied = t; return Promise.resolve(); }; });
    await pg.click('.page-actions [data-action="copy-md"]'); await pg.waitForTimeout(200);
    ok(await pg.evaluate(() => window.__copied) === md && (await pg.textContent('#toasts')).includes('Markdown 으로 복사'), '복사 안 됨');
    // 판정 뒤 건 경로 + 정책 변경 절
    await pg.evaluate(async (cid) => { const { proposal } = await UI.api.decide(cid, { decision: 'malicious', note: '타이포스쿼팅' }); await UI.api.apply(proposal.id, { reason: '이름이 한 글자 다름' }); }, s.caseId);
    await go(pg, `/report?case=${s.caseId}`); await pg.waitForSelector('[data-part="report"]', W);
    ok(await hash(pg) === `#/report?case=${s.caseId}`, `건 주소 ${await hash(pg)}`);
    const dec = await pg.textContent('[data-part="report"] [data-sec="decision"]');
    ok(dec.includes('악성') && dec.includes('보안 담당자') && dec.includes('메모 「타이포스쿼팅」') && dec.includes('종결'), `판정 절 ${dec}`);
    const ch = await pg.textContent('[data-part="report"] [data-sec="changes"]');
    ok(ch.includes('적용됨') && ch.includes('패키지 차단 pip:reqeusts') && ch.includes('제안 적용') && ch.includes('사유 「이름이 한 글자 다름」'), `정책 변경 절 ${ch}`);
    // 런타임 건 → 토폴로지 판정 카드 진입 · 대시보드 행 메뉴 진입 · 조회자 읽기
    await go(pg, '/topology'); await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(1200);
    await pg.click('.topo-side .chain-head'); await pg.waitForTimeout(300);
    const rc = await pg.evaluate(() => UI.state.cases.find((x) => x.source === 'runtime' && x.state === 'open').id);
    ok(await pg.getAttribute('.topo-side .case-card [data-action="report"]', 'href') === `#/report?case=${rc}`, '토폴로지 판정 카드 진입');
    await go(pg, '/');
    await pg.click(`[data-case="${rc}"] ~ .menu-anchor [data-action="row-menu"]`).catch(() => pg.click('.pending-row [data-action="row-menu"]')); await pg.waitForTimeout(200);
    const menuHref = await pg.getAttribute('.pending-row .row-menu:not([hidden]) [data-menu="report"]', 'href');
    ok(menuHref && menuHref.startsWith('#/report?case=case-'), `행 메뉴 진입 ${menuHref}`);
    await pg.click('.pending-row .row-menu:not([hidden]) [data-menu="report"]'); await pg.waitForSelector('[data-part="report"]', W);
    ok((await pg.textContent('[data-part="report"] h1')) === 'pkg-reqeusts' && (await pg.textContent('[data-part="report"] .report-chips')).includes('런타임'), '런타임 건 보고서');
    // 조회자 읽기 — 새 페이지는 모의 서버 상태가 처음으로 돌아가므로 시드 건(어제 격리 · 악성 판정 · 적용된 case-0001)으로 본다
    const pv = await newPage(); await go(pv, '/report?case=case-0001', '', 'viewer'); await pv.waitForSelector('[data-part="report"]', W);
    ok(/^(pip|npm) /.test(await pv.textContent('[data-part="report"] h1')) && (await pv.locator('[data-part="report"] button').count()) === 0 && (await pv.textContent('[data-part="report"] [data-sec="decision"]')).includes('악성'), '조회자 읽기');
    ok(await pv.locator('.page-actions [data-action="copy-md"]').count() === 1 && await pv.locator('.page-actions [data-action="print"]').count() === 1, '조회자도 인쇄 · 복사');
    await pv.close();
    await pg.close();
  });

  // ⑧ 넘침 · 1280
  await T('⑧ 1280 × 800 대시보드(시연 카드 · 신호등 포함) · 보고서 · 시연 끝난 대시보드 넘침 0', async () => {
    const pg = await newPage({ width: 1280, height: 800 });
    await go(pg, '/');
    const o = (p) => p.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'), pg = document.querySelector('#page'); return [d.scrollWidth - innerWidth, m.scrollWidth - m.clientWidth, pg.scrollWidth - pg.clientWidth, pg.scrollHeight - pg.clientHeight]; });
    ok((await o(pg)).every((x) => x <= 1), `대시보드 넘침 ${JSON.stringify(await o(pg))}`);
    const s = await runMalicious(pg);
    await go(pg, `/report?install=${s.id}`); await pg.waitForSelector('[data-part="report"]', W);
    const r = await o(pg); ok(r[0] <= 0 && r[1] <= 0 && r[2] <= 1, `보고서 가로 넘침 ${JSON.stringify(r)}`);
    await pg.close();
  });

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
