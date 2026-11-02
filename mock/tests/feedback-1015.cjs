/* 10/15 개인 피드백 회귀 — 목업 개편(두 시나리오 동등 · 「설치 검사」 화면 신설)
   1 사이드바는 시나리오별 묶음: 대시보드 / 설치 검사 / 런타임 감시(이벤트 · 토폴로지) / 설정 · 기록(정책 · 감사 로그)
   2 상단 「1 관찰 … 5 감사」 단계 칩은 없고, 그 자리에 화면 이름
   3 대시보드: 설치 검사 · 런타임 감시 나란히, 위험 점수 대신 「조치 필요」, 분당 위반 막대, 피드는 위반만
   4 설치 검사: 목록 표 + 결과 · 매니저 필터 칩 + 오른쪽 상세 시트(?id=) — 공격 체인 · 활동 요약(도메인 · 프로그램 · 종류별 횟수)
   5 「확인함」을 누르면 조치 필요가 1 줄고, 토스트 「되돌리기」로 돌아온다
   6 세션이 하나도 없으면 빈 상태에 CLI 명령 복사 버튼(?fresh=1)
   7 끝 보고가 없는 세션은 「결과 미확인」
   8 데모 제어 「설치 검사 실행」(악성) → 새 세션이 맨 위에 「격리」로
   9 격리 토스트는 같은 컨테이너끼리 묶이고(×N) 8초 뒤 닫힌다
   10 이벤트: 기본 위반만(정상은 토글), 행 상세는 오른쪽 시트(?id=), 한글 라벨
   11 감사 로그: 페이지는 고정 · 표만 스크롤, 사유 열 없음, 컨테이너 칸 1줄, 설치 검사 위반은 패키지 이름
   12 정책: 첫 정책 자동 선택(?id=), 적용 범위 칩, 관리자 토큰은 화면 머리
   13 실제 백엔드 모드의 설치 검사는 실제 API(GET /api/installs)로 뜬다 — 10/21 React 맞춤(전: 「백엔드 미지원」 안내). API=http://127.0.0.1:8011 처럼 백엔드가 있을 때만
   14 무결성: 전 화면 × 1440 · 1280에서 페이지 넘침 0 · 콘솔 오류 0, 토폴로지 공격 체인 유지
   10/15 목표(2차, tests/goals-1015.cjs)로 바뀐 기대: 3 대시보드 구성 · 5 확인함 → 판정 · 4/7 설치 검사 기본 필터 판정 대기 · 10 자동 공격 꺼짐.
   설치 시트가 OSV(api.osv.dev)를 부르므로 page.route 로 응답을 고정한다(네트워크에 기대지 않음)
   실행: (mock/ 에서) python3 -m http.server 8766 → PLAYWRIGHT=<playwright 경로> node tests/feedback-1015.cjs   (VERBOSE=1 · ONLY=정규식 · BASE=주소)
   13번은 make backend(:8000)가 떠 있을 때만 돈다 */
const PW = process.env.PLAYWRIGHT || 'playwright';
const { chromium } = require(PW);
const { splitHash, goState } = require('./nav-state.cjs'); // 10/21b: 필터는 주소 대신 상태로
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const API = process.env.API || 'http://127.0.0.1:8000';
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const ROUTES = ['/', '/installs', '/events', '/topology', '/policies', '/audit'];
const TITLES = { '/': '대시보드', '/installs': '설치 검사', '/events': '이벤트', '/topology': '토폴로지', '/policies': '정책', '/audit': '감사 로그' };

(async () => {
  const br = await chromium.launch();
  const newPage = async (viewport = { width: 1440, height: 900 }) => {
    const pg = await br.newPage({ viewport });
    // 10/15 목표: 설치 시트의 정적 분석 비교가 osv.dev 를 부른다 — 고정 응답(0건)
    await pg.route('https://api.osv.dev/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash, search = '') => { await pg.goto(`${BASE}${search ? search + '&' : '?'}as=admin#${splitHash(hash)[0]}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); if (splitHash(hash)[1]) await goState(pg, hash, 0); await pg.waitForTimeout(400); }; // 10/20: 로그인 건너뜀(?as=admin) // 10/21b
  const pendingNum = (pg) => pg.$eval('[data-pending-count]', (el) => Number(el.textContent.replace(/[^\d]/g, '')));
  const pg = await newPage();

  // ---------------- 1. 사이드바 묶음 ----------------
  await T('1 사이드바: 묶음 제목 3개와 메뉴 순서', async () => {
    await go(pg, '/');
    const groups = await pg.$$eval('.nav-group-title', (els) => els.map((e) => e.textContent.trim()));
    ok(JSON.stringify(groups) === JSON.stringify(['설치 검사', '런타임 감시', '설정 · 기록']), `묶음 ${JSON.stringify(groups)}`);
    const order = await pg.$$eval('.nav-link', (els) => els.map((e) => e.dataset.to));
    ok(JSON.stringify(order) === JSON.stringify(['/', '/installs', '/scans', '/events', '/topology', '/policies', '/audit', '/settings']), `순서 ${JSON.stringify(order)}`); // 10/16: 설치 검사 묶음에 공급망 검사 // 10/20: 「설정 · 기록」 끝에 설정
  });

  // ---------------- 2. 단계 칩 없음 · 화면 이름 ----------------
  await T('2 상단: 단계 칩 0개, 화면마다 화면 이름', async () => {
    for (const r of ROUTES) {
      await go(pg, r);
      ok(await pg.locator('.flow-step').count() === 0, `${r} 단계 칩 남음`);
      const t = (await pg.textContent('.page-title')).trim();
      ok(t === TITLES[r], `${r} 화면 이름 "${t}"`);
    }
  });

  // ---------------- 3. 대시보드 ----------------
  await T('3 대시보드: 설치 검사 · 런타임 감시 두 구역', async () => {
    await go(pg, '/');
    // 10/15 목표: 두 구역 대신 판정 대기(설치 · 런타임 함께) + 오늘 요약 + 「감시 중」 카드
    ok(await pg.locator('[data-section="pending"]').count() === 1, '판정 대기 구역 없음');
    // 10/16: 오늘 요약 · 감시 중 카드 → 「eBPF 수집 종합」(tests/overview-1016.cjs)
    ok(await pg.locator('[data-section="overview"]').count() === 1, 'eBPF 수집 종합 구역 없음');
  });
  await T('3 대시보드: 위험 점수 없음 · 조치 필요 있음', async () => {
    await go(pg, '/');
    const labels = await pg.$$eval('.kpi-label', (els) => els.map((e) => e.textContent));
    ok(!labels.some((l) => l.includes('위험 점수')), '위험 점수 남음');
    // 10/15 목표: 「조치 필요」 → 「판정 대기」
    ok(await pg.locator('[data-pending-count]').count() === 1, '판정 대기 숫자 없음');
    ok(!(await pg.textContent('#page')).includes('조치 필요'), '조치 필요 문구 남음');
  });
  await T('3 대시보드: 분당 위반 막대 차트', async () => {
    await go(pg, '/');
    const n = await pg.locator('[data-section="overview"] [data-chart="violations"] [data-bucket]').count(); // 10/16: 위반 추이(기간별)
    ok(n >= 3, `막대 ${n}개`);
  });
  await T('3 대시보드: 피드는 위반만', async () => {
    await go(pg, '/');
    // 10/15 목표: 최근 위반 피드는 대시보드에서 빼고 이벤트 탭에만 둔다(같은 정보를 두 탭에 두지 않음)
    ok(await pg.locator('#page .feed').count() === 0, '대시보드에 위반 피드 남음');
  });

  // ---------------- 4. 설치 검사 화면 ----------------
  await T('4 설치 검사: 시드 세션 8건 이상', async () => {
    await go(pg, '/installs?status=all'); // 10/15 목표: 기본 필터가 「판정 대기」 — 전체는 status=all
    const n = await pg.locator('table[data-table="installs"] tbody tr[data-id]').count();
    ok(n >= 8, `세션 ${n}건`);
  });
  await T('4 설치 검사: 결과 필터 칩 「격리」 → 격리만', async () => {
    await go(pg, '/installs');
    await pg.click('[data-filter="status"] button:has-text("격리")');
    await pg.waitForTimeout(200);
    const st = await pg.$$eval('table[data-table="installs"] tbody tr[data-id] [data-status]', (els) => els.map((e) => e.dataset.status));
    ok(st.length > 0 && st.every((s) => s === 'isolated'), `상태 ${JSON.stringify(st)}`);
    ok(!pg.url().includes('status='), `주소에 필터가 남음 ${pg.url()}`); // 10/21b: 필터는 화면 상태만(주소에 남기지 않는다)
  });
  await T('4 설치 검사: 매니저 칩 「npm」 → npm만', async () => {
    await go(pg, '/installs?status=all'); // 10/15 목표: 기본 필터가 「판정 대기」
    await pg.click('[data-filter="manager"] button:has-text("npm")');
    await pg.waitForTimeout(200);
    const m = await pg.$$eval('table[data-table="installs"] tbody tr[data-id] [data-manager]', (els) => els.map((e) => e.dataset.manager));
    ok(m.length > 0 && m.every((x) => x === 'npm'), `매니저 ${JSON.stringify(m)}`);
  });
  await T('4 설치 검사: 격리 세션 → 시트 · URL ?id= · 공격 체인 3단계', async () => {
    await go(pg, '/installs?status=isolated');
    await pg.click('table[data-table="installs"] tbody tr[data-id]');
    await pg.waitForSelector('.sheet[data-sheet="install"]');
    ok(/[?&]id=/.test(pg.url()), `URL ${pg.url()}`);
    const kinds = await pg.$$eval('.sheet[data-sheet="install"] .chain-step .step-no', (els) => [...new Set(els.map((e) => e.textContent.trim()))]);
    ok(['1 실행', '2 파일', '3 통신'].every((k) => kinds.includes(k)), `단계 ${JSON.stringify(kinds)}`);
  });
  await T('4 설치 검사: 통과 세션 시트 — 위반 없음 + 도메인 · 프로그램 · 종류별 횟수', async () => {
    await go(pg, '/installs?status=passed');
    await pg.click('table[data-table="installs"] tbody tr[data-id]');
    await pg.waitForSelector('.sheet[data-sheet="install"]');
    const txt = await pg.textContent('.sheet[data-sheet="install"]');
    ok(txt.includes('위반 없음'), '위반 없음 문구 없음');
    ok(await pg.locator('.sheet [data-activity="hosts"] li').count() >= 1, '접속 도메인 없음');
    ok(await pg.locator('.sheet [data-activity="programs"] li').count() >= 1, '실행 프로그램 없음');
    ok(await pg.locator('.sheet [data-activity="kinds"] [data-kind]').count() === 4, '종류별 횟수 4칸 아님'); // 10/30: 실행 · 파일 · 통신 + 조회(dns)
  });
  await T('4 설치 검사: 새로고침해도 시트 유지(URL 상태)', async () => {
    await go(pg, '/installs?status=isolated');
    await pg.click('table[data-table="installs"] tbody tr[data-id]');
    await pg.waitForSelector('.sheet[data-sheet="install"]');
    await pg.reload(); await pg.waitForSelector('.sheet[data-sheet="install"]', { timeout: 5000 });
  });

  // ---------------- 5. 확인함 ----------------
  // 10/15 목표: 「확인함」(되돌리기 토스트)을 없애고 판정 2버튼으로 닫는다. 판정하면 판정 대기가 1 줄고, 되돌리기 대신 정책에서 제안을 버릴 수 있다
  await T('5 확인함: 조치 필요 1 감소 → 되돌리기로 복구', async () => {
    const p = await newPage();
    await go(p, '/');
    const before = await pendingNum(p);
    const id = await p.evaluate(() => UI.runInstallDemo('malicious'));
    await p.waitForFunction((sid) => UI.state.installs.find((s) => s.id === sid && s.finishedAt), id, { timeout: 8000 });
    await p.waitForTimeout(300);
    ok(await pendingNum(p) === before + 1, `격리 뒤 판정 대기 ${await pendingNum(p)} ≠ ${before + 1}`);
    await go(p, `/installs?id=${id}`);
    await p.waitForSelector('.sheet[data-sheet="install"]');
    ok(await p.locator('.sheet button[aria-label="확인함"]').count() === 0, '확인함 버튼 남음');
    await p.click('.sheet button[aria-label="오탐"]');
    await p.click('dialog[data-part="confirm"] [data-confirm="ok"]'); // 10/20: 판정은 확인 대화상자(B)
    await p.waitForTimeout(300);
    const c = await p.evaluate(async (sid) => UI.api.case((await UI.api.install(sid)).caseId), id);
    ok(c.state === 'decided' && c.decision === 'false_positive', `서버 건 ${c.state}`);
    await go(p, '/');
    ok(await pendingNum(p) === before, `판정 뒤 ${await pendingNum(p)} ≠ ${before}`);
    await p.close();
  });

  // ---------------- 6. 빈 상태 ----------------
  await T('6 빈 상태(?fresh=1): CLI 명령 복사 버튼', async () => {
    const p = await newPage();
    await go(p, '/installs', '?fresh=1');
    ok(await p.locator('table[data-table="installs"] tbody tr[data-id]').count() === 0, '세션이 있음');
    ok(await p.locator('.empty button:has-text("명령 복사")').count() === 1, '명령 복사 버튼 없음');
    await p.close();
  });

  // ---------------- 7. 결과 미확인 ----------------
  await T('7 결과 미확인 세션이 목록에 있음', async () => {
    await go(pg, '/installs?status=all'); // 10/15 목표: 기본 필터가 「판정 대기」
    const n = await pg.locator('table[data-table="installs"] [data-status="unknown"]').count();
    ok(n >= 1, `결과 미확인 ${n}건`);
    const label = await pg.textContent('table[data-table="installs"] [data-status="unknown"]');
    ok(label.includes('결과 미확인'), `라벨 "${label}"`);
  });

  // ---------------- 8. 데모 제어 설치 검사 실행 ----------------
  await T('8 데모: 악성 설치 검사 실행 → 맨 위 진행 중 → 격리', async () => {
    const p = await newPage();
    await go(p, '/installs');
    await p.evaluate(() => UI.runInstallDemo('malicious'));
    await p.waitForTimeout(300);
    const first = await p.$eval('table[data-table="installs"] tbody tr[data-id] [data-status]', (el) => el.dataset.status);
    ok(first === 'running', `첫 행 ${first}`);
    await p.waitForFunction(() => document.querySelector('table[data-table="installs"] tbody tr[data-id] [data-status]').dataset.status === 'isolated', null, { timeout: 8000 });
    await p.close();
  });

  // ---------------- 9. 토스트 묶음 · 8초 ----------------
  await T('9 토스트: 같은 컨테이너 격리는 하나로 ×2', async () => {
    const p = await newPage();
    await go(p, '/');
    await p.evaluate(() => { document.getElementById('toasts').replaceChildren(); UI.runAttackNow(); UI.runAttackNow(); });
    await p.waitForTimeout(300);
    const kills = await p.$$eval('.toast', (els) => els.map((e) => e.textContent).filter((t) => t.includes('pkg-reqeusts 격리됨')));
    ok(kills.length === 1, `격리 토스트 ${kills.length}개`);
    ok(kills[0].includes('×2'), `묶음 표시 없음: ${kills[0]}`);
    await p.waitForTimeout(7000);
    ok(await p.locator('.toast:has-text("pkg-reqeusts 격리됨")').count() === 1, '8초 전에 닫힘');
    await p.waitForTimeout(1800);
    ok(await p.locator('.toast:has-text("pkg-reqeusts 격리됨")').count() === 0, '8초 뒤에도 남음');
    await p.close();
  });

  // ---------------- 10. 이벤트 ----------------
  await T('10 이벤트: 기본 위반만, 정상 포함 토글', async () => {
    await go(pg, '/events');
    ok(await pg.locator('.feed-row .badge-level-normal').count() === 0, '정상 행 보임');
    await pg.click('[data-toggle="normal"]');
    await pg.waitForTimeout(400);
    ok(await pg.locator('.feed-row .badge-level-normal').count() > 0, '토글 뒤에도 정상 없음');
  });
  await T('10 이벤트: 한글 라벨(종류)', async () => {
    await go(pg, '/events');
    const head = await pg.textContent('.feed-head');
    ok(head.includes('종류') && !head.includes('Kind'), `머리 "${head}"`);
    const filters = await pg.textContent('.filters');
    ok(!filters.includes('Kind'), 'Kind 라벨 남음');
  });
  await T('10 이벤트: 행 → 오른쪽 시트 · URL ?id=', async () => {
    await go(pg, '/events');
    // 10/15 목표: 자동 공격 기본 꺼짐(데모는 「판정 대기 0」에서 시작) — 위반 행을 만들려면 공격을 일으킨다
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(400);
    await pg.click('.feed-row');
    await pg.waitForSelector('.sheet[data-sheet="event"]');
    ok(/[?&]id=/.test(pg.url()), `URL ${pg.url()}`);
  });

  // ---------------- 11. 감사 로그 ----------------
  await T('11 감사 로그: 페이지 고정 · 표만 스크롤', async () => {
    await go(pg, '/audit');
    const s = await pg.$eval('#page', (el) => [el.scrollHeight, el.clientHeight]);
    ok(s[0] <= s[1] + 1, `페이지 스크롤 ${s[0]} > ${s[1]}`);
    const inner = await pg.$eval('table[data-table="audit"]', (el) => { const sc = el.closest('.grid-scroll'); return sc ? [sc.scrollHeight, sc.clientHeight] : null; });
    ok(inner && inner[0] > inner[1], '표 상자가 스크롤되지 않음');
  });
  await T('11 감사 로그: 사유 열 없음 · 컨테이너 1줄', async () => {
    await go(pg, '/audit');
    const ths = await pg.$$eval('table[data-table="audit"] th', (els) => els.map((e) => e.textContent.trim()));
    ok(!ths.includes('사유') && !ths.includes('Kind'), `열 ${JSON.stringify(ths)}`);
    const lines = await pg.$eval('table[data-table="audit"] tbody tr td.c-container', (td) => td.children.length);
    ok(lines <= 1, `컨테이너 칸 ${lines}줄`);
  });
  await T('11 감사 로그: 설치 검사 위반은 패키지 이름', async () => {
    await go(pg, '/audit');
    const n = await pg.locator('table[data-table="audit"] [data-pkg]').count();
    ok(n >= 1, `패키지 표시 ${n}건`);
  });

  // ---------------- 12. 정책 ----------------
  await T('12 정책: 첫 정책 자동 선택', async () => {
    await go(pg, '/policies');
    ok(pg.url().includes('id=sensitive-files'), `URL ${pg.url()}`);
    ok(await pg.locator('.rule-row.selected').count() === 1, '선택 없음');
  });
  await T('12 정책: 적용 범위 칩(설치 검사 전용)', async () => {
    await go(pg, '/policies');
    const chip = await pg.textContent('.rule-row:has-text("sandbox-egress") .scope-chip');
    ok(chip.includes('설치 검사 전용'), `칩 "${chip}"`);
    ok(await pg.locator('.rule-row:has-text("sensitive-files") .scope-chip').count() === 0, '전체 적용 정책에 칩');
  });
  await T('12 정책: 관리자 토큰 칸 없음(10/20 — 쓰기는 로그인 역할만)', async () => {
    await go(pg, '/policies');
    ok(await pg.locator('.topbar input[type="password"]').count() === 0, '머리에 토큰 칸이 남음'); // 10/20: 토큰 칸 삭제
    ok(await pg.locator('.token-row').count() === 0, '목록 아래 토큰 칸 남음');
  });

  // ---------------- 13. 실제 백엔드 모드 ----------------
  const backendUp = await fetch(`${API}/health`).then((r) => r.ok).catch(() => false);
  if (backendUp) await T('13 실제 백엔드: 설치 검사가 실제 API 로 뜬다(10/21 — 「백엔드 미지원」 아님)', async () => {
    const p = await newPage();
    await go(p, '/', '?source=sim'); await require('./live-login.cjs').liveLogin(p, API); // 10/21: live 는 쿠키 세션 로그인 뒤
    await go(p, '/installs?status=all', `?source=live&api=${encodeURIComponent(API)}`);
    await p.waitForTimeout(800);
    ok(!(await p.textContent('#page')).includes('백엔드 미지원'), '미지원 안내가 남음');
    ok(await p.locator('#page [data-table="installs"]:not([hidden]) tbody tr, #page [data-part="empty"]').count() >= 1, '목록도 빈 상태도 없음');
    await p.close();
  });
  else console.log('SKIP  13 — 백엔드가 떠 있지 않음');

  // ---------------- 14. 무결성 ----------------
  for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) for (const search of ['', '?fresh=1']) {
    await T(`14 전 화면 ${vp.width}${search ? ' 빈 서버' : ''}: 페이지 넘침 0`, async () => {
      const p = await newPage(vp);
      const bad = [];
      for (const r of ROUTES) {
        await go(p, r, search);
        const [sh, ch, sw, cw] = await p.$eval('#page', (el) => [el.scrollHeight, el.clientHeight, el.scrollWidth, el.clientWidth]);
        if (sh > ch + 1 || sw > cw + 1) bad.push(`${r} ${sw}x${sh} > ${cw}x${ch}`);
      }
      ok(!bad.length, bad.join(' · '));
      await p.close();
    });
  }
  await T('14 토폴로지: 공격 체인 유지', async () => {
    await go(pg, '/topology');
    await pg.evaluate(() => UI.runAttackNow());
    await pg.waitForTimeout(1500);
    ok(await pg.locator('.topo-side .chain-step').count() >= 3, '체인 단계 부족');
  });

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
