/* 11/04 평가 화면(#/evaluation) 회귀 — 작업 U1 1단계(목업 먼저, 확정 뒤 React)
   1 사이드바: 「설치 검사」 묶음 끝(공급망 검사 다음)에 「평가」 · 화면 이름 「평가」
   2 머리: 「예시 데이터」 배지 · 결론 한 줄(예시 값에서 계산) · 출처 태그 5개(DataDog 실제 악성 · 인기 PyPI 300 · sg-vm 런타임 · 생성 시각 · 백엔드 커밋)
   3 지표 6칸: 정적 탐지율 · 정상 오탐률 · 런타임 탐지율 · 정상 설치 오탐률 · 격리 지연 p50/p95 · 모델 시험 F1
   4 차트 4개: 세트별 판정 분포(쌓은 막대, 조각 비율) · 시나리오 탐지율 · 지연 범위(격리 안 한 시나리오 빠짐) · 규칙 적중 상위 10(합 순서) · 범례 · 마우스 올리면 툴팁
   5 표: 혼동 행렬 2×2 · 모델 비교(선택 모델 강조 · 「운영 미적용」) · 정상 설치 위반 목록(통과 행 제외)
   6 결과의 한계 상자 = 세 파일 limits 전부(출처 태그)
   7 결과 JSON 내려받기 = 화면 데이터 그대로(static · runtime · model)
   8 빈 상태: ?fresh=1 → 「평가 결과 없음」 · 내려받기 버튼 없음 / ?fail=evaluation → 오류 + 다시 시도 → 성공
   9 live: GET /api/evaluation — 404 → 「평가 결과 없음」, 200 → 그 값으로 그리고 「예시 데이터」 배지 없음(가짜 응답을 page.route 로)
   10 다크: 토큰 색(배경 · 막대 · 글자) · 대비
   11 768 미만(390): 넘침 0 · 1열 · 지표 칸 2열 / 1440 넘침 0
   12 조회자도 같은 화면(읽기 전용)
   13 [11/04b] 격리 지연 지표 = 격리된 공격 전체(runtime.killLatencyMs) · 지연 카드 단계별 막대(killStagesMs + 시나리오 matchLatencyMs · evidenceMs · killApiMs p50, 툴팁 p95) · 옛 파일(키 없음) 폴백
   14 [11/04c] 모델 비교: 시험 F1 이 선택 모델보다 높은 규칙 후보가 있으면 표 아래 「시험에서는 규칙 판정이 우세 — 운영은 규칙」(예시 값에는 없음)
   콘솔 오류 0(9번의 의도한 404 한 줄만 허용)
   실행: (mock/ 에서) python3 -m http.server 8767 --bind 127.0.0.1 → BASE=http://127.0.0.1:8767/index.html PLAYWRIGHT=<playwright 경로> node tests/eval-1104.cjs  (VERBOSE=1 · ONLY · SHOTS=1 → screenshots/eval-1104-*.png) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8766/index.html';
const SHOTS = process.env.SHOTS === '1';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
const FAKE_API = 'http://127.0.0.1:8099'; // 9번 — 떠 있는 백엔드가 아니라 page.route 로 답하는 가짜 주소
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

(async () => {
  const br = await chromium.launch();
  let allow404 = false;
  const newPage = async (viewport = { width: 1440, height: 900 }, opts = {}) => {
    const ctx = await br.newContext({ viewport, acceptDownloads: true, colorScheme: opts.colorScheme || 'light' });
    const pg = await ctx.newPage();
    pg.on('console', (m) => { if (m.type() === 'error' && !(allow404 && /status of 404/.test(m.text()))) consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    pg.closeAll = () => ctx.close();
    return pg;
  };
  const go = async (pg, hash, extra = '') => { await pg.goto(`${BASE}?source=sim&as=admin${extra}#${hash}`); await pg.waitForSelector('.page-title', { timeout: 5000 }); await pg.waitForTimeout(400); };
  const W = '[data-part="evaluation"]';
  const ready = async (pg) => { await pg.waitForSelector(`${W}[data-state="ready"]`, { timeout: 5000 }); await pg.waitForTimeout(200); };
  const sample = async (pg) => pg.evaluate(() => JSON.parse(JSON.stringify(window.EVAL_SAMPLE)));
  // 데스크톱은 본문(.page)만 스크롤하므로 내용 높이만큼 창을 늘려 한 장에 담는다
  const shot = async (pg, name) => {
    if (!SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true });
    const vp = pg.viewportSize(), need = await pg.evaluate(() => { const p = document.querySelector('#page'), w = p && p.firstElementChild; return w ? Math.ceil(w.scrollHeight + w.getBoundingClientRect().top + 24) : 0; });
    if (vp.width >= 768 && need > vp.height) { await pg.setViewportSize({ width: vp.width, height: need }); await pg.waitForTimeout(300); }
    await pg.screenshot({ path: path.join(SHOT_DIR, `eval-1104b-${name}.png`), fullPage: true }); // 11/04b 피드백 반영본은 새 이름(1차 eval-1104-* 는 남긴다)
    if (vp.width >= 768 && need > vp.height) await pg.setViewportSize(vp);
  };
  const overflow = (pg) => pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'), p = document.querySelector('#page'); return { doc: d.scrollWidth - innerWidth, main: m ? m.scrollWidth - m.clientWidth : 0, page: p ? p.scrollWidth - p.clientWidth : 0 }; });

  await T('1 사이드바: 설치 검사 묶음 끝(공급망 검사 다음)에 평가 · 화면 이름', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const order = await pg.$$eval('.nav-link', (els) => els.map((e) => e.dataset.to));
    ok(same(order.slice(0, 4), ['/', '/installs', '/scans', '/evaluation']), `순서 ${JSON.stringify(order)}`);
    const groups = await pg.$$eval('.nav-group-title', (els) => els.map((e) => e.textContent.trim()));
    ok(same(groups, ['설치 검사', '런타임 감시', '설정 · 기록']), `묶음 ${JSON.stringify(groups)}`);
    await pg.click('.nav-link[data-to="/evaluation"]'); await ready(pg);
    ok((await pg.textContent('.page-title')).trim() === '평가', '화면 이름');
    ok(await pg.$eval('.nav-link[data-to="/evaluation"]', (e) => e.classList.contains('active')), '사이드바 선택 표시');
    ok((await pg.title()).startsWith('평가'), `문서 제목 ${await pg.title()}`);
    await pg.closeAll();
  });

  await T('2 머리: 예시 데이터 배지 · 결론 한 줄 · 출처 태그 5개', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation'); await ready(pg);
    ok((await pg.textContent('[data-part="sample-badge"]')).trim() === '예시 데이터', '예시 데이터 배지');
    const c = (await pg.textContent('[data-part="conclusion"]')).trim();
    ok(c === '정적 검사: 실제 악성 100개 중 80개 탐지 · 정상 300개 중 3개 오탐 — 런타임: 공격 50회 중 49회 탐지 · 정상 설치 50건 중 1건 위반', `결론 "${c}"`);
    const tags = await pg.$$eval('[data-part="tags"] [data-tag]', (els) => els.map((e) => [e.dataset.tag, e.textContent]));
    ok(tags.length === 5, `태그 수 ${tags.length}`);
    ok(same(tags.map((t) => t[0]), ['dataset-datadog-malicious', 'dataset-pypi-top300', 'host', 'generated', 'commit']), `태그 순서 ${JSON.stringify(tags.map((t) => t[0]))}`);
    ok(tags[0][1] === '악성 세트DataDog 실제 악성' && tags[1][1] === '정상 세트인기 PyPI 300', `세트 태그 ${JSON.stringify(tags.slice(0, 2))}`);
    ok(tags[2][1] === '런타임sg-vm · 커널 5.15 · fanotify', `런타임 태그 ${tags[2][1]}`);
    ok(tags[3][1].startsWith('생성') && tags[4][1] === '백엔드0000000', `생성 · 커밋 ${JSON.stringify(tags.slice(3))}`);
    await pg.closeAll();
  });

  await T('3 지표 6칸 값 · 보조 줄', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation'); await ready(pg);
    const k = await pg.$$eval('[data-part="kpis"] [data-kpi]', (els) => els.map((e) => [e.dataset.kpi, e.querySelector('.kpi-value').textContent, e.querySelector('.kpi-hint').textContent.replace(/\u00a0/g, ' ')]));
    ok(same(k.map((x) => x[0]), ['static-detection', 'static-fpr', 'runtime-detection', 'runtime-fpr', 'latency', 'model-f1']), `칸 ${JSON.stringify(k.map((x) => x[0]))}`);
    // 11/04b 격리 지연 지표는 시나리오 최댓값이 아니라 격리된 공격 전체(killLatencyMs) 기준 — 200 / 400 → 100 / 300
    ok(same(k.map((x) => x[1]), ['80.0%', '1.0%', '98.0%', '2.0%', '100 / 300 ms', '0.92']), `값 ${JSON.stringify(k.map((x) => x[1]))}`);
    ok(k[0][2] === '악성 80 / 100 · 주의 포함 90.0%' && k[1][2] === '인기 패키지 3 / 300', `정적 보조 ${k[0][2]} | ${k[1][2]}`);
    ok(k[2][2] === '공격 49 / 50회 · 5종' && k[3][2] === '위반 1 / 50건 · pip 30, npm 20', `런타임 보조 ${k[2][2]} | ${k[3][2]}`);
    ok(k[5][2] === 'HGB · 운영 미적용', `모델 보조 ${k[5][2]}`);
    // 빨강은 위험에만 — 지표 숫자는 기본 글자색
    ok(await pg.$$eval('[data-part="kpis"] .kpi-value', (els) => els.every((e) => e.classList.contains('tone-default'))), '지표 숫자 색');
    await pg.closeAll();
  });

  await T('4 차트 4개: 판정 분포 · 시나리오 탐지율 · 지연 범위 · 규칙 상위 10 · 범례 · 툴팁', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation'); await ready(pg);
    const charts = await pg.$$eval(`${W} [data-chart]`, (els) => els.map((e) => e.dataset.chart));
    // 11/04b 지연 카드에 단계별 막대(kill-stages) 추가
    ok(same(charts, ['verdict-dist', 'rule-hits', 'scenario-rate', 'latency', 'kill-stages']), `차트 ${JSON.stringify(charts)}`);
    // 두 열: 왼쪽 정적 · 오른쪽 런타임, 모델 비교는 그 아래 전체 폭
    const cols = await pg.$$eval(`${W} .ev-col`, (els) => els.map((e) => [e.dataset.col, [...e.children].map((c) => c.dataset.part)]));
    ok(same(cols, [['static', ['dist', 'rules', 'confusion']], ['runtime', ['scenarios', 'latency', 'benign']]]), `열 ${JSON.stringify(cols)}`);
    ok(await pg.evaluate(() => { const m = document.querySelector('[data-part="model"]'), g = document.querySelector('.eval-grid'); return m.parentElement === g.parentElement && Math.abs(m.offsetWidth - g.offsetWidth) <= 1; }), '모델 비교 전체 폭');
    // 판정 분포: 세트 2행, 조각 비율 = 판정 수 / 합(0 인 판정은 조각 없음), 순서 악성 → 주의 → 취약 → 정상 → 오류
    const dist = await pg.$$eval('[data-chart="verdict-dist"] g[data-row]', (gs) => gs.map((g) => [g.dataset.row, [...g.querySelectorAll('rect.ev-seg')].map((r) => [r.dataset.key, Number(r.dataset.v).toFixed(3)])]));
    ok(same(dist, [['datadog-malicious', [['malicious', '0.800'], ['suspicious', '0.100'], ['clean', '0.100']]], ['pypi-top300', [['malicious', '0.010'], ['suspicious', '0.100'], ['vulnerable', '0.067'], ['clean', '0.823']]]]), `분포 ${JSON.stringify(dist)}`);
    const leg = await pg.$$eval('[data-chart="verdict-dist"] [data-part="legend"] span', (els) => els.map((e) => e.textContent));
    ok(same(leg, ['악성', '주의', '취약', '정상', '오류']), `범례 ${JSON.stringify(leg)}`);
    // 시나리오: 6행, 대조는 회색 · 0
    const sc = await pg.$$eval('[data-chart="scenario-rate"] g[data-row]', (gs) => gs.map((g) => { const r = g.querySelector('rect.ev-seg'); return [g.dataset.row, r.dataset.key, Number(r.dataset.v)]; }));
    ok(sc.length === 6 && same(sc[3], ['dns-exfil', 'attack', 0.9]) && same(sc[5], ['benign-install', 'zero', 0]), `시나리오 ${JSON.stringify(sc)}`);
    // 지연: 격리한 시나리오 4개만, 값 그대로 · 빠진 시나리오 안내
    const lat = await pg.$$eval('[data-chart="latency"] g[data-row]', (gs) => gs.map((g) => [g.dataset.row, g.dataset.p50, g.dataset.p95, g.dataset.max]));
    ok(same(lat, [['shell-download', '100', '200', '300'], ['read-secrets', '100', '200', '300'], ['egress', '100', '300', '400'], ['dns-exfil', '200', '400', '500']]), `지연 ${JSON.stringify(lat)}`);
    ok((await pg.textContent('[data-part="latency"]')).includes('격리하지 않아 빠짐: 연쇄(내려받기 → 연결 → 읽기)'), '빠진 시나리오 안내');
    // 규칙: 12개 중 합 순서 상위 10, 행마다 막대 2개(악성 · 정상)
    const rules = await pg.$$eval('[data-chart="rule-hits"] g[data-row]', (gs) => gs.map((g) => [g.dataset.row, g.querySelectorAll('rect.ev-seg').length]));
    ok(rules.length === 10 && same(rules.slice(0, 4).map((r) => r[0]), ['threat-setup-exec', 'threat-setup-download', 'threat-dynamic-import', 'network-exfil']) && rules.every((r) => r[1] === 2), `규칙 ${JSON.stringify(rules)}`);
    ok(!rules.some((r) => r[0] === 'self-propagation' || r[0] === 'npm-preinstall-script'), '11 · 12번째 규칙이 들어감');
    // 툴팁: 행에 마우스 → 세트 이름 · 판정별 수
    const hit = await pg.$('[data-chart="verdict-dist"] g[data-row="pypi-top300"] rect.ev-hit');
    await hit.hover(); await pg.waitForTimeout(150);
    const tip = await pg.$eval('[data-chart="verdict-dist"] [data-part="chart-tip"]', (e) => [e.hidden, e.textContent]);
    ok(!tip[0] && tip[1].includes('인기 PyPI 300 · 검사 300 / 300') && tip[1].includes('악성 3 (1.0%)') && tip[1].includes('정상 247 (82.3%)'), `툴팁 ${JSON.stringify(tip)}`);
    ok(await pg.$eval('[data-chart="verdict-dist"] g[data-row="pypi-top300"]', (g) => g.classList.contains('on')), '행 강조');
    await pg.mouse.move(5, 5); await pg.waitForTimeout(100);
    ok(await pg.$eval('[data-chart="verdict-dist"] [data-part="chart-tip"]', (e) => e.hidden), '툴팁이 안 닫힘');
    // 축: 0% ~ 100% 눈금 · 점선 격자
    const ticks = await pg.$$eval('[data-chart="scenario-rate"] svg > text.tick', (els) => els.map((e) => e.textContent));
    ok(same(ticks, ['0%', '25%', '50%', '75%', '100%']), `눈금 ${JSON.stringify(ticks)}`);
    ok(await pg.$$eval('[data-chart="scenario-rate"] svg > line.grid', (els) => els.length === 4 && els.every((e) => e.getAttribute('stroke-dasharray') === '3 3')), '점선 격자');
    await shot(pg, 'desktop');
    await pg.closeAll();
  });

  await T('5 표: 혼동 행렬 · 모델 비교(선택 강조 · 운영 미적용) · 정상 설치 위반', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation'); await ready(pg);
    const cm = await pg.$$eval('[data-part="confusion"] td[data-cell]', (els) => els.map((e) => [e.dataset.cell, e.querySelector('b').textContent]));
    ok(same(cm, [['tp', '80'], ['fn', '20'], ['fp', '3'], ['tn', '297']]), `혼동 행렬 ${JSON.stringify(cm)}`);
    ok((await pg.textContent('[data-part="confusion"]')).includes('정밀도 96.4% · 재현율 80.0% · F1 0.87'), '정밀도 줄');
    const models = await pg.$$eval('[data-table="models"] tbody tr', (els) => els.map((e) => [e.dataset.model, e.classList.contains('ev-pick'), [...e.querySelectorAll('td')].map((td) => td.textContent)]));
    ok(same(models.map((m) => [m[0], m[1]]), [['rules', false], ['logreg', false], ['hgb', true]]), `모델 ${JSON.stringify(models)}`);
    ok(same(models[2][2], ['HGB보정 기준 선택', '0.90', '0.92', '94.7%', '90.0%', '1.7%']), `선택 행 ${JSON.stringify(models[2][2])}`); // 11/04c 배지 「선택」 → 「보정 기준 선택」
    ok(same(models[0][2], ['규칙 판정', '0.86', '0.86', '94.1%', '80.0%', '1.7%']), `규칙 행 ${JSON.stringify(models[0][2])}`);
    const head = await pg.$$eval('[data-table="models"] thead th', (els) => els.map((e) => e.textContent));
    ok(same(head, ['후보', '보정 F1', '시험 F1', '정밀도', '재현율', '오탐률']), `열 ${JSON.stringify(head)}`);
    ok((await pg.textContent('[data-part="model"] [data-part="not-deployed"]')).trim() === '운영 미적용', '운영 미적용 배지');
    const bv = await pg.$$eval('[data-table="benign-violations"] tbody tr', (els) => els.map((e) => [e.dataset.pkg, [...e.querySelectorAll('td')].map((td) => td.textContent)]));
    ok(same(bv, [['npm:example-npm-c', ['npm', 'example-npm-c', '격리', 'sandbox-egress', '20초']]]), `위반 목록 ${JSON.stringify(bv)}`);
    ok((await pg.textContent('[data-part="benign"] .panel-head h2')).trim() === '정상 설치 위반 1건', '위반 제목');
    await pg.closeAll();
  });

  await T('6 결과의 한계 = 세 파일 limits 전부(출처 태그)', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation'); await ready(pg);
    const d = await sample(pg);
    const want = ['static', 'runtime', 'model'].flatMap((k) => d[k].limits.map((t) => [k, t]));
    const got = await pg.$$eval('[data-part="limits"] li', (els) => els.map((e) => [e.dataset.src, e.lastElementChild.textContent]));
    ok(same(got, want), `한계 ${JSON.stringify(got)}`);
    ok((await pg.textContent('[data-part="limits"] h2')).trim() === '결과의 한계', '제목');
    const srcTags = await pg.$$eval('[data-part="limits"] li .ev-tag', (els) => [...new Set(els.map((e) => e.textContent))]);
    ok(same(srcTags, ['정적', '런타임', '모델']), `출처 ${JSON.stringify(srcTags)}`);
    await pg.closeAll();
  });

  await T('7 결과 JSON 내려받기 = 화면 데이터 그대로', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation'); await ready(pg);
    const [dl] = await Promise.all([pg.waitForEvent('download'), pg.click('[data-action="download-json"]')]);
    ok(dl.suggestedFilename() === 'supplyguard-evaluation-2026-01-01.json', `파일 이름 ${dl.suggestedFilename()}`);
    const body = JSON.parse(fs.readFileSync(await dl.path(), 'utf8'));
    const d = await sample(pg);
    ok(same(body, d), '내용이 화면 데이터와 다름');
    ok(body.static.schema === 1 && Array.isArray(body.runtime.scenarios) && body.model.preferredId === 'hgb', '세 파일 모양');
    await pg.closeAll();
  });

  await T('8 빈 상태(?fresh=1) · 조회 실패(?fail=evaluation) → 다시 시도', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation', '&fresh=1');
    await pg.waitForSelector(`${W}[data-state="empty"]`, { timeout: 5000 });
    ok((await pg.textContent(`${W} [data-part="empty"] b`)).trim() === '평가 결과 없음', '빈 상태 제목');
    ok(await pg.locator('[data-action="download-json"]').count() === 0, '빈 상태인데 내려받기 버튼');
    ok(await pg.locator(`${W} [data-chart]`).count() === 0, '빈 상태인데 차트');
    await shot(pg, 'empty');
    await go(pg, '/evaluation', '&fail=evaluation');
    await pg.waitForSelector(`${W}[data-state="error"]`, { timeout: 5000 });
    ok((await pg.textContent(`${W} [data-part="error"] b`)).includes('평가 결과을(를) 불러오지 못했습니다'), '오류 제목');
    await pg.click(`${W} [data-action="retry"]`);
    await ready(pg);
    ok(await pg.locator(`${W} [data-chart]`).count() === 5, '다시 시도 뒤 차트'); // 11/04b 단계별 막대 추가로 4 → 5
    // 다른 화면으로 가면 머리 버튼이 남지 않는다
    await pg.click('.nav-link[data-to="/scans"]'); await pg.waitForTimeout(300);
    ok(await pg.locator('[data-action="download-json"]').count() === 0, '다른 화면에 내려받기 버튼');
    await pg.closeAll();
  });

  await T('9 live: GET /api/evaluation — 404 → 평가 결과 없음 · 200 → 그 값(예시 배지 없음)', async () => {
    const pg = await newPage();
    await go(pg, '/scans');
    let answer = { status: 404, body: '404 page not found', type: 'text/plain' }; const calls = [];
    const origin = new URL(BASE).origin;
    await pg.route(`${FAKE_API}/**`, (r) => { calls.push(new URL(r.request().url()).pathname); r.fulfill({ status: answer.status, contentType: answer.type, headers: { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true' }, body: answer.body }); });
    // 로그인 · 실시간 연결까지 띄우지 않고 화면 데이터 API 만 실제 경로로 — 데이터 소스만 live 로 바꾼다
    await pg.evaluate((api) => { UI.state.source = 'live'; UI.state.apiBase = api; }, FAKE_API);
    allow404 = true;
    await pg.evaluate(() => UI.go('#/evaluation'));
    await pg.waitForSelector(`${W}[data-state="empty"]`, { timeout: 5000 });
    allow404 = false;
    ok(same(calls, ['/api/evaluation']), `부른 경로 ${JSON.stringify(calls)}`);
    ok((await pg.textContent(`${W} [data-part="empty"] b`)).trim() === '평가 결과 없음', '404 → 빈 상태');
    const d = await sample(pg); delete d.sample; d.runtime = null; // 실측 파일 모양(예시 표시 없음) · 런타임 결과 없음
    answer = { status: 200, body: JSON.stringify(d), type: 'application/json' };
    await pg.evaluate(() => UI.remount());
    await ready(pg);
    ok(await pg.locator('[data-part="sample-badge"]').count() === 0, '실측인데 예시 배지');
    ok(await pg.locator(`${W} [data-part="scenarios"] .ev-none`).count() === 1 && (await pg.textContent('[data-part="scenarios"]')).includes('런타임 결과 없음'), '런타임 없음 칸');
    ok((await pg.$eval('[data-kpi="runtime-detection"] .kpi-value', (e) => e.textContent)) === '—', '런타임 지표 —');
    ok((await pg.textContent('[data-part="conclusion"]')).trim() === '정적 검사: 실제 악성 100개 중 80개 탐지 · 정상 300개 중 3개 오탐', '결론(정적만)');
    await pg.closeAll();
  });

  await T('10 다크: 토큰 색(배경 · 카드 · 막대 · 축 글자) · 본문 대비', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation', '&theme=dark'); await ready(pg);
    const c = await pg.evaluate(() => {
      const css = (el, p) => getComputedStyle(el)[p];
      const v = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
      return { theme: document.documentElement.dataset.theme, bg: css(document.body, 'backgroundColor'), card: css(document.querySelector('[data-part="dist"]'), 'backgroundColor'),
        mal: css(document.querySelector('[data-chart="verdict-dist"] rect[data-key="malicious"]'), 'fill'), attack: css(document.querySelector('[data-chart="scenario-rate"] rect[data-key="attack"]'), 'fill'),
        tick: css(document.querySelector('[data-chart="scenario-rate"] text.tick'), 'fill'), text: css(document.querySelector('[data-part="conclusion"]'), 'color'),
        want: { danger: v('--danger'), accent: v('--accent'), text3: v('--text-3'), bg: v('--bg'), surface: v('--surface'), text: v('--text') } };
    });
    const rgb = (hex) => { const n = parseInt(hex.slice(1), 16); return `rgb(${n >> 16}, ${(n >> 8) & 255}, ${n & 255})`; };
    ok(c.theme === 'dark', 'data-theme');
    ok(c.bg === rgb(c.want.bg) && c.card === rgb(c.want.surface), `배경 ${c.bg} · 카드 ${c.card}`);
    ok(c.mal === rgb(c.want.danger) && c.attack === rgb(c.want.accent) && c.tick === rgb(c.want.text3), `막대 · 눈금 ${JSON.stringify([c.mal, c.attack, c.tick])}`);
    ok(c.text === rgb(c.want.text), `결론 글자 ${c.text}`);
    // 대비(본문 글자 vs 카드) ≥ 4.5
    const lum = (s) => { const [r, g, b] = s.match(/\d+/g).map(Number).map((x) => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
    const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
    ok(ratio(c.text, c.card) >= 4.5, `대비 ${ratio(c.text, c.card).toFixed(2)}`);
    await shot(pg, 'dark');
    await pg.closeAll();
  });

  await T('11 768 미만(390): 넘침 0 · 차트 1열 · 지표 2열 / 1440 · 1280 넘침 0', async () => {
    for (const w of [1440, 1280]) {
      const p = await newPage({ width: w, height: 900 });
      await go(p, '/evaluation'); await ready(p);
      const o = await overflow(p);
      ok(o.doc <= 0 && o.main <= 0 && o.page <= 0, `${w} 넘침 ${JSON.stringify(o)}`);
      if (w === 1440) ok(await p.$eval('.eval-kpis', (e) => getComputedStyle(e).gridTemplateColumns.split(' ').length) === 6, '1440 지표 6열');
      await p.closeAll();
    }
    const pg = await newPage({ width: 390, height: 844 });
    await go(pg, '/evaluation'); await ready(pg);
    const o = await overflow(pg);
    ok(o.doc <= 0 && o.main <= 0 && o.page <= 0, `390 넘침 ${JSON.stringify(o)}`);
    const cols = await pg.evaluate(() => [getComputedStyle(document.querySelector('.eval-grid')).gridTemplateColumns.split(' ').length, getComputedStyle(document.querySelector('.eval-kpis')).gridTemplateColumns.split(' ').length]);
    ok(same(cols, [1, 2]), `열 수(차트 · 지표) ${JSON.stringify(cols)}`);
    // 카드 안 차트가 카드 밖으로 나가지 않는다
    const spill = await pg.$$eval(`${W} .ev-card`, (els) => els.filter((e) => e.scrollWidth > e.clientWidth + 1).map((e) => e.dataset.part));
    ok(!spill.length, `카드 넘침 ${JSON.stringify(spill)}`);
    ok(await pg.isVisible('.menu-btn'), '서랍 메뉴 버튼');
    await shot(pg, 'mobile');
    await pg.closeAll();
  });

  await T('12 조회자도 같은 화면(읽기 전용 — 내려받기는 된다)', async () => {
    const pg = await newPage();
    await pg.goto(`${BASE}?source=sim&as=viewer#/evaluation`); await pg.waitForSelector('.page-title'); await ready(pg);
    ok(await pg.locator(`${W} [data-chart]`).count() === 5, '차트 5개'); // 11/04b 단계별 막대 추가로 4 → 5
    ok(await pg.locator('[data-action="download-json"]').count() === 1, '내려받기 버튼');
    await pg.closeAll();
  });

  await T('13 [11/04b] 격리 지연: 격리된 공격 전체 기준 · 단계별 막대(판정 → 증거 수집 → kill 호출) · 옛 파일 폴백', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation'); await ready(pg);
    const d = await sample(pg);
    ok(d.runtime.killLatencyMs && d.runtime.killStagesMs, '예시 데이터에 killLatencyMs · killStagesMs 없음');
    ok(same(d.runtime.killLatencyMs.scenarios, ['shell-download', 'read-secrets', 'egress', 'dns-exfil']) && d.runtime.killLatencyMs.n === 39, `killLatencyMs ${JSON.stringify(d.runtime.killLatencyMs)}`);
    const kpi = async () => pg.$eval('[data-kpi="latency"]', (e) => [e.querySelector('.kpi-value').textContent, e.querySelector('.kpi-hint').textContent.replace(/ /g, ' ')]);
    const k = await kpi();
    ok(same(k, ['100 / 300 ms', '격리된 공격 39회 기준 · 백엔드 수신→격리']), `지표 ${JSON.stringify(k)}`);
    // 단계 막대는 지연 카드 안, 범위 그림 아래
    const C = '[data-part="latency"] [data-chart="kill-stages"]';
    ok(await pg.locator(C).count() === 1, '지연 카드에 단계 막대 없음');
    ok(await pg.$eval('[data-part="latency"]', (e) => { const a = e.querySelector('[data-chart="latency"]'), b = e.querySelector('[data-chart="kill-stages"]'); return !!(a && b && (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING)); }), '단계 막대가 범위 그림 아래가 아님');
    // 행: 격리된 공격 전체(killStagesMs) → 격리한 시나리오(연쇄 · 대조 빠짐), 조각은 p50 · 판정 → 증거 수집 → kill 호출 순서
    const rows = await pg.$$eval(`${C} g[data-row]`, (gs) => gs.map((g) => [g.dataset.row, [...g.querySelectorAll('rect.ev-seg')].map((r) => [r.dataset.key, Number(r.dataset.v)]), g.querySelector('text.ev-value').textContent]));
    const st = (m, e, k) => [['match', m], ['evidence', e], ['killApi', k]];
    ok(same(rows, [['all', st(0.1, 40, 60), '합계 100 ms'], ['shell-download', st(0.1, 40, 60), '합계 100 ms'], ['read-secrets', st(0.1, 40, 60), '합계 100 ms'], ['egress', st(0.1, 40, 60), '합계 100 ms'], ['dns-exfil', st(0.1, 100, 100), '합계 200 ms']]), `단계 행 ${JSON.stringify(rows)}`);
    ok((await pg.$eval(`${C} g[data-row="all"] text.ev-label`, (e) => e.textContent)) === '격리된 공격 전체', '전체 행 이름');
    const leg = await pg.$$eval(`${C} [data-part="legend"] span`, (els) => els.map((e) => e.textContent));
    ok(same(leg, ['판정', '증거 수집', 'kill 호출']), `범례 ${JSON.stringify(leg)}`);
    ok((await pg.textContent('[data-part="latency"]')).includes('증거를 먼저 모으고(≤0.7초) 격리합니다'), '캡션');
    // 툴팁: 단계마다 p50 · p95
    await (await pg.$(`${C} g[data-row="all"] rect.ev-hit`)).hover(); await pg.waitForTimeout(150);
    const tip = await pg.$eval(`${C} [data-part="chart-tip"]`, (e) => [e.hidden, [...e.children].map((c) => c.textContent)]);
    ok(!tip[0] && same(tip[1], ['격리된 공격 전체', '판정 p50 0.1 ms · p95 0.2 ms', '증거 수집 p50 40 ms · p95 100 ms', 'kill 호출 p50 60 ms · p95 200 ms', '격리 39회 기준']), `툴팁 ${JSON.stringify(tip)}`);
    // 빨강은 위험에만 — 단계 조각은 빨강(--danger)이 아니다
    const fills = await pg.$$eval(`${C} rect.ev-seg`, (els) => [...new Set(els.map((e) => getComputedStyle(e).fill))]);
    const danger = await pg.evaluate(() => { const n = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--danger').trim().slice(1), 16); return `rgb(${n >> 16}, ${(n >> 8) & 255}, ${n & 255})`; });
    ok(fills.length === 3 && !fills.includes(danger), `조각 색 ${JSON.stringify(fills)}`);
    // 옛 파일(두 키 없음): 지표는 시나리오 중 가장 큰 값 + 그 기준, 단계 막대는 숨김
    await pg.evaluate(() => { delete window.EVAL_SAMPLE.runtime.killLatencyMs; delete window.EVAL_SAMPLE.runtime.killStagesMs; UI.remount(); });
    await pg.waitForTimeout(200); await ready(pg);
    const k2 = await kpi();
    ok(same(k2, ['200 / 400 ms', '공격 시나리오 중 가장 느린 값']), `폴백 지표 ${JSON.stringify(k2)}`);
    ok(await pg.locator(C).count() === 0 && await pg.locator('[data-part="latency"] [data-chart="latency"]').count() === 1, '옛 파일인데 단계 막대');
    ok(!(await pg.textContent('[data-part="latency"]')).includes('증거를 먼저 모으고'), '옛 파일인데 캡션');
    await pg.closeAll();
  });

  // 11/04c — 선택(보정 기준) 모델보다 시험 F1 이 높은 규칙 후보(id 가 rule 로 시작)가 있으면 표 아래 한 줄. 예시 값은 HGB 가 가장 높아 없음
  await T('14 [11/04c] 모델 비교: 규칙 후보가 시험 F1 에서 앞서면 「규칙 우세」 한 줄', async () => {
    const pg = await newPage();
    await go(pg, '/evaluation'); await ready(pg);
    ok(await pg.locator('[data-part="model"] [data-part="rule-wins"]').count() === 0, '예시 값인데 규칙 우세 줄');
    await pg.evaluate(() => { window.EVAL_SAMPLE.model.candidates[0].test.f1 = 0.95; UI.remount(); });
    await pg.waitForTimeout(200); await ready(pg);
    const line = await pg.locator('[data-part="model"] [data-part="rule-wins"]');
    ok(await line.count() === 1 && (await line.textContent()).trim() === '시험에서는 규칙 판정이 우세 — 운영은 규칙', '규칙 우세 줄');
    ok((await pg.textContent('[data-table="models"] tr[data-model="hgb"] .ev-pick-badge')).trim() === '보정 기준 선택', '선택 배지는 그대로 HGB');
    await pg.closeAll();
  });

  await br.close();
  const pass = results.filter((r) => r[0]).length;
  if (!process.env.VERBOSE) for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  for (const e of consoleErrors) console.log(`CONSOLE  ${e}`);
  console.log(`\n${pass}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  process.exit(pass === results.length && !consoleErrors.length ? 0 : 1);
})();
