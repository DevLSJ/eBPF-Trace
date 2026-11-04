/* 11/04e UI 업그레이드 회귀 — 스크롤 없는 페이지 · KPI 카드 · 패널 · 표(정렬 · 쪽 번호) · 타이포 · 차트 모양 · 대시보드 재배치
   1 768 이상 모든 화면: 문서 · 본문(#page) 스크롤 0, 스크롤은 「채움 칸」([data-fill]) 안에서만 — 1280×720 · 1440×900 · 1920×1080
   2 높이 낮은 화면(1280×720 · 1366×768): 대시보드 차트 ≥ 120px · x축 글자 겹침 없음
   3 대시보드 배치: KPI 줄(6칸) → 차트 줄(추이 · 위반 · 결과 분포) → 아래 3칸(판정 대기 · 많이 걸린 정책 · 위반 많은 컨테이너), 아래 줄이 남은 높이를 채움
   4 KPI 카드: 왼쪽 4px 띠 · 아이콘 칩 · 이름 12.5~13/600 · 값 28/700 tabular · 단위 분리 · 증감 줄(위반 증가만 빨강) · 보조 줄
   5 KPI 0 규칙(?fresh=1): 값 0 이면 띠만 색, 숫자 · 테두리는 기본색 / 처음 렌더는 바로 값 · 바뀌면 링
   6 패널: 반경 12 · 1px 테두리 · 그림자 · 머리 제목 14.5/600 · 「더 보기 ›」 슬롯
   7 표: 머리 sticky 12/700 · 정렬(aria-sort 오름 → 내림) · 행 44~48 · 숫자 오른쪽 · 배지 11.5/700 + 테두리 · 판정 대기 · 격리 행만 3px 막대
   8 쪽 번호 바닥줄: 감사 로그 「1–20 / N」 · 페이지당 · 다음 쪽 · 설치 검사 · 공급망 검사도 바닥줄
   9 재조회 진행 띠(이전 데이터 유지) · 첫 로딩 스켈레톤
   10 타이포: 화면 글자 12px 이상(배지 11.5 예외) · 스크롤바 얇게(숨기지 않음)
   11 차트 모양: 추이 선 굵기 2 · 점 숨김 · 끝 라벨 겹침 없음 · 점선 격자 · y축 선 없음 / 막대 폭 ≤ 22 / 도넛 58% · 84% · 가운데 숫자 · 0 이면 회색 고리 / 반전 툴팁 / 첫 렌더만 그리기 애니메이션
   12 다크: 대시보드 KPI · 패널 색이 다크 토큰, 스크롤 0 유지
   13 390: 문서 스크롤 허용 · 가로 넘침 0 · KPI 2열
   14 평가: 머리 · 지표 고정, 아래 몸통만 스크롤
   콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8768 --bind 127.0.0.1 → BASE=http://127.0.0.1:8768/index.html PLAYWRIGHT=<playwright 경로> node tests/ui-1104.cjs
         (VERBOSE=1 · ONLY=정규식 · SHOTS=1 → screenshots/ui-1104-*.png) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = (process.env.BASE || 'http://127.0.0.1:8768').replace(/\/index\.html$/, '').replace(/\/$/, '') + '/index.html';
const SHOTS = process.env.SHOTS === '1';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const near = (a, b, d) => Math.abs(a - b) <= d;
const SCREENS = ['/', '/installs', '/scans', '/evaluation', '/events', '/topology', '/policies', '/audit', '/settings', '/report?case=case-0001'];

(async () => {
  const br = await chromium.launch();
  const newPage = async (opts = {}) => {
    const ctx = await br.newContext(Object.assign({ viewport: { width: 1440, height: 900 } }, opts));
    const pg = await ctx.newPage();
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    pg.done = () => ctx.close();
    return pg;
  };
  const go = async (pg, hash, extra = '') => { await pg.goto(`${BASE}?source=sim&as=admin${extra}#${hash}`); await pg.waitForSelector('.page-title', { timeout: 6000 }); await pg.waitForTimeout(600); };
  const shot = async (pg, name) => { if (!SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.screenshot({ path: path.join(SHOT_DIR, `ui-1104-${name}.png`), fullPage: true }); };
  // 스크롤 점검: 문서 · 본문 넘침, 채움 칸 밖에서 스크롤되는 요소(시트 · 대화상자 · 도우미 패널 안은 허용)
  const scrollState = (pg) => pg.evaluate(() => {
    const se = document.scrollingElement, p = document.querySelector('#page');
    const allowed = (e) => e.matches('[data-fill], [data-fill] *, .sheet *, dialog *, .assist-panel *');
    const bad = [...document.querySelectorAll('#page *')].filter((e) => { const cs = getComputedStyle(e); return /(auto|scroll)/.test(cs.overflowY) && e.scrollHeight > e.clientHeight + 1 && !allowed(e); })
      .map((e) => `${e.tagName.toLowerCase()}.${String(e.className).split(' ').slice(0, 2).join('.')}+${e.scrollHeight - e.clientHeight}`);
    return { doc: se.scrollHeight - innerHeight, page: p.scrollHeight - p.clientHeight, fills: document.querySelectorAll('#page [data-fill]').length, bad };
  });

  // ---------------- 1 스크롤 없는 페이지 ----------------
  for (const [w, hh] of [[1280, 720], [1440, 900], [1920, 1080]]) {
    await T(`1 ${w}×${hh}: 모든 화면 문서 · 본문 스크롤 0, 채움 칸만 스크롤`, async () => {
      const pg = await newPage({ viewport: { width: w, height: hh } });
      const errs = [];
      for (const s of SCREENS) {
        await go(pg, s);
        const r = await scrollState(pg);
        if (r.doc > 0) errs.push(`${s} 문서 +${r.doc}`);
        if (r.page > 1) errs.push(`${s} 본문 +${r.page}`);
        if (!r.fills) errs.push(`${s} 채움 칸 없음`);
        if (r.bad.length) errs.push(`${s} 채움 칸 밖 스크롤 ${r.bad.join(',')}`);
      }
      ok(!errs.length, errs.join(' · '));
      await pg.done();
    });
  }

  // ---------------- 2 높이 낮은 화면 ----------------
  for (const [w, hh] of [[1280, 720], [1366, 768]]) {
    await T(`2 ${w}×${hh}: 대시보드 차트 ≥ 120px · x축 글자 겹침 없음`, async () => {
      const pg = await newPage({ viewport: { width: w, height: hh } });
      await go(pg, '/');
      const r = await pg.$$eval('[data-section="overview"] [data-chart] svg.chart-svg', (svgs) => svgs.map((s) => {
        const ticks = [...s.querySelectorAll('text.tick-x')].map((t) => t.getBoundingClientRect());
        let overlap = 0; for (let i = 1; i < ticks.length; i++) if (ticks[i].left < ticks[i - 1].right - 0.5) overlap++;
        return [s.closest('[data-chart]').dataset.chart, Math.round(s.getBoundingClientRect().height), overlap];
      }));
      ok(r.length >= 3, `차트 ${r.length}개`);
      for (const [name, hgt, ov] of r) { ok(hgt >= 120, `${name} 높이 ${hgt}`); ok(!ov, `${name} x축 글자 겹침 ${ov}`); }
      ok((await scrollState(pg)).page <= 1, '본문 스크롤');
      await pg.done();
    });
  }

  // ---------------- 3 대시보드 배치 ----------------
  await T('3 대시보드: KPI 줄 → 차트 줄(추이 · 위반 · 결과 분포) → 아래 3칸, 아래 줄이 남은 높이 채움 · 몸통만 스크롤', async () => {
    const pg = await newPage({ viewport: { width: 1920, height: 1080 } });
    await go(pg, '/');
    const box = (sel) => pg.$eval(sel, (e) => e.getBoundingClientRect().toJSON());
    const [k, c, b, page] = [await box('.ov-kpis'), await box('.ov-charts'), await box('.ov-bottom'), await box('#page')];
    ok(k.bottom <= c.top && c.bottom <= b.top, `순서 kpi ${k.top} · 차트 ${c.top} · 아래 ${b.top}`);
    ok(await pg.locator('.ov-kpis > [data-kpi]').count() === 6, 'KPI 6칸');
    const charts = await pg.$$eval('.ov-charts > *', (els) => els.map((e) => [e.querySelector('[data-chart]')?.dataset.chart, Math.round(e.getBoundingClientRect().width)]));
    ok(JSON.stringify(charts.map((x) => x[0])) === JSON.stringify(['collected', 'violations', 'results']), `차트 줄 ${JSON.stringify(charts)}`);
    const bottom = await pg.$$eval('.ov-bottom > *', (els) => els.map((e) => e.dataset.section || e.dataset.card));
    ok(JSON.stringify(bottom) === JSON.stringify(['pending', 'top-rules', 'top-containers']), `아래 줄 ${JSON.stringify(bottom)}`);
    const pad = await pg.$eval('#page', (e) => parseFloat(getComputedStyle(e).paddingBottom));
    ok(near(b.bottom, page.bottom - pad, 2), `아래 줄 끝 ${b.bottom} / 본문 끝 ${page.bottom - pad}`);
    ok(await pg.locator('.ov-bottom [data-fill]').count() === 3, '아래 3칸 몸통 [data-fill]');
    ok(await pg.locator('.dash [data-section="pending"]').count() === 1, '판정 대기');
    await shot(pg, 'dashboard-1920');
    await pg.setViewportSize({ width: 1440, height: 900 }); await pg.waitForTimeout(400); await shot(pg, 'dashboard-1440');
    await pg.done();
  });

  // ---------------- 4 KPI 카드 ----------------
  await T('4 KPI 카드: 4px 띠 · 아이콘 칩 · 이름 13/600 · 값 28/700 tabular · 단위 분리 · 증감 줄 · 보조 줄', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const cards = await pg.$$eval('.ov-kpis > [data-kpi]', (els) => els.map((e) => {
      const cs = getComputedStyle(e), name = e.querySelector('.kpi-name'), val = e.querySelector('[data-value]'), ico = e.querySelector('.kpi-ico'), delta = e.querySelector('[data-delta]'), sub = e.lastElementChild;
      const n = name && getComputedStyle(name), v = val && getComputedStyle(val), i = ico && getComputedStyle(ico);
      return { key: e.dataset.kpi, bl: cs.borderLeftWidth, blc: cs.borderLeftColor, bt: cs.borderTopColor, nameFs: n && n.fontSize, nameFw: n && n.fontWeight, valFs: v && v.fontSize, valFw: v && v.fontWeight, tab: v && v.fontVariantNumeric, ico: !!ico && i.backgroundColor !== 'rgba(0, 0, 0, 0)', icoText: ico ? ico.textContent : 'x', delta: delta ? delta.dataset.delta : null, deltaTone: delta ? delta.dataset.deltaTone : null, sub: sub && sub.classList.contains('kpi-sub'), pad: cs.paddingTop + ' ' + cs.paddingLeft };
    }));
    ok(cards.length === 6, `칸 ${cards.length}`);
    for (const c of cards) {
      ok(c.bl === '4px' && c.blc !== c.bt, `${c.key} 띠 ${c.bl} ${c.blc}`);
      ok(c.ico && c.icoText === '', `${c.key} 아이콘 칩(글자 없이 그림 · 옅은 배경)`);
      ok(['12.5px', '13px'].includes(c.nameFs) && c.nameFw === '600', `${c.key} 이름 ${c.nameFs}/${c.nameFw}`);
      ok(c.valFs === '28px' && c.valFw === '700' && c.tab.includes('tabular-nums'), `${c.key} 값 ${c.valFs}/${c.valFw}/${c.tab}`);
      ok(c.delta !== null, `${c.key} 증감 줄`);
      ok(c.sub, `${c.key} 보조 줄(.kpi-sub 마지막)`);
      ok(c.pad === '16px 18px', `${c.key} 패딩 ${c.pad}`);
    }
    ok(cards.find((c) => c.key === 'collected').deltaTone !== 'danger', '수집 증감은 빨강 아님');
    // 단위 분리: 격리 지연 「ms」
    await pg.evaluate(() => UI.runInstallDemo('malicious')); await pg.waitForTimeout(2600);
    const unit = await pg.$eval('[data-kpi="isolation"]', (e) => { const u = e.querySelector('.kpi-unit'); return u ? [u.textContent.trim(), getComputedStyle(u).fontSize, getComputedStyle(u).fontWeight] : null; });
    ok(unit && unit[0] === 'ms' && unit[1] === '13px' && unit[2] === '500', `단위 ${JSON.stringify(unit)}`);
    // 위반 증가 → 빨강 ▲
    const vd = await pg.$eval('[data-kpi="violations"] [data-delta]', (e) => [e.dataset.delta, e.dataset.deltaTone, e.textContent]);
    ok(vd[0] === 'up' && vd[1] === 'danger' && vd[2].includes('▲'), `위반 증감 ${JSON.stringify(vd)}`);
    // 길게 눌러 순서 바꾸기(11/04d)는 그대로 — Alt+→ 한 칸
    await pg.focus('.ov-kpis > [data-kpi="collected"]'); await pg.keyboard.press('Alt+ArrowRight'); await pg.waitForTimeout(300);
    const order = await pg.$$eval('.ov-kpis > [data-kpi]', (els) => els.map((e) => e.dataset.kpi));
    ok(order[1] === 'collected', `순서 바꾸기 ${order}`);
    await pg.evaluate(() => { try { localStorage.removeItem('supplyguard.layout'); } catch { /* */ } });
    await pg.done();
  });

  await T('5 KPI: 값 0 이면 띠만 색(숫자 · 테두리 기본) · 처음 렌더는 바로 값 · 값이 바뀌면 링', async () => {
    const pg = await newPage();
    await go(pg, '/', '&fresh=1');
    const z = await pg.$eval('[data-kpi="violations"]', (e) => { const cs = getComputedStyle(e), v = getComputedStyle(e.querySelector('[data-value]')); return [e.querySelector('[data-value]').textContent.trim(), cs.borderLeftColor, cs.borderTopColor, v.color, getComputedStyle(document.body).color]; });
    ok(z[0] === '0', `값 ${z[0]}`);
    ok(z[1] !== z[2], `띠 색 ${z[1]} = 테두리 ${z[2]}`);
    ok(z[3] === z[4], `0 인데 숫자 색 ${z[3]} (본문 ${z[4]})`);
    // 처음 렌더: 카운트업 없이 바로 최종값
    // 시뮬 수집량은 250ms 마다 바뀌므로 「처음 붙는 순간」의 글자를 잰다(MutationObserver — 그리기 직후, 다음 프레임 전)
    const pg2 = await newPage();
    await pg2.addInitScript(() => { new MutationObserver((ms, ob) => { const b = document.querySelector('[data-kpi="collected"] [data-value]'); if (b && !window.__first) { window.__first = [b.textContent, b.dataset.countup]; ob.disconnect(); } }).observe(document, { childList: true, subtree: true }); });
    await pg2.goto(`${BASE}?source=sim&as=admin#/`);
    await pg2.waitForSelector('[data-kpi="collected"] [data-value]', { timeout: 6000 });
    const first = await pg2.evaluate(() => window.__first);
    ok(Number(first[0].replace(/,/g, '')) === Number(first[1]), `첫 렌더 ${JSON.stringify(first)}`);
    await pg2.done();
    // 값이 바뀌면 링
    await pg.evaluate(() => { window.__ring = 0; new MutationObserver((ms) => { for (const m of ms) if (m.target.classList && m.target.classList.contains('kpi-ring')) window.__ring++; }).observe(document.querySelector('.ov-kpis'), { attributes: true, subtree: true, attributeFilter: ['class'] }); });
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(2600);
    ok(await pg.evaluate(() => window.__ring) > 0, '링 없음');
    await pg.done();
  });

  // ---------------- 6 패널 ----------------
  await T('6 패널: 반경 12 · 테두리 1px · 그림자 · 머리 제목 14.5/600 · 「더 보기 ›」', async () => {
    const pg = await newPage();
    for (const s of ['/', '/installs', '/audit']) {
      await go(pg, s);
      const ps = await pg.$$eval('#page .panel', (els) => els.map((e) => { const cs = getComputedStyle(e), h2 = e.querySelector(':scope > .panel-head h2'); return [cs.borderTopLeftRadius, cs.borderTopWidth, cs.boxShadow !== 'none', h2 ? getComputedStyle(h2).fontSize + '/' + getComputedStyle(h2).fontWeight : null]; }));
      ok(ps.length, `${s} 패널 없음`);
      for (const p of ps) { ok(p[0] === '12px' && p[1] === '1px' && p[2], `${s} 패널 ${JSON.stringify(p)}`); if (p[3]) ok(p[3] === '14.5px/600', `${s} 제목 ${p[3]}`); }
    }
    await go(pg, '/');
    const more = await pg.$$eval('.ov-bottom [data-more]', (els) => els.map((e) => [e.textContent.trim(), e.getAttribute('href')]));
    ok(more.length === 3 && more.every((m) => m[0].endsWith('›') && m[1]), `더 보기 ${JSON.stringify(more)}`);
    await pg.done();
  });

  // ---------------- 7 표 ----------------
  await T('7 표: 머리 sticky 12/700 · 정렬 aria-sort · 행 44~48 · 숫자 오른쪽 · 배지 11.5/700 + 테두리 · 판정 대기 · 격리만 3px 막대', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    await pg.click('[data-filter="status"] button[data-value="all"]'); await pg.waitForTimeout(300);
    const th = await pg.$eval('table[data-table="installs"] th', (e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight, getComputedStyle(e.closest('thead')).position]);
    ok(th.join() === '12px,700,sticky', `머리 ${th}`);
    const sortable = await pg.$$eval('table[data-table="installs"] th[aria-sort]', (els) => els.map((e) => e.dataset.col));
    ok(sortable.length >= 5, `정렬 칸 ${sortable}`);
    const pkgs = () => pg.$$eval('table[data-table="installs"] tbody tr[data-id] td[data-col="package"]', (els) => els.map((e) => e.textContent.trim()));
    await pg.click('table[data-table="installs"] th[data-col="package"]'); await pg.waitForTimeout(200);
    let a = await pkgs(); const asc = [...a].sort((x, y) => x.localeCompare(y, 'ko'));
    ok(JSON.stringify(a) === JSON.stringify(asc), `오름 ${a}`);
    ok(await pg.$eval('table[data-table="installs"] th[data-col="package"]', (e) => e.getAttribute('aria-sort')) === 'ascending', 'aria-sort 오름');
    await pg.click('table[data-table="installs"] th[data-col="package"]'); await pg.waitForTimeout(200);
    a = await pkgs(); ok(JSON.stringify(a) === JSON.stringify([...asc].reverse()), `내림 ${a}`);
    ok(await pg.$eval('table[data-table="installs"] th[data-col="package"]', (e) => e.getAttribute('aria-sort')) === 'descending', 'aria-sort 내림');
    ok(await pg.$eval('table[data-table="installs"] th[data-col="started"]', (e) => e.getAttribute('aria-sort')) === 'none', '다른 칸 none');
    // 키보드: 머리 단추 Enter
    await pg.focus('table[data-table="installs"] th[data-col="violations"] button'); await pg.keyboard.press('Enter'); await pg.waitForTimeout(200);
    ok(await pg.$eval('table[data-table="installs"] th[data-col="violations"]', (e) => e.getAttribute('aria-sort')) === 'ascending', '키보드 정렬');
    const row = await pg.$eval('table[data-table="installs"] tbody tr[data-id]', (e) => e.getBoundingClientRect().height);
    ok(row >= 44 && row <= 48, `행 ${row}`);
    const right = await pg.$eval('table[data-table="installs"] tbody td[data-col="violations"]', (e) => getComputedStyle(e).textAlign);
    ok(right === 'right', `숫자 정렬 ${right}`);
    const badge = await pg.$eval('table[data-table="installs"] tbody [data-status]', (e) => { const cs = getComputedStyle(e); return [cs.fontSize, cs.fontWeight, cs.borderTopWidth !== '0px' || cs.boxShadow !== 'none']; });
    ok(badge[0] === '11.5px' && badge[1] === '700' && badge[2], `배지 ${badge}`);
    // 막대: 격리 · 판정 대기 행만
    await pg.evaluate(() => UI.runInstallDemo('malicious')); await pg.waitForTimeout(2600);
    const bars = await pg.$$eval('table[data-table="installs"] tbody tr[data-id]', (els) => els.map((e) => [e.querySelector('[data-status]').dataset.status, getComputedStyle(e.firstElementChild).boxShadow.includes('inset')]));
    ok(bars.some((b) => b[0] === 'isolated' && b[1]), '격리 행 막대 없음');
    ok(bars.filter((b) => b[1]).every((b) => ['isolated', 'warned', 'running'].includes(b[0])), `막대 대상 ${JSON.stringify(bars)}`);
    ok(bars.filter((b) => b[0] === 'passed').every((b) => !b[1]), '통과 행에 막대');
    await shot(pg, 'table-installs');
    await pg.done();
  });

  // ---------------- 8 쪽 번호 ----------------
  await T('8 쪽 번호 바닥줄: 감사 로그 1–20 / N · 다음 · 페이지당 · 설치 검사 · 공급망 검사', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    const pager = '[data-table-foot="audit"] [data-part="pager"]';
    await pg.waitForSelector(pager, { timeout: 3000 });
    const t = await pg.textContent(`${pager} [data-part="range"]`);
    const m = t.match(/^1–20 \/ (\d+)$/); ok(m && Number(m[1]) > 40, `범위 "${t}"`);
    ok(await pg.locator('table[data-table="audit"] tbody tr').count() === 20, '20행');
    ok(await pg.$eval(`${pager} select[data-part="page-size"]`, (e) => e.value) === '20', '페이지당 20');
    const first = await pg.$eval('table[data-table="audit"] tbody tr', (e) => e.dataset.audit);
    await pg.click(`${pager} [data-page="2"]`); await pg.waitForTimeout(300);
    ok((await pg.textContent(`${pager} [data-part="range"]`)).startsWith('21–40 / '), '2쪽 범위');
    ok(await pg.$eval('table[data-table="audit"] tbody tr', (e) => e.dataset.audit) !== first, '2쪽 행');
    ok(await pg.$eval(`${pager} [data-page="2"]`, (e) => e.getAttribute('aria-current')) === 'page', 'aria-current');
    await pg.selectOption(`${pager} select[data-part="page-size"]`, '50'); await pg.waitForTimeout(300);
    ok((await pg.textContent(`${pager} [data-part="range"]`)).startsWith('1–50 / '), '페이지당 50');
    ok(await pg.locator('table[data-table="audit"] tbody tr').count() === 50, '50행');
    // 바닥줄은 표 몸통 밖(고정) — 스크롤해도 제자리
    const footFixed = await pg.evaluate(() => { const f = document.querySelector('[data-table-foot="audit"]'), sc = document.querySelector('table[data-table="audit"]').closest('[data-fill]'); return !!f && !!sc && !sc.contains(f); });
    ok(footFixed, '바닥줄이 몸통 안');
    await go(pg, '/installs'); await pg.click('[data-filter="status"] button[data-value="all"]'); await pg.waitForTimeout(300);
    ok(/^1–\d+ \/ \d+$/.test(await pg.textContent('[data-table-foot="installs"] [data-part="range"]')), '설치 검사 바닥줄');
    await go(pg, '/scans');
    ok(await pg.locator('[data-table-foot="scans"]').count() === 1, '공급망 검사 바닥줄');
    await pg.done();
  });

  // ---------------- 9 진행 띠 · 스켈레톤 ----------------
  await T('9 재조회 진행 띠(이전 행 유지) · 첫 로딩 스켈레톤', async () => {
    const pg = await newPage();
    await pg.goto(`${BASE}?source=sim&as=admin&latency=700#/audit`);
    await pg.waitForSelector('.page-title');
    ok(await pg.locator('#page .skeleton').count() >= 1, '스켈레톤 없음');
    await pg.waitForSelector('table[data-table="audit"] tbody tr', { timeout: 4000 });
    const n = await pg.locator('table[data-table="audit"] tbody tr').count();
    await pg.selectOption('#page select[aria-label="대응"]', 'alert');
    await pg.waitForSelector('[data-part="busy"]:not([hidden])', { timeout: 1500 });
    ok(await pg.locator('table[data-table="audit"] tbody tr').count() === n, '진행 중 이전 행이 사라짐');
    await pg.waitForSelector('[data-part="busy"][hidden]', { state: 'attached', timeout: 3000 });
    await pg.done();
  });

  // ---------------- 10 타이포 · 스크롤바 ----------------
  await T('10 타이포: 글자 12px 이상(배지 11.5) · 스크롤바 얇게 보임', async () => {
    const pg = await newPage();
    const small = [];
    for (const s of ['/', '/installs', '/scans', '/evaluation', '/events', '/topology', '/policies', '/audit', '/settings']) {
      await go(pg, s);
      const r = await pg.evaluate(() => [...document.querySelectorAll('.shell *')].filter((e) => {
        if (!e.getClientRects().length) return false;
        const own = [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
        if (!own) return false;
        const fs = parseFloat(getComputedStyle(e).fontSize);
        const isBadge = e.closest('.badge');
        return fs < (isBadge ? 11.5 : 12) - 0.01;
      }).slice(0, 4).map((e) => `${e.tagName.toLowerCase()}.${String(e.className && e.className.baseVal !== undefined ? e.className.baseVal : e.className).split(' ')[0]}:${getComputedStyle(e).fontSize}`));
      if (r.length) small.push(`${s} ${r.join(',')}`);
    }
    ok(!small.length, small.join(' | '));
    await go(pg, '/audit');
    const sb = await pg.$eval('#page [data-fill]', (e) => getComputedStyle(e).scrollbarWidth);
    ok(sb === 'thin', `스크롤바 ${sb}`);
    await pg.done();
  });

  // ---------------- 11 차트 모양 ----------------
  await T('11 차트: 선 2 · 점 숨김 · 끝 라벨 · 점선 격자 · y축 없음 / 막대 ≤ 22 · 위 모서리 / 도넛 58·84 · 가운데 숫자 / 반전 툴팁 / 첫 렌더만 그리기', async () => {
    const pg = await newPage({ viewport: { width: 1920, height: 1080 } });
    await go(pg, '/');
    const C = '[data-chart="collected"]';
    const lines = await pg.$$eval(`${C} path[data-kind]`, (els) => els.map((e) => [e.dataset.kind, getComputedStyle(e).strokeWidth]));
    ok(JSON.stringify(lines.map((x) => x[0]).sort()) === JSON.stringify(['connect', 'dns', 'exec', 'open']) && lines.every((x) => x[1] === '2px'), `선 ${JSON.stringify(lines)}`);
    ok(await pg.$$eval(`${C} circle`, (els) => els.filter((e) => getComputedStyle(e).opacity !== '0' && getComputedStyle(e).display !== 'none' && !e.closest('[hidden]')).length) === 0, '점이 보임');
    const labels = await pg.$$eval(`${C} [data-end-label]`, (els) => els.map((e) => e.getBoundingClientRect().toJSON()));
    ok(labels.length === 4, `끝 라벨 ${labels.length}`);
    labels.sort((a, b) => a.top - b.top);
    for (let i = 1; i < labels.length; i++) ok(labels[i].top >= labels[i - 1].bottom - 0.5, '끝 라벨 겹침');
    const grid = await pg.$$eval(`${C} line.grid`, (els) => els.map((e) => e.getAttribute('stroke-dasharray')));
    ok(grid.length >= 2 && grid.every((d) => d), `격자 ${grid}`);
    ok(await pg.locator(`${C} line.axis-y`).count() === 0, 'y축 선');
    const xs = await pg.$$eval(`${C} text.tick-x`, (els) => els.map((e) => [getComputedStyle(e).fontSize]));
    ok(xs.length && xs.every((x) => ['12px', '13px'].includes(x[0])), `축 글자 ${xs}`);
    const bars = await pg.$$eval('[data-chart="violations"] [data-bucket] rect.bar, [data-chart="violations"] [data-bucket] path.bar', (els) => els.map((e) => e.getBoundingClientRect().width));
    ok(bars.every((w) => w <= 22.5), `막대 폭 ${Math.max(...bars)}`);
    const d = await pg.$eval('[data-chart="results"]', (e) => [Number(e.dataset.inner), Number(e.dataset.outer), e.querySelector('[data-part="donut-center"]')?.textContent.trim()]);
    ok(near(d[0], 0.58, 0.005) && near(d[1], 0.84, 0.005), `도넛 ${d}`);
    const sum = await pg.evaluate(() => UI.srv.overview('24h').installs.total);
    ok(d[2] === String(sum), `가운데 ${d[2]} / ${sum}`);
    ok(await pg.locator('[data-chart="results"] path[data-slice]').count() >= 2, '도넛 조각');
    // 반전 툴팁
    const g = await pg.$eval(`${C} [data-bucket]:nth-of-type(12) rect.hit`, (e) => { const r = e.getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2]; });
    await pg.mouse.move(g[0], g[1]); await pg.waitForTimeout(200);
    const tip = await pg.$eval(`${C} .chart-tip`, (e) => [e.hidden, getComputedStyle(e).backgroundColor]);
    const ink = await pg.evaluate(() => { const x = document.createElement('i'); x.style.color = 'var(--ink)'; document.body.append(x); const c = getComputedStyle(x).color; x.remove(); return c; });
    ok(!tip[0] && tip[1] === ink, `툴팁 ${tip} / ${ink}`);
    ok(await pg.$$eval(`${C} circle`, (els) => els.filter((e) => getComputedStyle(e).opacity !== '0' && !e.closest('[hidden]')).length) >= 1, 'hover 점');
    // 첫 렌더만 그리기 애니메이션 — 기간을 바꿔 다시 그리면 없음
    await pg.click('[data-range="1h"]'); await pg.waitForTimeout(400);
    ok(await pg.locator('[data-section="overview"] .draw-in').count() === 0, '다시 그릴 때 애니메이션');
    // 0 이면 회색 고리
    const pz = await newPage();
    await go(pz, '/', '&fresh=1');
    const zero = await pz.$eval('[data-chart="results"]', (e) => [e.querySelectorAll('path[data-slice]').length, !!e.querySelector('circle.donut-zero'), e.querySelector('[data-part="donut-center"]').textContent.trim()]);
    ok(zero[0] === 0 && zero[1] && zero[2] === '0', `0 도넛 ${zero}`);
    await pz.done();
    await pg.done();
  });

  // ---------------- 12 다크 ----------------
  await T('12 다크: KPI · 패널 다크 토큰, 스크롤 0', async () => {
    const pg = await newPage({ colorScheme: 'dark' });
    await pg.addInitScript(() => { try { localStorage.setItem('supplyguard.theme', 'dark'); } catch { /* */ } });
    for (const s of ['/', '/audit']) {
      await go(pg, s);
      const bg = await pg.$eval('#page .panel, #page .ov-kpi', (e) => getComputedStyle(e).backgroundColor);
      ok(bg === 'rgb(23, 26, 33)', `${s} 카드 ${bg}`);
      const r = await scrollState(pg); ok(r.doc <= 0 && r.page <= 1 && !r.bad.length, `${s} 스크롤 ${JSON.stringify(r)}`);
    }
    await go(pg, '/'); await shot(pg, 'dashboard-dark');
    await go(pg, '/audit'); await shot(pg, 'table-dark');
    await pg.done();
  });

  // ---------------- 13 390 ----------------
  await T('13 390: 문서 스크롤 허용 · 가로 넘침 0 · KPI 2열', async () => {
    const pg = await newPage({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    await go(pg, '/');
    const r = await pg.evaluate(() => ({ docH: document.scrollingElement.scrollHeight - innerHeight, docW: document.documentElement.scrollWidth - innerWidth, cols: getComputedStyle(document.querySelector('.ov-kpis')).gridTemplateColumns.split(' ').length }));
    ok(r.docH > 0, '문서 스크롤이 없음(모바일은 문서 스크롤)');
    ok(r.docW <= 0, `가로 넘침 ${r.docW}`);
    ok(r.cols === 2, `KPI ${r.cols}열`);
    await shot(pg, 'dashboard-390');
    for (const s of ['/installs', '/audit', '/evaluation']) { await go(pg, s); const w = await pg.evaluate(() => document.documentElement.scrollWidth - innerWidth); ok(w <= 0, `${s} 가로 넘침 ${w}`); }
    await pg.done();
  });

  // ---------------- 14 평가 ----------------
  await T('14 평가: 머리 · 지표 고정, 몸통만 스크롤', async () => {
    const pg = await newPage({ viewport: { width: 1280, height: 720 } });
    await go(pg, '/evaluation'); await pg.waitForSelector('[data-part="evaluation"][data-state="ready"]');
    const r = await pg.evaluate(() => { const b = document.querySelector('.eval-body'); return b ? [b.hasAttribute('data-fill'), b.scrollHeight > b.clientHeight, document.querySelector('.eval-kpis').getBoundingClientRect().bottom <= b.getBoundingClientRect().top] : null; });
    ok(r && r[0] && r[1] && r[2], `평가 몸통 ${JSON.stringify(r)}`);
    const top0 = await pg.$eval('.eval-kpis', (e) => e.getBoundingClientRect().top);
    await pg.$eval('.eval-body', (e) => { e.scrollTop = 400; }); await pg.waitForTimeout(100);
    ok(await pg.$eval('.eval-kpis', (e) => e.getBoundingClientRect().top) === top0, '지표가 같이 스크롤됨');
    await pg.done();
  });

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
