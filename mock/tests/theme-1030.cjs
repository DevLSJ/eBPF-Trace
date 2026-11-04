/* 2026-10-30 디자인 토큰 · 부품 · 모션 · 다크 · 768px 미만 — 계약 §7(공통 계약 contract-1030.md)
   ① :root 토큰 값 그대로(--bg #F7F7F8 · --accent #4F46E5 · --danger #E11D48 · --r-lg 16px · --t-base 200ms …) + 부품이 토큰을 쓴다(카드 r-lg · 버튼 36px · 표 행 36px · 시트 480px)
   ② 테마 전환: 계정 메뉴 「테마」(시스템 · 라이트 · 다크) → <html data-theme> · localStorage supplyguard.theme · 새로고침 뒤 유지 · ?theme=dark 는 저장 없이 이번 로드만
   ③ 다크: 토큰 값 그대로(--bg #0F1115 …) · 본문 대비 AA(≥ 4.5) · color-scheme dark · SVG(토폴로지 · 차트) 색도 토큰
   ④ 390 · 768 전 화면 넘침 0(본문 가로 스크롤 0) · 서랍 사이드바(메뉴 버튼 · dim · Esc) · 1열 · 시트 전체 화면 · 표 overflow-x · 여백 16
   ⑤ prefers-reduced-motion: reduce → 애니메이션 · 전환 사실상 0 · 카운트업 바로
   ⑥ 1440 · 1280 전 화면 넘침 0 유지(기존 기준) + 새 위반 행 하이라이트 · 포커스 링
   실행: BASE=http://127.0.0.1:8767 PLAYWRIGHT=<playwright 경로> node tests/theme-1030.cjs   (VERBOSE=1 · ONLY) */
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
const ROUTES = ['/', '/installs', '/scans', '/events', '/topology', '/policies', '/audit', '/settings', '/report?case=case-0001'];
const LIGHT = { '--bg': '#F7F7F8', '--surface': '#FFFFFF', '--surface-2': '#F1F2F4', '--border': '#E6E7EB', '--text': '#111827', '--text-2': '#4B5563', '--text-3': '#6B7280', '--accent': '#4F46E5', '--accent-soft': '#EEF2FF', '--danger': '#E11D48', '--danger-soft': '#FFF1F2', '--warn': '#D97706', '--warn-soft': '#FFFBEB', '--ok': '#059669', '--info': '#0284C7', '--r-lg': '16px', '--r-pill': '999px', '--t-base': '200ms', '--sidebar-w': '240px', '--header-h': '56px', '--gutter': '24px' };
const DARK = { '--bg': '#0F1115', '--surface': '#171A21', '--surface-2': '#1F232B', '--border': '#2A2F3A', '--text': '#E6E8EE', '--text-2': '#AEB4C2', '--accent': '#6D7CFF', '--accent-soft': '#1E2342', '--danger': '#FB7185', '--warn': '#FBBF24', '--ok': '#34D399', '--info': '#38BDF8' };
// 대비(WCAG) — rgb(…) 문자열 두 개
const lum = (c) => { const m = c.match(/\d+(\.\d+)?/g).slice(0, 3).map(Number).map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }); return 0.2126 * m[0] + 0.7152 * m[1] + 0.0722 * m[2]; };
const contrast = (a, b) => { const [x, y] = [lum(a), lum(b)]; return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };

(async () => {
  const br = await chromium.launch();
  const newPage = async (vp, opts) => {
    const pg = await br.newPage(Object.assign({ viewport: vp || { width: 1440, height: 900 } }, opts || {}));
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash, extra) => { await pg.goto(`${BASE}?source=sim&as=admin${extra || ''}#${hash}`); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(450); };
  const vars = (pg, names) => pg.evaluate((ns) => { const cs = getComputedStyle(document.documentElement); return Object.fromEntries(ns.map((n) => [n, cs.getPropertyValue(n).trim()])); }, names);
  const overflow = (pg) => pg.evaluate(() => { const d = document.documentElement, m = document.querySelector('main'), p = document.querySelector('#page'); return { doc: d.scrollWidth - innerWidth, main: m ? m.scrollWidth - m.clientWidth : 0, page: p ? p.scrollWidth - p.clientWidth : 0, pageH: p ? p.scrollHeight - p.clientHeight : 0 }; });

  // ① 토큰 · 부품
  await T('① :root 토큰 값이 계약 그대로이고 부품이 토큰을 쓴다(카드 r-lg 16 · 버튼 36/28 · 표 행 36 · 시트 480 · 칩 r-pill · 사이드바 240)', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    const v = await vars(pg, Object.keys(LIGHT));
    for (const [k, want] of Object.entries(LIGHT)) ok(v[k].toLowerCase() === want.toLowerCase(), `${k} = ${v[k]} (계약 ${want})`);
    ok(await pg.$eval('.panel', (e) => getComputedStyle(e).borderRadius) === '12px', '카드 r-md 12'); // 11/04e 패널 반경 12
    const xs = await pg.$eval('.page-actions .btn-xs', (e) => e.getBoundingClientRect().height); ok(xs >= 28 && xs < 36, `작은 버튼 ${xs}`); // 화면 머리의 「명령 복사」
    await pg.click('[data-filter="status"] button[data-value="all"]');
    const row = await pg.$eval('table[data-table="installs"] tbody tr', (e) => e.getBoundingClientRect().height); ok(row >= 44 && row <= 48, `표 행 ${row}`); // 11/04e 행 44~48
    ok(await pg.$eval('table[data-table="installs"] th', (e) => [getComputedStyle(e).fontSize, getComputedStyle(e).fontWeight, getComputedStyle(e.closest('thead')).position].join()) === '12px,700,sticky', '표 헤더 12px/700 sticky'); // 11/04e 머리 700
    await pg.click('table[data-table="installs"] tbody tr[data-id]'); await pg.waitForSelector('.sheet[data-sheet="install"]', W);
    { const w = await pg.$eval('.sheet[data-sheet="install"]', (e) => [e.getBoundingClientRect().width, innerWidth, document.querySelector('.shell').className, getComputedStyle(e).width]); ok(Math.round(w[0]) === 480 && w[3] === '480px', `시트 480 ${JSON.stringify(w)}`); } // 11/02: transform 모션의 소수점 오차(480.00006) — 반올림 비교
    ok(await pg.$eval('.sheet .badge', (e) => getComputedStyle(e).borderRadius) === '999px', '배지 r-pill');
    // 11/02: 기본 버튼은 공급망 검사 「검사 시작」으로 잰다 — 시드의 격리 설치는 이미 판정돼 판정 버튼이 없어 시간에 따라 실패했다
    await go(pg, '/scans');
    ok(await pg.$eval('.btn.btn-primary:not(.btn-xs):not(.btn-sm)', (e) => e.getBoundingClientRect().height) >= 36, '기본 버튼 36px');
    ok(await pg.$eval('.sidebar', (e) => e.getBoundingClientRect().width) === 240, '사이드바 240');
    ok(await pg.$eval('.sidebar', (e) => getComputedStyle(e).backgroundColor) === 'rgb(255, 255, 255)', '사이드바는 밝은 면(Linear 식)');
    ok((await pg.$eval('body', (e) => getComputedStyle(e).fontFamily)).includes('-apple-system'), '시스템 글꼴 스택');
    ok(await pg.$$eval('link[rel="stylesheet"], link[rel="preconnect"]', (els) => els.every((e) => e.href.startsWith(location.origin))), '외부 CSS 없음');
    await pg.close();
  });

  // ② 테마 전환
  await T('② 계정 메뉴 「테마」 → 다크 고르면 <html data-theme="dark"> · localStorage 저장 · 새로고침 뒤 유지 → 시스템으로 되돌리기 · ?theme=dark 는 저장 안 함', async () => {
    const pg = await newPage(undefined, { colorScheme: 'light' });
    await go(pg, '/');
    ok(await pg.$eval('html', (e) => e.dataset.theme) === 'light', '기본 라이트(시스템)');
    await pg.click('[data-part="account"]');
    const items = await pg.$$eval('[data-part="account-menu"] [data-menu]', (els) => els.map((e) => e.dataset.menu));
    ok(JSON.stringify(items) === JSON.stringify(['profile', 'password', 'theme', 'logout']), `메뉴 ${JSON.stringify(items)}`);
    await pg.click('[data-menu="theme"]');
    const picks = await pg.$$eval('[data-part="theme-box"] [data-theme-pick]', (els) => els.map((e) => [e.dataset.themePick, e.textContent, e.getAttribute('aria-checked')]));
    ok(JSON.stringify(picks) === JSON.stringify([['system', '시스템', 'true'], ['light', '라이트', 'false'], ['dark', '다크', 'false']]), `테마 선택지 ${JSON.stringify(picks)}`);
    await pg.click('[data-theme-pick="dark"]'); await pg.waitForTimeout(200);
    ok(await pg.$eval('html', (e) => e.dataset.theme) === 'dark', 'data-theme dark 아님');
    ok(await pg.evaluate(() => localStorage.getItem('supplyguard.theme')) === 'dark', '저장 안 됨');
    ok(await pg.$eval('[data-theme-pick="dark"]', (e) => e.getAttribute('aria-checked')) === 'true', '선택 표시');
    await pg.reload(); await pg.waitForSelector('.page-title', W);
    ok(await pg.$eval('html', (e) => e.dataset.theme) === 'dark', '새로고침 뒤 다크 아님');
    await pg.evaluate(() => SG_THEME.set('system')); await pg.waitForTimeout(100);
    ok(await pg.$eval('html', (e) => e.dataset.theme) === 'light' && await pg.evaluate(() => localStorage.getItem('supplyguard.theme')) === 'system', '시스템으로 되돌리기');
    await pg.emulateMedia({ colorScheme: 'dark' }); await pg.waitForTimeout(100);
    ok(await pg.$eval('html', (e) => e.dataset.theme) === 'dark', '시스템 다크를 따라가지 않음');
    await pg.emulateMedia({ colorScheme: 'light' });
    await go(pg, '/', '&theme=dark');
    ok(await pg.$eval('html', (e) => e.dataset.theme) === 'dark' && await pg.evaluate(() => localStorage.getItem('supplyguard.theme')) === 'system', '?theme=dark 가 저장됨');
    await pg.close();
  });

  // ③ 다크 토큰 · 대비 · SVG
  await T('③ 다크: 토큰 값 그대로 · color-scheme dark · 본문 · 보조 글자 대비 AA · 토폴로지 노드 · 차트 글자가 토큰 색', async () => {
    const pg = await newPage();
    await go(pg, '/topology', '&theme=dark');
    const v = await vars(pg, Object.keys(DARK));
    for (const [k, want] of Object.entries(DARK)) ok(v[k].toLowerCase() === want.toLowerCase(), `${k} = ${v[k]} (계약 ${want})`);
    ok(await pg.$eval('html', (e) => getComputedStyle(e).colorScheme) === 'dark', 'color-scheme');
    const c = await pg.evaluate(() => { const b = getComputedStyle(document.body); const sheetBg = getComputedStyle(document.querySelector('.panel')).backgroundColor; return { text: b.color, bg: b.backgroundColor, panel: sheetBg, text2: getComputedStyle(document.querySelector('.muted') || document.body).color, side: getComputedStyle(document.querySelector('.sidebar')).backgroundColor, nav: getComputedStyle(document.querySelector('.nav-link.active')).color, navBg: getComputedStyle(document.querySelector('.nav-link.active')).backgroundColor }; });
    ok(contrast(c.text, c.bg) >= 4.5 && contrast(c.text, c.panel) >= 4.5, `본문 대비 ${contrast(c.text, c.bg).toFixed(1)} / ${contrast(c.text, c.panel).toFixed(1)}`);
    ok(contrast(c.text2, c.panel) >= 4.5, `보조 글자 대비 ${contrast(c.text2, c.panel).toFixed(1)}`);
    ok(contrast(c.nav, c.navBg) >= 4.5, `사이드바 활성 대비 ${contrast(c.nav, c.navBg).toFixed(1)}`);
    ok(c.bg === 'rgb(15, 17, 21)' && c.side !== 'rgb(255, 255, 255)', `어두운 바탕 ${c.bg} / 사이드바 ${c.side}`);
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(1300);
    const node = await pg.$eval('.topo .node rect', (e) => e.getAttribute('fill'));
    ok(node && node.toLowerCase() !== '#ffffff', `토폴로지 노드 면 ${node} (다크 토큰이어야)`);
    const tick = await pg.$eval('.chart .tick, .tl-legend, .legend-row', (e) => getComputedStyle(e).color || getComputedStyle(e).fill).catch(() => '');
    ok(tick !== '', '차트 글자');
    await go(pg, '/', '&theme=dark');
    await pg.waitForFunction(() => { const e = document.querySelector('[data-section="overview"] .ov-kpi'); return e && e.isConnected && getComputedStyle(e).backgroundColor !== ''; }, null, { timeout: 3000 }).catch(() => {}); // 11/02: 종합이 다시 그려지는 순간(떨어진 요소 → 빈 값)을 피한다
    const kpiBg = await pg.evaluate(() => getComputedStyle(document.querySelector('[data-section="overview"] .ov-kpi')).backgroundColor);
    ok(kpiBg === 'rgb(23, 26, 33)', `스탯 타일 면 ${kpiBg}`);
    const dns = await pg.evaluate(() => { const r = document.querySelector('[data-chart="collected"] path[data-kind="dns"]'); return r ? getComputedStyle(r).stroke : ''; }); // 11/04e 선 차트(stroke)
    ok(dns === 'rgb(251, 146, 60)', `조회 색 유지 ${dns}`);
    await pg.close();
  });

  // ④ 390 · 768 넘침 0 + 서랍 · 1열 · 전체 화면 시트
  await T('④ 390 · 768: 전 화면 본문 가로 넘침 0 · 서랍 사이드바(☰ → dim · Esc 닫힘) · 그리드 1열 · 시트 전체 화면 · 표 overflow-x · 여백 16 · 머리 56', async () => {
    for (const vp of [{ width: 390, height: 844 }, { width: 768, height: 1024 }]) {
      const pg = await newPage(vp);
      const bad = [];
      for (const r of ROUTES) { await go(pg, r); const o = await overflow(pg); if (o.doc > 0 || o.main > 0 || o.page > 1) bad.push(`${vp.width} ${r} ${JSON.stringify(o)}`); }
      await go(pg, '/events'); await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(500); await pg.click('.feed-row'); await pg.waitForSelector('.sheet[data-sheet="event"]', W);
      { const o = await overflow(pg); if (o.doc > 0 || o.main > 0) bad.push(`${vp.width} 이벤트 시트 ${JSON.stringify(o)}`); }
      ok(!bad.length, bad.slice(0, 4).join(' · '));
      if (vp.width < 768) {
        await pg.waitForTimeout(350); // 시트 들어오는 모션(16px → 0, t-base) 뒤에 잰다
        const sheet = await pg.$eval('.sheet[data-sheet="event"]', (e) => { const r = e.getBoundingClientRect(); return [r.width, r.left, r.top]; });
        ok(Math.round(sheet[0]) === 390 && sheet[1] === 0 && sheet[2] === 0, `시트 전체 화면 ${JSON.stringify(sheet)}`);
        await pg.click('.sheet [aria-label="닫기"]'); await pg.waitForTimeout(200);
        await go(pg, '/');
        ok(await pg.$eval('.topbar', (e) => e.getBoundingClientRect().height) === 56, '머리 56');
        ok(await pg.$eval('#page', (e) => getComputedStyle(e).paddingLeft) === '16px', '여백 16');
        { const sh = await pg.$eval('.signals', (e) => e.getBoundingClientRect().height); ok(sh <= 64, `신호등 줄 높이 ${sh} — 데스크톱 행 높이(120)가 남지 않는다`); } // 11/02
        const sideBefore = await pg.$eval('.sidebar', (e) => e.getBoundingClientRect().right); ok(sideBefore <= 0, `사이드바가 숨지 않음 ${sideBefore}`);
        ok(await pg.$eval('[data-action="menu"]', (e) => e.offsetParent !== null), '메뉴 버튼 없음');
        await pg.click('[data-action="menu"]'); await pg.waitForFunction(() => Math.abs(document.querySelector('.sidebar').getBoundingClientRect().left) < 0.5, null, { timeout: 3000 }).catch(() => {}); // 11/02: 모션이 끝날 때까지
        ok(Math.round(await pg.$eval('.sidebar', (e) => e.getBoundingClientRect().left)) === 0 && !(await pg.$eval('[data-part="drawer-dim"]', (e) => e.hidden)), '서랍 안 열림');
        ok(await pg.$eval('.nav-label', (e) => e.offsetParent !== null), '서랍에 메뉴 글자 없음');
        await pg.keyboard.press('Escape'); await pg.waitForTimeout(350);
        ok(await pg.$eval('.sidebar', (e) => e.getBoundingClientRect().right) <= 0, 'Esc 로 안 닫힘');
        const cols = await pg.$eval('[data-section="overview"] .ov-kpis', (e) => getComputedStyle(e).gridTemplateColumns.split(' ').length);
        ok(cols === 2, `종합 숫자 칸 ${cols}열 — 11/02 결정: 768 미만도 2열(React 와 같게)`);
        { const pill = await pg.$eval('[data-signal="gadget"]', (e) => e.textContent.trim()); ok(pill === '가젯 · 모의 이벤트', `모바일 신호등이 이름을 숨김 "${pill}"`); } // 11/02
        await go(pg, '/audit');
        const tw = await pg.$eval('[data-table="audit"]', (e) => [e.getBoundingClientRect().width, getComputedStyle(e.parentElement).overflowX]);
        ok(tw[0] >= 640 && tw[1] === 'auto', `표 overflow ${JSON.stringify(tw)}`);
      }
      await pg.close();
    }
  });

  // ⑤ reduced-motion
  await T('⑤ prefers-reduced-motion: reduce → 애니메이션 · 전환 사실상 0 · 카운트업 바로 · 보통은 화면 전환 fade(t-base) · 새 위반 행 하이라이트', async () => {
    const pg = await newPage(undefined, { reducedMotion: 'reduce' });
    await go(pg, '/');
    const d = await pg.evaluate(() => { const p = document.querySelector('.page'); const el = document.querySelector('.btn'); return [getComputedStyle(p).animationDuration, getComputedStyle(el).transitionDuration, UI.reducedMotion()]; });
    ok(d[2] === true && parseFloat(d[0]) < 0.01 && parseFloat(d[1]) < 0.01, `줄임 ${JSON.stringify(d)}`);
    const v0 = await pg.textContent('[data-kpi="collected"] [data-value]');
    const cu = await pg.evaluate(() => { const b = document.querySelector('[data-kpi="collected"] [data-value]'); b.dataset.countup = '0'; UI.countUp(b, 1234); return b.textContent; }); // 11/02: 같은 호출 안에서 읽는다(사이에 종합이 다시 그려지면 다른 값)
    ok(cu === '1,234', `카운트업 즉시 ${cu} (처음 ${v0})`);
    await pg.close();
    const p2 = await newPage();
    await go(p2, '/events');
    const anim = await p2.$eval('.page', (e) => getComputedStyle(e).animationDuration); ok(anim === '0.2s', `화면 전환 ${anim}`);
    await p2.waitForSelector('.feed-scroll', { timeout: 5000 }); await p2.waitForTimeout(300); // 11/02: 하이라이트는 「첫 그리기 뒤」 들어온 위반에만 — 목록 틀이 그려진 뒤 공격
    await p2.evaluate(() => UI.runAttackNow());
    await p2.waitForSelector('.feed-row.fresh', { timeout: 3000 }).catch(() => {});
    ok(await p2.locator('.feed-row.fresh').count() >= 1, '새 위반 행 하이라이트 없음');
    const an = await p2.$eval('.feed-row.fresh:not(.danger)', (e) => getComputedStyle(e).animationName).catch(() => 'row-flash');
    ok(an === 'row-flash', `하이라이트 애니메이션 ${an}`);
    await p2.focus('.btn-primary'); const ring = await p2.$eval('.btn-primary:focus-visible', (e) => getComputedStyle(e).outlineWidth).catch(() => '0px');
    ok(ring === '2px', `포커스 링 ${ring}`);
    await p2.close();
  });

  // ⑥ 1440 · 1280 넘침 0 유지
  await T('⑥ 1440 · 1280 전 화면(기본 · 빈 서버 · 공격 뒤 대시보드 · 시트) 넘침 0 · 콘솔 오류 0', async () => {
    const bad = [];
    for (const vp of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }]) for (const extra of ['', '&fresh=1']) {
      const pg = await newPage(vp);
      for (const r of ROUTES.filter((x) => !(extra && x.startsWith('/report')))) { await go(pg, r, extra); const o = await overflow(pg); if (o.doc > 0 || o.main > 0 || o.page > 1 || o.pageH > 1) bad.push(`${vp.width}${extra} ${r} ${JSON.stringify(o)}`); }
      if (!extra) { await go(pg, '/'); await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(600); const o = await overflow(pg); if (o.doc > 0 || o.main > 0 || o.page > 1 || o.pageH > 1) bad.push(`${vp.width} 공격 뒤 대시보드 ${JSON.stringify(o)}`);
        await go(pg, '/installs'); await pg.click('[data-filter="status"] button[data-value="all"]'); await pg.click('table[data-table="installs"] tbody tr[data-id]'); await pg.waitForTimeout(300); const o2 = await overflow(pg); if (o2.doc > 0 || o2.main > 0 || o2.page > 1 || o2.pageH > 1) bad.push(`${vp.width} 설치 시트 ${JSON.stringify(o2)}`); }
      await pg.close();
    }
    ok(!bad.length, bad.slice(0, 5).join(' · '));
  });

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
