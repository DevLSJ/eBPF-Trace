/* 11/04f AI 도우미 채팅 화면 회귀 — 우측 하단 도우미 패널의 「AI 도우미」 탭(사용자가 준 Uiverse.io 채팅 카드 CSS 는 구조 · 원리만, 토큰으로 다시 구현)
   ⓐ 머리줄 40px: 왼쪽 제목(보조색 · 말줄임) · 오른쪽 닫기 40×40 — 2px 선 두 개를 45° · 135° 로 교차한 X(글꼴 · 이미지 아님, 둥근 끝, hover 진해짐)
   ⓑ 대화 = 말풍선 대신 한 턴 한 줄 띠(사용자 · 도우미 바탕 한 단계씩 번갈아) · 행 패딩 10~12 · 긴 글 줄바꿈 · 코드 블록은 코드 창
   ⓒ 보내는 칸: 반경 7 입력칸(1px · 안쪽 바탕 한 단계 · placeholder 보조색 · 말줄임 · 포커스 링) + 30×30 보내기(글리프 아이콘, 못 보낼 때 흐림)
   높이: 패널을 채우고 대화 칸만 스크롤 · 새 메시지는 아래에서 6px 올라오며 등장(--t-base) — 이미 있던 줄은 다시 그려도 움직이지 않음 · reduced-motion 이면 없음
   + 기존 기능 · 문구(모델 안내 · 지우기 · 추천 질문 · 읽기 전용 안내 · 관련 화면 링크 · AI 꺼짐 안내) 그대로 · 다크 · 390 · 콘솔 오류 0
   실행: (mock/ 에서) python3 -m http.server 8768 --bind 127.0.0.1 → BASE=http://127.0.0.1:8768 PLAYWRIGHT=<playwright 경로> node tests/chat-1104.cjs
         (VERBOSE=1 · ONLY=정규식 · SHOTS=1 → screenshots/chat-1104-*.png) */
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
const P = '[data-part="assistant"]';
const LIST = '[data-part="chat-list"]';
const INPUT = `${P} .chat-input`;
const SEND = `${P} [aria-label="보내기"]`;

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
  const openChat = async (pg, extra = '') => {
    await pg.goto(`${BASE}?source=sim&as=admin${extra}#/`); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(400);
    await pg.evaluate(() => UI.assistant.open('chat'));
    await pg.waitForSelector(`${P} [role="tab"][data-tab="chat"][aria-selected="true"]`, W);
  };
  const ask = async (pg, q) => {
    const n = await pg.locator(`${LIST} .chat-msg.assistant [data-part="chat-links"]`).count();
    await pg.fill(INPUT, q); await pg.keyboard.press('Enter');
    await pg.waitForFunction(([L, k]) => document.querySelectorAll(`${L} .chat-msg.assistant [data-part="chat-links"]`).length > k || !document.querySelector('[aria-label="보내기"]').hasAttribute('data-busy'), [LIST, n], { timeout: 15000 });
    await pg.waitForFunction(() => !document.querySelector('[data-part="assistant"] [aria-label="보내기"]').hasAttribute('data-busy'), null, { timeout: 15000 });
  };
  const tok = (pg, v, prop = 'color') => pg.evaluate(([v, prop]) => { const t = document.createElement('i'); t.style[prop] = `var(${v})`; document.body.append(t); const c = getComputedStyle(t)[prop]; t.remove(); return c; }, [v, prop]);
  const shot = async (pg, name) => { if (!SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(300); await pg.screenshot({ path: path.join(SHOT_DIR, `chat-1104-${name}.png`) }); };

  await T('ⓐ 머리줄 40px · 제목 보조색 · 말줄임 · 닫기 40×40 안 2px 선 두 개(45° · 135°, 둥근 끝, 글자 없음) · hover 진해짐 · 눌러서 닫힘', async () => {
    const pg = await newPage();
    await openChat(pg);
    const m = await pg.evaluate((P) => {
      const cs = getComputedStyle, head = document.querySelector(`${P} .assist-head`), title = head.querySelector('.assist-title'), btn = head.querySelector('[aria-label="닫기"]');
      const lines = [...btn.querySelectorAll('.x-line')];
      return { head: Math.round(head.getBoundingClientRect().height), title: title && [cs(title).color, cs(title).textOverflow, cs(title).whiteSpace, cs(title).overflow, title.textContent],
        btn: [Math.round(btn.getBoundingClientRect().width), Math.round(btn.getBoundingClientRect().height), btn.textContent.trim(), btn.querySelector('img, svg') ? 'img' : ''],
        lines: lines.map((l) => [cs(l).height, cs(l).transform, parseFloat(cs(l).borderRadius) > 0, cs(l).backgroundColor]),
        right: Math.round(head.getBoundingClientRect().right - btn.getBoundingClientRect().right) };
    }, P);
    ok(m.head === 40, `머리줄 ${m.head}`);
    ok(m.title && m.title[0] === await tok(pg, '--text-2') && m.title[1] === 'ellipsis' && m.title[2] === 'nowrap' && m.title[3] === 'hidden' && m.title[4].includes('도우미'), `제목 ${JSON.stringify(m.title)}`);
    ok(m.btn[0] === 40 && m.btn[1] === 40 && m.btn[2] === '' && !m.btn[3], `닫기 ${JSON.stringify(m.btn)}`);
    const deg = (t) => { const v = (t.match(/matrix\(([^)]+)\)/) || [])[1]; if (!v) return null; const [a, b] = v.split(',').map(Number); return Math.round((Math.atan2(b, a) * 180) / Math.PI + 360) % 180; };
    ok(m.lines.length === 2 && m.lines.every((l) => l[0] === '2px' && l[2]) && JSON.stringify(m.lines.map((l) => deg(l[1])).sort((a, b) => a - b)) === '[45,135]', `X 선 ${JSON.stringify(m.lines)}`);
    ok(m.right <= 4, `닫기가 오른쪽 끝이 아님 ${m.right}`);
    await pg.hover(`${P} .assist-head [aria-label="닫기"]`); await pg.waitForTimeout(300);
    const hov = await pg.$$eval(`${P} .assist-head [aria-label="닫기"] .x-line`, (ls) => ls.map((l) => getComputedStyle(l).backgroundColor));
    ok(hov[0] !== m.lines[0][3], `hover 색 그대로 ${hov[0]}`);
    await pg.click(`${P} .assist-head [aria-label="닫기"]`); await pg.waitForTimeout(200);
    ok(await pg.$eval(P, (e) => e.hidden), '닫히지 않음');
    await pg.done();
  });

  await T('ⓑ 한 턴 한 줄 띠: 행 폭 = 대화 칸 · 바탕 사용자/도우미 번갈아(한 단계) · 말풍선 없음 · 패딩 10~12 · 긴 글 줄바꿈 · 관련 화면 링크 그대로', async () => {
    const pg = await newPage();
    await openChat(pg);
    await ask(pg, '판정 대기 요약해 줘');
    await ask(pg, `오늘 가장 많이 걸린 정책은? ${'아주긴글'.repeat(40)}`);
    const rows = await pg.evaluate((L) => {
      const list = document.querySelector(L), lw = list.clientWidth;
      return [...list.querySelectorAll('.chat-msg')].map((m) => { const b = m.querySelector('.bubble'), cs = getComputedStyle(m), bs = getComputedStyle(b);
        return [m.dataset.role, Math.round(m.getBoundingClientRect().width) >= lw - 1, cs.backgroundColor, parseFloat(cs.paddingTop), parseFloat(cs.paddingLeft), bs.backgroundColor, parseFloat(bs.borderTopLeftRadius), b.scrollWidth <= b.clientWidth + 1]; });
    }, LIST);
    ok(JSON.stringify(rows.map((r) => r[0])) === JSON.stringify(['user', 'assistant', 'user', 'assistant']), `행 ${JSON.stringify(rows.map((r) => r[0]))}`);
    ok(rows.every((r) => r[1]), `행 폭 ${JSON.stringify(rows.map((r) => r[1]))}`);
    const [s1, s2] = [await tok(pg, '--surface-2', 'backgroundColor'), await tok(pg, '--surface', 'backgroundColor')];
    ok(rows.filter((r) => r[0] === 'user').every((r) => r[2] === s1) && rows.filter((r) => r[0] === 'assistant').every((r) => r[2] === s2), `바탕 ${JSON.stringify(rows.map((r) => r[2]))} / ${s1} ${s2}`);
    ok(rows.every((r) => r[3] >= 10 && r[3] <= 12 && r[4] >= 10 && r[4] <= 12), `패딩 ${JSON.stringify(rows.map((r) => [r[3], r[4]]))}`);
    ok(rows.every((r) => r[5] === 'rgba(0, 0, 0, 0)' && r[6] === 0), `말풍선 남음 ${JSON.stringify(rows.map((r) => [r[5], r[6]]))}`);
    ok(rows.every((r) => r[7]), '긴 글이 넘침');
    ok(await pg.locator(`${LIST} .chat-msg.assistant [data-part="chat-links"] a`).count() >= 1, '관련 화면 링크');
    await shot(pg, 'light');
    await pg.done();
  });

  await T('ⓒ 입력칸: 반경 7 · 1px · 안쪽 바탕 한 단계 · placeholder 보조색 · 말줄임 · 포커스 링 / 보내기 30×30 글리프 · 비었거나 답 기다리는 중이면 흐림(disabled)', async () => {
    const pg = await newPage();
    await openChat(pg);
    const m = await pg.evaluate(([I, S, P]) => {
      const cs = getComputedStyle, i = document.querySelector(I), s = document.querySelector(S), panel = document.querySelector(P);
      return { tag: i.tagName, r: cs(i).borderTopLeftRadius, bw: cs(i).borderTopWidth, bs: cs(i).borderTopStyle, bg: cs(i).backgroundColor, panel: cs(panel).backgroundColor, ph: cs(i, '::placeholder').color, to: cs(i).textOverflow,
        send: [Math.round(s.getBoundingClientRect().width), Math.round(s.getBoundingClientRect().height), s.textContent.trim(), s.disabled, parseFloat(cs(s).opacity)] };
    }, [INPUT, SEND, P]);
    ok(m.r === '7px' && m.bw === '1px' && m.bs === 'solid', `입력칸 테두리 ${JSON.stringify(m)}`);
    ok(m.bg === await tok(pg, '--surface-2', 'backgroundColor') && m.bg !== m.panel, `입력칸 바탕 ${m.bg} / 패널 ${m.panel}`);
    ok(m.ph === await tok(pg, '--text-3'), `placeholder ${m.ph}`);
    ok(m.to === 'ellipsis', `말줄임 ${m.to}`);
    ok(m.send[0] === 30 && m.send[1] === 30 && m.send[2].length === 1 && m.send[2] !== '보' , `보내기 ${JSON.stringify(m.send)}`);
    ok(m.send[3] === true && m.send[4] < 0.6, `빈 입력인데 보낼 수 있음 ${JSON.stringify(m.send)}`);
    await pg.focus(INPUT);
    const ring = await pg.$eval(INPUT, (i) => [getComputedStyle(i).outlineStyle, getComputedStyle(i).outlineWidth, getComputedStyle(i).boxShadow]);
    ok((ring[0] !== 'none' && parseFloat(ring[1]) >= 2) || ring[2] !== 'none', `포커스 링 ${JSON.stringify(ring)}`);
    await pg.keyboard.type('판정 대기 요약해 줘'); await pg.waitForTimeout(250); // 흐림 해제 전환(--t-fast)이 끝난 뒤
    ok(await pg.$eval(SEND, (s) => !s.disabled && parseFloat(getComputedStyle(s).opacity) === 1), '글을 썼는데 잠김');
    await pg.click(SEND); await pg.waitForTimeout(150);
    ok(await pg.$eval(SEND, (s) => s.disabled && parseFloat(getComputedStyle(s).opacity) < 0.6), '답 기다리는 중인데 보낼 수 있음');
    await pg.waitForSelector(`${LIST} .chat-msg.assistant [data-part="chat-links"] a`, { timeout: 15000 });
    await pg.done();
  });

  await T('높이: 패널을 채우고 대화 칸만 스크롤(입력칸 · 안내는 패널 안에 고정)', async () => {
    const pg = await newPage({ viewport: { width: 1440, height: 760 } });
    await openChat(pg);
    for (const q of ['판정 대기 요약해 줘', '오늘 가장 많이 걸린 정책은?', '이 화면은 뭘 하는 곳이야?', '최근 공급망 검사 결과 알려 줘']) await ask(pg, q);
    const r = await pg.evaluate(([P, L, I]) => { const p = document.querySelector(P).getBoundingClientRect(), l = document.querySelector(L), i = document.querySelector(I).getBoundingClientRect(), note = document.querySelector(`${P} .chat-note`).getBoundingClientRect();
      const body = document.querySelector(`${P} .chat-body`);
      return { scroll: l.scrollHeight > l.clientHeight, overflowY: getComputedStyle(l).overflowY, input: [i.top >= p.top, i.bottom <= p.bottom], note: note.bottom <= p.bottom + 1, bodyScroll: body.scrollHeight - body.clientHeight, panelScroll: document.querySelector(P).scrollHeight - document.querySelector(P).clientHeight }; }, [P, LIST, INPUT]);
    ok(r.scroll && r.overflowY === 'auto', `대화 칸 스크롤 ${JSON.stringify(r)}`);
    ok(r.input.every(Boolean) && r.note && r.bodyScroll <= 0 && r.panelScroll <= 0, `칸 배치 ${JSON.stringify(r)}`);
    await pg.done();
  });

  await T('새 메시지 등장: 아래 6px → 제자리(--t-base) · 이미 있던 줄은 다시 그려도 등장 없음 / reduced-motion 이면 없음', async () => {
    for (const rm of ['no-preference', 'reduce']) {
      const pg = await newPage({ reducedMotion: rm });
      await openChat(pg);
      await pg.evaluate(() => { window.__anims = []; document.addEventListener('animationstart', (e) => { const m = e.target.closest && e.target.closest('.chat-msg'); if (m) window.__anims.push([m.dataset.role, e.animationName, Array.prototype.indexOf.call(m.parentElement.children, m)]); }, true); });
      await pg.fill(INPUT, '판정 대기 요약해 줘'); await pg.keyboard.press('Enter');
      await pg.waitForTimeout(40);
      const first = await pg.$eval(`${LIST} .chat-msg[data-role="user"]`, (m) => [getComputedStyle(m).animationName, getComputedStyle(m).animationDuration]);
      await pg.waitForSelector(`${LIST} .chat-msg.assistant [data-part="chat-links"] a`, { timeout: 15000 });
      const anims = await pg.evaluate(() => window.__anims);
      if (rm === 'reduce') ok(parseFloat(first[1]) < 0.02, `reduced-motion 등장 ${JSON.stringify(first)}`);
      else {
        ok(first[0] === 'chat-in' && Math.abs(parseFloat(first[1]) - 0.2) < 0.001, `등장 ${JSON.stringify(first)}`);
        ok(anims.length === 2 && anims.every((a) => a[1] === 'chat-in'), `등장은 새 줄 2개만(사용자 · 답 자리) ${JSON.stringify(anims)}`);
        const kf = await pg.evaluate(() => { for (const s of document.styleSheets) for (const r of s.cssRules) if (r.type === CSSRule.KEYFRAMES_RULE && r.name === 'chat-in') return r.cssText; return ''; });
        ok(/translateY\(6px\)/.test(kf) && /opacity: 0/.test(kf), `키프레임 ${kf}`);
      }
      await pg.done();
    }
  });

  await T('기존 기능 · 문구 그대로: 모델 안내 · 지우기 · 추천 질문 · 읽기 전용 안내 · 코드 블록 = 코드 창 · AI 꺼짐 안내', async () => {
    const pg = await newPage();
    await openChat(pg);
    const t = await pg.textContent(`${P} .chat-body`);
    ok(t.includes('로컬 모델 qwen2.5:3b · 데이터는 서버 밖으로 나가지 않음') && t.includes('읽기 전용 — 판정 · 정책 변경은 하지 않습니다.') && t.includes('판정 대기 요약해 줘'), '문구');
    await pg.evaluate(() => UI.runAttackNow()); await pg.waitForTimeout(500);
    await pg.evaluate(() => UI.assistant.open('chat'));
    const name = await pg.evaluate(() => UI.state.audit.find((a) => !a.event.containerName.startsWith('sg-install')).event.containerName);
    await ask(pg, `${name} 는 왜 격리됐어?`);
    ok(await pg.locator(`${LIST} .chat-msg.assistant .code-win`).count() === 1, '코드 창');
    await pg.click(`${P} [aria-label="대화 지우기"]`); await pg.waitForTimeout(200);
    ok(await pg.locator(`${LIST} .chat-msg[data-role="user"]`).count() === 0, '지우기');
    const p2 = await newPage();
    await openChat(p2, '&ai=off');
    ok((await p2.textContent(`${P} [data-part="chat-off"]`)).includes('AI 도우미가 꺼져 있습니다'), 'AI 꺼짐 안내');
    await p2.done(); await pg.done();
  });

  await T('다크: 행 바탕 번갈아 · 입력칸 바탕 · 글자 대비 · 머리줄 X 색', async () => {
    const pg = await newPage({ colorScheme: 'dark' });
    await openChat(pg);
    await ask(pg, '판정 대기 요약해 줘');
    const d = await pg.evaluate(([L, I, P]) => {
      const cs = getComputedStyle, rgb = (c) => (String(c).match(/[\d.]+/g) || []).slice(0, 3).map(Number);
      const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
      const ms = [...document.querySelectorAll(`${L} .chat-msg`)];
      const con = (m) => { const a = lum(rgb(cs(m).backgroundColor)), b = lum(rgb(cs(m.querySelector('.bubble')).color)); return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05); };
      return { theme: document.documentElement.dataset.theme, bgs: ms.map((m) => cs(m).backgroundColor), con: ms.map(con), input: cs(document.querySelector(I)).backgroundColor, panel: cs(document.querySelector(P)).backgroundColor, x: cs(document.querySelector(`${P} .x-line`)).backgroundColor };
    }, [LIST, INPUT, P]);
    ok(d.theme === 'dark' && d.bgs.length === 2 && d.bgs[0] !== d.bgs[1], `행 바탕 ${JSON.stringify(d)}`);
    ok(d.con.every((c) => c >= 4.5), `대비 ${d.con}`);
    ok(d.input !== d.panel && d.x !== 'rgba(0, 0, 0, 0)', `입력칸 · X ${JSON.stringify(d)}`);
    await shot(pg, 'dark');
    await pg.done();
  });

  await T('390: 패널 · 입력칸 · 보내기가 화면 안 · 가로 넘침 0', async () => {
    const pg = await newPage({ viewport: { width: 390, height: 844 } });
    await openChat(pg);
    await ask(pg, '판정 대기 요약해 줘');
    const r = await pg.evaluate(([P, S]) => { const p = document.querySelector(P).getBoundingClientRect(), s = document.querySelector(S).getBoundingClientRect(), l = document.querySelector('[data-part="chat-list"]'); return [p.left >= 0, p.right <= innerWidth, s.right <= p.right, document.documentElement.scrollWidth - innerWidth, l.scrollWidth - l.clientWidth]; }, [P, SEND]);
    ok(r[0] && r[1] && r[2] && r[3] <= 0 && r[4] <= 0, `390 ${JSON.stringify(r)}`);
    await shot(pg, 'mobile');
    await pg.done();
  });

  await T('콘솔 오류 0', async () => { ok(consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | ')); });

  await br.close();
  const pass = results.filter((r) => r[0]).length;
  for (const r of results) if (!r[0]) console.log(`FAIL  ${r[1]}  — ${r[2]}`);
  console.log(`chat-1104: ${pass}/${results.length}`);
  process.exit(pass === results.length ? 0 : 1);
})();
