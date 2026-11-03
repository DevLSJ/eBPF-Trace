/* 2026-10-30 DNS 질의 규칙(kind: dns) — 계약 §1(공통 계약 contract-1030.md)
   ① 엔진 매칭 순서 · 사유 문구(denyHosts → allowHosts 통과 → denyQtypes → 라벨 길이 → 이름 길이 → 허용 목록 밖, 점 없는 이름 · *.arpa 제외)
   ② 기본 규칙 2개(runtime-dns-exfil · sandbox-dns) · 정책 목록 짧은 라벨 「조회」 · 새 기본 규칙 모의 값(missing · differs)은 그대로
   ③ 템플릿 「DNS 유출 패턴 차단」 → 쉬운 설정(도메인 조회 · 어떤 도메인 · 질의인가요? · 라벨 · 이름 길이 상한) · 요약
   ④ 고급 · YAML 왕복(kind: dns · denyQtypes · maxLabelLength) · dns 에 connect 전용 필드는 거부
   ⑤ 이벤트: dns 배지(amber) · 상세 「<이름> (<질의 유형>)」 · 종류 필터 dns(도메인 조회) · 시트에 「도메인 조회」 줄 없음
   ⑥ 데모 제어 「DNS 유출 질의 지금 실행」 → runtime-dns-exfil 경고 2건 / ?dns=off 면 질의 자체가 없음
   ⑦ 설치 dnsExfil → 시트 활동 요약 「조회」 타일 · 공격 체인 「3 통신」 · sandbox-dns 격리(11/03 dryRun 해제)
   ⑧ 종합: 수집한 이벤트 「조회 N」 · 차트 조각 dns · 감사 로그 kind=dns 필터 · 설정 도메인 판단 off 문구 · 대응 가이드 egress 묶음
   실행: (mock/ 에서) python3 -m http.server 8767 --bind 127.0.0.1 → BASE=http://127.0.0.1:8767 PLAYWRIGHT=<playwright 경로> node tests/dns-1030.cjs   (VERBOSE=1 · ONLY) */
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const BASE = (process.env.BASE || 'http://127.0.0.1:8767').replace(/\/index\.html$/, '').replace(/\/$/, '') + '/index.html';
const results = []; const consoleErrors = [];
const T = async (name, fn) => {
  if (process.env.ONLY && !new RegExp(process.env.ONLY).test(name)) return;
  try { await fn(); results.push([true, name]); } catch (e) { results.push([false, name, e.message.split('\n')[0]]); }
  if (process.env.VERBOSE) { const r = results[results.length - 1]; console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`); }
};
const ok = (c, m) => { if (!c) throw new Error(m); };
const W = { timeout: 5000 };
const ED = '[data-view="rule-editor"]';

(async () => {
  const br = await chromium.launch();
  const newPage = async (vp) => {
    const pg = await br.newPage({ viewport: vp || { width: 1440, height: 900 } });
    await pg.route('https://api.osv.dev/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*' }, body: '{}' }));
    pg.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${pg.url()} ${m.text()}`); });
    pg.on('pageerror', (e) => consoleErrors.push(`${pg.url()} PAGEERROR ${e.message}`));
    return pg;
  };
  const go = async (pg, hash, extra) => { await pg.goto(`${BASE}?source=sim&as=admin${extra || ''}#${hash}`); await pg.waitForSelector('.page-title', W); await pg.waitForTimeout(450); };
  const chips = (pg, key) => pg.$$eval(`${ED} [data-chips="${key}"] [data-chip]`, (els) => els.map((e) => `${e.dataset.type}:${e.dataset.value}`));
  const dnsEv = (host, qtype, c) => ({ kind: 'dns', comm: 'python3', dstHost: host, qtype, dstIp: '127.0.0.11', dstPort: 53, containerName: c || 'sg-install-pip-1-1', imageName: 'python:3.12-slim', timestamp: new Date().toISOString() });

  // ① 엔진 매칭 순서 · 사유 문구
  await T('① 엔진: 매칭 6경로의 순서와 사유 문구가 계약 그대로 (denyHosts → allowHosts 통과 → denyQtypes → 라벨 → 이름 → 허용 목록 밖, 점 없는 이름 · .arpa 제외)', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const r = await pg.evaluate((ev) => {
      const M = window.MOCK, E = (h, q, c) => Object.assign({}, ev, { dstHost: h, qtype: q, containerName: c || ev.containerName });
      const user = [{ id: 'block-c2-dns', kind: 'dns', action: 'kill', denyHosts: ['attacker.test'], denyQtypes: ['TXT', 'ALL'] }, ...M.rules];
      const only = (rs, e) => { const v = M.evaluate(rs, e); return v.matched ? `${v.ruleId}|${v.action}${v.dryRun ? '(dry)' : ''}|${v.reason}` : 'pass'; };
      const long = 'a'.repeat(30) + '.' + 'b'.repeat(30) + '.' + 'c'.repeat(30) + '.' + 'd'.repeat(30) + '.example.com';
      return {
        deny: only(user, E('c2.attacker.test', 'A')), // ① denyHosts 가 allowHosts(sandbox-dns) 보다 먼저 — 그런데 user 규칙 kill 이 가장 강함
        allowPass: only(M.rules, E('files.pythonhosted.org', 'A')), // ② allowHosts 통과(sandbox-dns), runtime-dns-exfil 도 조건 없음
        allowPassTxt: only(M.rules, E('pypi.org', 'TXT')), // ② sandbox-dns 는 통과, ③ runtime-dns-exfil TXT 는 경고
        qtype: only(user, E('data.example.net', 'ALL', 'web-api')), // ③ denyQtypes(ALL) — 런타임 컨테이너
        label: only(M.rules, E(M.DNS_EXFIL_NAME, 'A')), // ④ 라벨 48 > 40 (sandbox-dns kill 이 runtime-dns-exfil alert 보다 강함)
        labelRuntime: only(M.rules, E(M.DNS_EXFIL_NAME, 'A', 'web-api')), // ④ 런타임: runtime-dns-exfil 경고
        name: only(M.rules, E(long, 'A', 'web-api')), // ⑤ 이름 135 > 120
        outside: only(M.rules, E('data.exfil.example', 'TXT')), // ⑥ 허용 목록 밖(sandbox-dns) > ③ TXT(runtime)
        noDot: only(M.rules, E('localhost', 'A')), arpa: only(M.rules, E('11.0.113.203.in-addr.arpa', 'PTR')), local: only(M.rules, E('printer.local', 'A')), // ⑥ 제외
        runtimeOutside: only(M.rules, E('data.exfil.example', 'A', 'web-api')), // 런타임엔 allowHosts 규칙이 없어 통과
      };
    }, dnsEv('x', 'A'));
    ok(r.deny === 'block-c2-dns|kill|block-c2-dns: 금지 도메인 질의: c2.attacker.test (A)', `① ${r.deny}`);
    ok(r.allowPass === 'pass', `② ${r.allowPass}`);
    ok(r.allowPassTxt === 'runtime-dns-exfil|alert|runtime-dns-exfil: 금지 질의 유형: TXT — pypi.org', `②③ ${r.allowPassTxt}`);
    ok(r.qtype === 'block-c2-dns|kill|block-c2-dns: 금지 질의 유형: ALL — data.example.net', `③ ${r.qtype}`);
    ok(r.label === `sandbox-dns|kill|sandbox-dns: 긴 DNS 라벨(유출 의심): ${'deadbeef'.repeat(6)}.exfil.example (라벨 48자 > 40)`, `④ ${r.label}`);
    ok(r.labelRuntime === `runtime-dns-exfil|alert|runtime-dns-exfil: 긴 DNS 라벨(유출 의심): ${'deadbeef'.repeat(6)}.exfil.example (라벨 48자 > 40)`, `④ 런타임 ${r.labelRuntime}`);
    ok(/^runtime-dns-exfil\|alert\|runtime-dns-exfil: 긴 DNS 이름\(유출 의심\): a{30}\.b{30}\.c{30}\.d{30}\.example\.com \(135자 > 120\)$/.test(r.name), `⑤ ${r.name}`);
    ok(r.outside === 'sandbox-dns|kill|sandbox-dns: 허용 목록 밖 도메인 질의: data.exfil.example (TXT)', `⑥ ${r.outside}`);
    ok(r.noDot === 'pass' && r.arpa === 'pass' && r.local === 'pass', `⑥ 제외 ${r.noDot} ${r.arpa} ${r.local}`);
    ok(r.runtimeOutside === 'pass', `런타임 통과 ${r.runtimeOutside}`);
    await pg.close();
  });

  // ② 기본 규칙 2개 · 목록 라벨 · 새 기본 규칙 모의 값 유지
  await T('② 기본 규칙 runtime-dns-exfil(alert · 40 · 120 · TXT) · sandbox-dns(kill · sg-install-* · 허용 10개 · 40 — 11/03 dryRun 해제) + 정책 목록 라벨 「조회」 + defaults missing/differs 그대로', async () => {
    const pg = await newPage();
    await go(pg, '/policies');
    const r = await pg.evaluate(async () => {
      const R = UI.state.rules, a = R.find((x) => x.id === 'runtime-dns-exfil'), b = R.find((x) => x.id === 'sandbox-dns');
      const d = await UI.api.policyDefaults();
      return { a, b, missing: d.missing.map((x) => x.id), differs: d.differs.map((x) => x.id), ids: R.map((x) => x.id) };
    });
    ok(r.a && r.a.kind === 'dns' && r.a.action === 'alert' && r.a.maxLabelLength === 40 && r.a.maxNameLength === 120 && JSON.stringify(r.a.denyQtypes) === '["TXT"]', `runtime-dns-exfil ${JSON.stringify(r.a)}`);
    ok(r.b && r.b.kind === 'dns' && r.b.action === 'kill' && !r.b.dryRun && JSON.stringify(r.b.containers) === '["sg-install-*"]' && r.b.allowHosts.length === 10 && r.b.allowHosts.includes('static.crates.io') && r.b.maxLabelLength === 40 && !r.b.maxNameLength, `sandbox-dns ${JSON.stringify(r.b)}`);
    ok(JSON.stringify(r.missing) === '["runtime-direct-ip"]' && JSON.stringify(r.differs) === '["sandbox-egress"]', `defaults ${JSON.stringify([r.missing, r.differs])}`);
    ok(r.ids.indexOf('runtime-dns-exfil') < r.ids.indexOf('blocklist-hosts'), '시스템 규칙은 끝');
    const labels = await pg.$$eval('[data-section="rules"] .rule-row', (els) => els.map((e) => [e.querySelector('.rule-name small').textContent, e.querySelector('.badge-kind').textContent]));
    ok(labels.some(([id, k]) => id === 'runtime-dns-exfil' && k === '조회') && labels.some(([id, k]) => id === 'sandbox-dns' && k === '조회'), `목록 라벨 ${JSON.stringify(labels.filter(([id]) => /dns/.test(id)))}`);
    ok(labels.some(([id, k]) => id === 'sandbox-egress' && k === '통신'), '기존 라벨 유지');
    await pg.close();
  });

  // ③ 템플릿 → 쉬운 설정
  await T('③ 템플릿 「DNS 유출 패턴 차단」 → ① 도메인 조회 선택 · ② 「어떤 도메인 · 질의인가요?」 막을 도메인 · 질의 유형(TXT) · 허용할 도메인 · 라벨 40 · 이름 120 · 요약 문장', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=__new__');
    await pg.waitForSelector('[data-view="templates"]', W);
    const tpl = await pg.$eval('[data-view="templates"] [data-template="dns-exfil"]', (e) => [e.querySelector('b').textContent, e.querySelector('small').textContent, e.querySelector('.tpl-kind').textContent]);
    ok(tpl[0] === 'DNS 유출 패턴 차단' && tpl[1] === '긴 라벨 · 긴 이름 · TXT 질의를 알림' && tpl[2] === '도메인 조회', `템플릿 ${JSON.stringify(tpl)}`);
    await pg.click('[data-view="templates"] [data-template="dns-exfil"]');
    await pg.waitForSelector(ED, W);
    ok(await pg.isChecked(`${ED} [data-step="what"] input[value="dns"]`), '도메인 조회 선택 안 됨');
    const what = await pg.$eval(`${ED} [data-step="what"] input[value="dns"]`, (e) => e.closest('label').textContent);
    ok(what.includes('도메인 조회') && what.includes('어떤 도메인을 조회하는지 봅니다'), `① 문구 ${what}`);
    ok((await pg.textContent(`${ED} [data-step="values"] h3`)).includes('어떤 도메인 · 질의인가요?'), '② 제목');
    const labels = await pg.$$eval(`${ED} [data-step="values"] .chip-label`, (els) => els.map((e) => [e.querySelector('b').textContent, e.querySelector('small').textContent.trim()]));
    ok(labels[0][0] === '막을 도메인 · 질의 유형' && labels[0][1] === '도메인(예: attacker.test) 또는 질의 유형(TXT) — 허용 목록과 상관없이 위반', `막을 그룹 ${JSON.stringify(labels[0])}`);
    ok(labels[1][0] === '허용할 도메인' && labels[1][1] === '하나라도 넣으면 여기 없는 도메인 질의는 모두 위반 — 점 없는 이름 · *.arpa 는 제외', `허용 그룹 ${JSON.stringify(labels[1])}`);
    ok((await chips(pg, 'block')).includes('qtype:TXT'), `칩 ${JSON.stringify(await chips(pg, 'block'))}`);
    const nums = await pg.$$eval(`${ED} [data-part="dns-limits"] label`, (els) => els.map((e) => [e.querySelector('b').textContent, e.querySelector('input').dataset.field, e.querySelector('input').value]));
    ok(JSON.stringify(nums) === JSON.stringify([['라벨 길이 상한', 'maxLabelLength', '40'], ['이름 길이 상한', 'maxNameLength', '120']]), `숫자 칸 ${JSON.stringify(nums)}`);
    const sum = await pg.textContent(`${ED} [data-summary]`);
    ok(sum.includes('TXT 질의') && sum.includes('40자') && sum.includes('120자') && sum.includes('알림'), `요약 ${sum}`);
    // 막을 칩에 도메인 · 질의 유형 입력 — 알아서 나뉜다, 틀린 값은 거부
    const input = `${ED} [data-chips="block"] input.chip-input`;
    await pg.fill(input, 'attacker.test'); await pg.press(input, 'Enter'); await pg.waitForTimeout(100);
    await pg.fill(input, 'all'); await pg.press(input, 'Enter'); await pg.waitForTimeout(100);
    const c2 = await chips(pg, 'block');
    ok(c2.includes('host:attacker.test') && c2.includes('qtype:all'), `칩 분류 ${JSON.stringify(c2)}`);
    await pg.fill(input, 'not a domain!'); await pg.press(input, 'Enter'); await pg.waitForTimeout(100);
    ok(!(await pg.$eval(`${ED} [data-chips="block"] [data-chip-error]`, (e) => e.hidden)), '틀린 값 거부 안 됨');
    await pg.close();
  });

  // ④ YAML 왕복 · 검증
  await T('④ 고급 · YAML 왕복: kind: dns · denyQtypes · maxLabelLength · maxNameLength 가 남고 돌아온다 / dns 에 allowPorts 는 거부 / 조건 없는 dns 거부', async () => {
    const pg = await newPage();
    await go(pg, '/policies?id=runtime-dns-exfil');
    await pg.waitForSelector(ED, W);
    await pg.click(`${ED} [data-mode="yaml"]`);
    const y = await pg.inputValue(`${ED} textarea.yaml`);
    ok(/kind: dns/.test(y) && /maxLabelLength: 40/.test(y) && /maxNameLength: 120/.test(y) && /denyQtypes:\n\s+- TXT/.test(y) && !/allowPorts/.test(y), `YAML ${y}`);
    await pg.fill(`${ED} textarea.yaml`, y.replace('maxLabelLength: 40', 'maxLabelLength: 32').replace(/denyQtypes:\n\s+- TXT/, 'denyQtypes:\n  - txt\n  - ALL'));
    await pg.click(`${ED} [data-mode="easy"]`); await pg.waitForTimeout(150);
    const c = await chips(pg, 'block');
    ok(c.includes('qtype:TXT') && c.includes('qtype:ALL'), `되돌린 칩 ${JSON.stringify(c)} (대문자 정규화)`);
    ok(await pg.inputValue(`${ED} [data-field="maxLabelLength"]`) === '32', '숫자 칸 되돌림');
    // 저장 전 확인까지(검증 통과) → 요약
    await pg.click(`${ED} button:has-text("저장 전 확인")`);
    await pg.waitForSelector('[data-part="save-check"]', W);
    ok((await pg.textContent('[data-part="save-check"] [data-summary]')).includes('32자'), '저장 전 확인 요약');
    // connect 전용 필드는 거부 · 조건 없는 dns 거부
    await go(pg, '/policies?id=__new__');
    await pg.click('[data-view="templates"] [data-template="dns-exfil"]'); await pg.waitForSelector(ED, W);
    await pg.click(`${ED} [data-mode="yaml"]`);
    const y2 = await pg.inputValue(`${ED} textarea.yaml`);
    await pg.fill(`${ED} textarea.yaml`, y2 + '\nallowPorts:\n  - 53\n');
    await pg.click(`${ED} button:has-text("저장 전 확인")`); await pg.waitForTimeout(150);
    const err1 = await pg.textContent(`${ED} .foot .tone-danger`).catch(() => '');
    ok(/allowPorts 는 dns 규칙에서 쓸 수 없습니다/.test(err1), `connect 전용 필드 거부 "${err1}"`);
    await pg.fill(`${ED} textarea.yaml`, 'id: dns-empty\nkind: dns\naction: alert\n');
    await pg.click(`${ED} button:has-text("저장 전 확인")`); await pg.waitForTimeout(150);
    const err2 = await pg.textContent(`${ED} .foot .tone-danger`).catch(() => '');
    ok(/조건이 하나 이상 필요/.test(err2), `조건 없음 거부 "${err2}"`);
    await pg.fill(`${ED} textarea.yaml`, 'id: dns-bad\nkind: dns\naction: alert\nmaxLabelLength: 99\n');
    await pg.click(`${ED} button:has-text("저장 전 확인")`); await pg.waitForTimeout(150);
    ok(/maxLabelLength: 1~63 정수/.test(await pg.textContent(`${ED} .foot .tone-danger`).catch(() => '')), '라벨 상한 범위 거부');
    await pg.close();
  });

  // ⑤ 이벤트 · 감사: 배지 · 상세 · 필터 · 시트
  await T('⑤ 이벤트: dns 행 배지(amber) · 상세 「<이름> (<질의 유형>)」 · 종류 필터 dns(도메인 조회) · 시트에 connect 의 「도메인 조회」 줄 없음 · 감사 로그 kind=dns 필터', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    await pg.evaluate(() => UI.runDnsExfilNow()); await pg.waitForTimeout(500);
    const rows = await pg.$$eval('.feed-row:has(.badge-kind-dns)', (els) => els.map((e) => [e.querySelector('.badge-kind').textContent, e.querySelector('.c-detail').textContent, e.querySelector('.c-rule').textContent, e.querySelector('.c-verdict').textContent]));
    ok(rows.length === 2, `dns 위반 행 ${rows.length}`);
    ok(rows.some((r) => r[1] === 'data.exfil.example (TXT)') && rows.some((r) => r[1] === `${'deadbeef'.repeat(6)}.exfil.example (A)`), `상세 ${JSON.stringify(rows)}`);
    ok(rows.every((r) => r[0] === 'dns' && r[2] === 'runtime-dns-exfil' && r[3] === '경고'), `배지 · 규칙 · 결과 ${JSON.stringify(rows)}`);
    const bg = await pg.$eval('.feed-row .badge-kind-dns', (e) => [getComputedStyle(e).backgroundColor, getComputedStyle(document.body).backgroundColor, getComputedStyle(e).color]);
    ok(bg[0] && bg[0] !== 'rgba(0, 0, 0, 0)' && bg[0] !== bg[1] && bg[2] !== bg[0], `배지 배경 ${JSON.stringify(bg)}`); // amber soft 배경 + amber 글자(토큰 --warn-soft / --warn)
    const opt = await pg.$$eval('#page .filters label:has-text("종류") select option', (els) => els.map((e) => [e.value, e.textContent]));
    ok(JSON.stringify(opt.find((o) => o[0] === 'dns')) === JSON.stringify(['dns', 'dns (도메인 조회)']), `종류 필터 ${JSON.stringify(opt)}`);
    await pg.selectOption('#page .filters label:has-text("종류") select', 'dns'); await pg.waitForTimeout(300);
    ok((await pg.$$eval('.feed-row', (els) => els.map((e) => e.querySelector('.badge-kind').textContent))).every((k) => k === 'dns'), '필터 dns 만');
    await pg.click('.feed-row:has(.badge-kind-dns)'); await pg.waitForSelector('.sheet[data-sheet="event"]', W);
    const dts = await pg.$$eval('.sheet[data-sheet="event"] dl dt', (els) => els.map((e) => e.textContent));
    ok(!dts.includes('도메인 조회'), `dns 시트에 「도메인 조회」 줄 ${JSON.stringify(dts)}`);
    ok((await pg.textContent('.sheet[data-sheet="event"] dl')).includes('runtime-dns-exfil:'), '시트 사유');
    ok((await pg.textContent('.sheet[data-sheet="event"] pre.json')).includes('"qtype": "TXT"') || (await pg.textContent('.sheet[data-sheet="event"] pre.json')).includes('"qtype": "A"'), 'JSON 에 qtype');
    // 감사 로그 kind=dns
    await go(pg, '/audit');
    await pg.selectOption('#page select[aria-label="종류"]', 'dns'); await pg.waitForTimeout(500);
    const a = await pg.$$eval('[data-table="audit"] tbody tr', (els) => els.map((e) => [e.children[3].textContent.trim(), e.children[4].textContent.trim()]));
    ok(a.length === 2 && a.every((x) => x[0] === 'dns') && a.some((x) => x[1] === 'data.exfil.example (TXT)'), `감사 dns ${JSON.stringify(a)}`);
    await pg.click('[data-table="audit"] tbody tr'); await pg.waitForSelector('.sheet[data-sheet="audit"]', W);
    const adts = await pg.$$eval('.sheet[data-sheet="audit"] dl dt', (els) => els.map((e) => e.textContent));
    ok(!adts.includes('도메인 조회') && adts.includes('상세'), `감사 시트 ${JSON.stringify(adts)}`);
    await pg.close();
  });

  // ⑥ 데모 제어
  await T('⑥ 데모 제어 「DNS 유출 질의 지금 실행」 → runtime-dns-exfil 경고 2건(기존 attack 시드 안 바뀜 · 건은 안 열림) / ?dns=off 면 dns 이벤트 0 + 안내 토스트', async () => {
    const pg = await newPage();
    await go(pg, '/events');
    ok(await pg.locator('#demo [data-demo="attack-dns"]').count() === 1, '버튼 없음');
    const attackLen = await pg.evaluate(() => window.MOCK.attack.length);
    ok(attackLen === 6 && await pg.evaluate(() => window.MOCK.attack.every((a) => a.kind !== 'dns')), '기존 attack 시드가 바뀜');
    await pg.click('button:has-text("데모 제어")'); await pg.click('#demo [data-demo="attack-dns"]'); await pg.waitForTimeout(500);
    const r = await pg.evaluate(() => ({ dns: UI.state.verdicts.filter((v) => v.event.kind === 'dns' && v.matched).map((v) => [v.ruleId, v.action, v.event.containerName]), cases: UI.state.cases.filter((c) => c.source === 'runtime' && c.state !== 'closed').length, audit: UI.state.audit.filter((a) => a.event.kind === 'dns').length }));
    ok(r.dns.length === 2 && r.dns.every(([id, act, c]) => id === 'runtime-dns-exfil' && act === 'alert' && c === 'pkg-reqeusts'), `dns 위반 ${JSON.stringify(r.dns)}`);
    ok(r.cases === 0, '경고만으로 런타임 건이 열림'); // 11/04: 종결된 시드 건(연쇄 규칙 예시)은 세지 않는다
    ok(r.audit === 2, `감사 ${r.audit}`);
    ok((await pg.textContent('#toasts')).includes('DNS 유출 질의 실행'), '토스트');
    // dns off
    const p2 = await newPage();
    await go(p2, '/events', '&dns=off');
    await p2.evaluate(() => UI.runDnsExfilNow()); await p2.waitForTimeout(400);
    const n = await p2.evaluate(() => UI.state.verdicts.filter((v) => v.event.kind === 'dns').length);
    ok(n === 0, `dns off 인데 dns 이벤트 ${n}`);
    ok((await p2.textContent('#toasts')).includes('도메인 판단이 꺼져'), 'dns off 안내 없음');
    ok((await p2.textContent('[data-banner="dns"]')).includes('DNS 질의 규칙(kind: dns)'), '배너 문구');
    await pg.close(); await p2.close();
  });

  // ⑦ 설치 dnsExfil
  await T('⑦ 설치 dnsExfil(SG_DEMO_SCENARIOS=dns-exfil): 시트 활동 요약 타일 4개(「조회」 2) · 공격 체인 「3 통신」 2단계 · sandbox-dns 격리(11/03 dryRun 해제) → 결과 격리 · 판정 대기 건', async () => {
    const pg = await newPage();
    await go(pg, '/installs');
    ok(await pg.locator('#demo [data-demo="install-dns-exfil"]').count() === 1, '데모 제어 버튼 없음');
    const id = await pg.evaluate(() => UI.runInstallDemo('dnsExfil'));
    await pg.waitForTimeout(2200);
    await pg.evaluate((x) => UI.go(`#/installs?id=${x}`, { status: 'all' }), id); await pg.waitForTimeout(500);
    await pg.waitForSelector('.sheet[data-sheet="install"]', W);
    const tiles = await pg.$$eval('.sheet [data-activity="kinds"] [data-kind]', (els) => els.map((e) => [e.dataset.kind, e.querySelector('span').textContent, e.querySelector('b').textContent]));
    ok(tiles.length === 4 && JSON.stringify(tiles[3]) === JSON.stringify(['dns', '조회', '2']), `타일 ${JSON.stringify(tiles)}`);
    const steps = await pg.$$eval('.sheet [data-part="attack-chain"] .chain-step', (els) => els.map((e) => [e.querySelector('.step-no').textContent, e.querySelector('.step-no').className, e.querySelector('.step-label').title, e.querySelector('.badge-level').textContent]));
    ok(steps.length === 2 && steps.every((s) => s[0] === '3 통신' && /step-dns/.test(s[1]) && s[3] === '격리됨'), `체인 ${JSON.stringify(steps)}`);
    ok(steps.some((s) => s[2] === 'data.exfil.example (TXT)'), '체인 상세');
    ok(await pg.$eval('.sheet [data-part="result"] [data-status]', (e) => e.dataset.status) === 'isolated', '결과 격리 아님'); // 11/04: sandbox-dns dryRun 해제(11/03 sg-vm 실측)
    ok(await pg.locator('.sheet [data-part="decision"] button:has-text("악성 확정")').count() === 1, '판정 버튼 없음');
    ok(await pg.locator('[data-table="installs"] tbody tr[data-id].needs-action').count() >= 1, '판정 대기 표시');
    await pg.close();
  });

  // ⑧ 종합 · 설정 · 가이드
  await T('⑧ 종합 「조회 N」 + 차트 조각 dns(#fb923c) · 설정 도메인 판단 off 문구 · 대응 가이드 egress 묶음에 dns 규칙', async () => {
    const pg = await newPage();
    await go(pg, '/');
    const txt = await pg.textContent('[data-section="overview"] [data-kpi="collected"]');
    ok(/조회 [\d,]+/.test(txt) && /통신 [\d,]+/.test(txt), `수집한 이벤트 "${txt}"`);
    const kinds = await pg.$$eval('[data-section="overview"] [data-chart="collected"] rect[data-kind]', (els) => [...new Set(els.map((e) => e.dataset.kind))].sort());
    ok(kinds.includes('dns'), `차트 종류 ${JSON.stringify(kinds)}`);
    const fill = await pg.$eval('[data-section="overview"] [data-chart="collected"] rect[data-kind="dns"]', (e) => getComputedStyle(e).fill);
    ok(fill === 'rgb(251, 146, 60)', `조회 색 ${fill}`);
    ok((await pg.$$eval('[data-section="overview"] [data-chart="collected"] .chart-legend span', (els) => els.map((e) => e.textContent))).includes('조회'), '범례 조회');
    await go(pg, '/settings', '&dns=off');
    const dns = await pg.textContent('[data-ss="dns"]');
    ok(dns.includes('DNS 질의 규칙(kind: dns)이 통과 처리됩니다'), `설정 문구 "${dns}"`);
    const follow = await pg.evaluate(() => UI.assistant.FOLLOW.find((f) => f.group === 'egress').rules);
    ok(follow.includes('runtime-dns-exfil') && follow.includes('sandbox-dns'), `가이드 ${JSON.stringify(follow)}`);
    await pg.close();
  });

  await br.close();
  const failed = results.filter((r) => !r[0]);
  if (!process.env.VERBOSE) results.forEach((r) => console.log(`${r[0] ? 'PASS' : 'FAIL'}  ${r[1]}${r[2] ? '  — ' + r[2] : ''}`));
  console.log(`\n${results.length - failed.length}/${results.length} 통과 · 콘솔 오류 ${consoleErrors.length}건`);
  consoleErrors.slice(0, 5).forEach((e) => console.log('  ', e));
  process.exit(failed.length || consoleErrors.length ? 1 : 0);
})();
