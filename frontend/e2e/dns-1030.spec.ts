import type { Page } from '@playwright/test';
import { expect, test, closeSheet } from './fixtures';
import { DNS_EXFIL_NAME, dnsVerdict } from './mock-backend';

// 10/30 F1 — Kind 에 dns(도메인 조회) 추가. 계약 contract-1030 §1 화면 라벨 표 그대로.
// 배지 · 필터 · 상세(「<name> (<qtype>)」, 도메인 조회 줄 없음) · 정책 쉬운 설정 · 고급 폼 · YAML · 템플릿 · 목록 짧은 라벨 · 설치 시트 타일 ·
// 종합 KPI 「조회 N」 · 공격 체인 「3 통신」 · 대응 가이드 egress 묶음 · 설정 도메인 판단(off) 문구

const ED = '[data-view="rule-editor"]';
const chips = (page: Page, group: string) =>
  page.locator(`${ED} [data-chips="${group}"] [data-chip]`).evaluateAll((els) => els.map((e) => `${(e as HTMLElement).dataset.type}:${(e as HTMLElement).dataset.value}`));

test.describe('DNS 질의 규칙(kind: dns) — 화면', () => {
  test('이벤트: dns 배지(amber · 「도메인 조회」) · 상세 「<name> (<qtype>)」 · 도메인 조회 줄 없음 · 종류 필터 dns', async ({ page, backend }) => {
    backend.enableDns();
    await page.goto('/events');
    const row = page.locator('li[data-key]', { hasText: 'data.exfil.example (TXT)' }).first();
    await expect(row).toBeVisible();
    const badge = row.locator('[data-kind-badge="dns"]');
    await expect(badge).toHaveText('dns');
    await expect(badge).toHaveAttribute('title', '도메인 조회');
    // 다른 종류와 다른(amber 계열) 배경
    const [dnsBg, connBg] = await Promise.all([
      badge.evaluate((e) => getComputedStyle(e).backgroundColor),
      page.locator('li[data-key] [data-kind-badge="connect"]').first().evaluate((e) => getComputedStyle(e).backgroundColor),
    ]);
    expect(dnsBg).not.toBe(connBg);
    await row.click();
    const sheet = page.locator('[data-sheet="event"]');
    await expect(sheet.locator('[data-part="detail"]')).toHaveText('data.exfil.example (TXT)');
    await expect(sheet.locator('[data-kind-badge="dns"]')).toBeVisible();
    await expect(sheet.locator('[data-dns]')).toHaveCount(0); // connect 의 「도메인 조회」 줄은 dns 행에 없다
    await expect(sheet).toContainText('금지 질의 유형: TXT — data.exfil.example');
    // 종류 필터: exec · open · connect · dns(도메인 조회)
    const sel = page.getByLabel('종류');
    expect(await sel.locator('option').evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))).toEqual(['', 'exec', 'open', 'connect', 'dns']);
    await expect(sel.locator('option[value="dns"]')).toHaveText(/도메인 조회/);
    await sel.selectOption('dns');
    await expect(page.locator('li[data-key]')).toHaveCount(2);
    await expect(page.locator('li[data-key]').first()).toContainText(DNS_EXFIL_NAME);
    await expect(page.locator('[data-part="filter-chips"] [data-chip="kind"]')).toContainText('dns');
    // WS 로 들어온 dns 판정도 바로 보인다
    backend.send({ type: 'verdict', data: dnsVerdict('worker', { name: 'c2.attacker.test', qtype: 'TXT' }) });
    await expect(page.locator('li[data-key]')).toHaveCount(3);
    await expect(page.locator('li[data-key]').first()).toContainText('c2.attacker.test (TXT)');
  });

  test('정책 템플릿 「DNS 유출 패턴 차단」 → 쉬운 설정 ①② 문구 · 칩(질의 유형 · 도메인) · 길이 칸 2개 → 고급 폼(dns 에서만) → YAML', async ({ page, backend }) => {
    void backend;
    await page.goto('/policies');
    await page.getByRole('button', { name: '새 정책' }).click();
    const tpl = page.locator('[data-view="templates"] [data-template="dns-exfil"]');
    await expect(tpl).toContainText('DNS 유출 패턴 차단');
    await expect(tpl).toContainText('긴 라벨 · 긴 이름 · TXT 질의를 알림');
    await expect(tpl).toContainText('도메인 조회');
    await tpl.click();
    const ed = page.locator(ED);
    await expect(ed.locator('[data-step="what"] input[value="dns"]')).toBeChecked();
    await expect(ed.locator('[data-step="what"]')).toContainText('도메인 조회');
    await expect(ed.locator('[data-step="what"]')).toContainText('어떤 도메인을 조회하는지 봅니다');
    await expect(ed.locator('[data-step="values"] h3')).toContainText('어떤 도메인 · 질의인가요?');
    await expect(ed.locator('[data-chips="block"]')).toContainText('막을 도메인 · 질의 유형');
    await expect(ed.locator('[data-chips="block"]')).toContainText('허용 목록과 상관없이 위반');
    await expect(ed.locator('[data-chips="allow"]')).toContainText('허용할 도메인');
    await expect(ed.locator('[data-chips="allow"]')).toContainText('점 없는 이름 · *.arpa 는 제외');
    expect(await chips(page, 'block')).toEqual(['qtype:TXT']);
    await expect(ed.locator('[data-step="values"] [data-field="maxLabelLength"]')).toHaveValue('40');
    await expect(ed.locator('[data-step="values"] [data-field="maxNameLength"]')).toHaveValue('120');
    await expect(ed.locator('[data-step="values"]')).toContainText('라벨 길이 상한');
    await expect(ed.locator('[data-step="values"]')).toContainText('이름 길이 상한');
    // 칩 추가: 도메인 · 질의 유형(소문자는 대문자로) · 틀린 값은 이유와 함께 거부
    const input = ed.locator('[data-chips="block"] input');
    await input.fill('attacker.test');
    await input.press('Enter');
    await input.fill('all');
    await input.press('Enter');
    await input.fill('999');
    await input.press('Enter');
    expect(await chips(page, 'block')).toEqual(['host:attacker.test', 'qtype:TXT', 'qtype:ALL']);
    await expect(ed.locator('[data-chips="block"] [data-chip-error]')).toBeVisible();
    await expect(ed.locator('[data-summary]')).toContainText('attacker.test');
    await expect(ed.locator('[data-summary]')).toContainText('TXT');
    // 고급 폼: 허용 도메인 · 금지 도메인 · 금지 질의 유형 · 라벨 길이 상한 · 이름 길이 상한
    await ed.locator('[data-mode="form"]').click();
    for (const label of ['허용 도메인', '금지 도메인', '금지 질의 유형', '라벨 길이 상한', '이름 길이 상한']) await expect(ed).toContainText(label);
    await expect(ed.locator('textarea[data-field="denyQtypes"]')).toHaveValue('TXT\nALL');
    await expect(ed.locator('input[data-field="maxLabelLength"]')).toHaveValue('40');
    await expect(ed.locator('[data-field="directIp"]')).toHaveCount(0); // connect 전용 조건은 dns 에 없다
    await ed.locator('select[data-field="kind"]').selectOption('connect');
    await expect(ed.locator('[data-field="maxLabelLength"]')).toHaveCount(0);
    await expect(ed.locator('[data-field="denyQtypes"]')).toHaveCount(0);
    await ed.locator('select[data-field="kind"]').selectOption('dns');
    await expect(ed.locator('input[data-field="maxNameLength"]')).toHaveValue('120');
    // YAML 에 세 필드가 나온다
    await ed.locator('[data-mode="yaml"]').click();
    const yaml = await ed.getByLabel('정책 YAML').inputValue();
    expect(yaml).toContain('kind: dns');
    expect(yaml).toContain('denyQtypes');
    expect(yaml).toContain('maxLabelLength: 40');
    expect(yaml).toContain('maxNameLength: 120');
    expect(yaml).toContain('denyHosts');
    // 저장 → 규칙 모양 그대로(숫자 · 대문자)
    await ed.getByRole('button', { name: '저장 전 확인' }).click();
    await page.locator(`${ED} [data-part="save-check"]`).getByRole('button', { name: '저장 후 적용' }).click();
    const saved = backend.rules.find((r) => r.id.startsWith('runtime-dns-exfil'))!;
    expect(saved).toMatchObject({ kind: 'dns', action: 'alert', denyQtypes: ['TXT', 'ALL'], denyHosts: ['attacker.test'], maxLabelLength: 40, maxNameLength: 120 });
  });

  test('정책 목록 짧은 라벨 「조회」 · dns 규칙을 열면 쉬운 설정에 값이 그대로 · 길이 칸 범위 밖은 저장 전 오류', async ({ page, backend }) => {
    backend.enableDns();
    await page.goto('/policies?id=sandbox-dns');
    await expect(page.locator('[data-rule="runtime-dns-exfil"] [data-kind-badge="dns"]')).toHaveText('조회');
    await expect(page.locator('[data-rule="sandbox-dns"] [data-scope="sandbox"]')).toHaveText('설치 검사 전용');
    const ed = page.locator(ED);
    await expect(ed.locator('[data-step="what"] input[value="dns"]')).toBeChecked();
    expect(await chips(page, 'allow')).toContain('host:pypi.org');
    await expect(ed.locator('[data-summary]')).toContainText('설치 검사 컨테이너에서');
    await expect(ed.locator('[data-summary]')).toContainText('격리 대상으로 표시만');
    await ed.locator('[data-step="values"] [data-field="maxLabelLength"]').fill('99');
    await ed.getByRole('button', { name: '저장 전 확인' }).click();
    await expect(ed).toContainText('라벨 길이 상한');
    await expect(ed).toContainText('1~63');
    await expect(page.locator(`${ED} [data-part="save-check"]`)).toHaveCount(0);
  });

  test('감사 로그: 종류 필터 dns → 서버에 kind=dns · 상세 시트에 도메인 조회 줄 없음 · CSV 종류 열 dns', async ({ page, backend }) => {
    backend.enableDns();
    await page.goto('/audit');
    const dnsRows = backend.audit.filter((a) => a.event.kind === 'dns');
    expect(dnsRows.length).toBe(3);
    await page.getByLabel('종류').selectOption('dns');
    await expect.poll(() => backend.requests.some((r) => r.path.startsWith('/audit?') && r.path.includes('kind=dns'))).toBe(true);
    await expect(page.locator('tr[data-audit]')).toHaveCount(3);
    await expect(page.locator('tr[data-audit] [data-kind-badge="dns"]')).toHaveCount(3);
    await page.locator('tr[data-audit]', { hasText: 'cdn.reqeusts-update.test (A)' }).click();
    const sheet = page.locator('[data-sheet="audit"]');
    await expect(sheet.locator('[data-part="detail"]')).toHaveText('cdn.reqeusts-update.test (A)');
    await expect(sheet.locator('[data-dns]')).toHaveCount(0);
    await expect(sheet.getByTestId('audit-reason')).toHaveText('허용 목록 밖 도메인 질의: cdn.reqeusts-update.test (A)');
    // CSV: 종류 열에 dns
    await closeSheet(page); // 11/05 슬라이드 패널: 열린 동안 뒤 화면은 어두운 배경에 가려 눌리지 않는다 — 먼저 닫는다
    await page.getByLabel('기간 시작').fill('2020-01-01T00:00');
    await page.getByLabel('기간 끝').fill('2099-01-01T00:00');
    const dl = page.waitForEvent('download');
    await page.locator('[data-action="export-csv"]').click();
    const file = await dl;
    const text = await (await import('node:fs/promises')).readFile(await file.path(), 'utf8');
    const lines = text.trim().split('\n');
    expect(lines).toHaveLength(1 + 3);
    expect(lines.slice(1).every((l) => l.includes(',dns,'))).toBe(true);
    expect(lines[1]).toContain('(A)');
  });

  test('종합 KPI: dns 가 있으면 「조회 N」 + 차트 키 「조회」, 없는 옛 백엔드는 오류 없이 셋만', async ({ page, backend }) => {
    await page.goto('/');
    const kpi = page.locator('[data-section="overview"] [data-kpi="collected"]');
    await expect(kpi).toContainText('통신');
    await expect(kpi).not.toContainText('조회');
    await expect(page.locator('[data-section="overview"] [data-chart="collected"] [data-kind="dns"]')).toHaveCount(0); // R2 11/04: 수집량 추이는 선 차트(path.line[data-kind])
    backend.enableDns();
    await page.reload();
    const s = backend.summary('24h');
    expect(s.collected.byKind.dns).toBeGreaterThan(0);
    await expect(kpi).toContainText(`조회 ${s.collected.byKind.dns!.toLocaleString('ko-KR')}`);
    await expect(kpi.locator('[data-value]')).toHaveText(s.collected.total.toLocaleString('ko-KR'));
    const chart = page.locator('[data-section="overview"] [data-chart="collected"]');
    await expect(chart).toContainText('조회');
    // R2 11/04: 선 차트 — 조회 선 · 선 끝 라벨 「조회 N」 색이 토큰 --k-dns
    expect(await chart.locator('path.line[data-kind="dns"]').count()).toBe(1);
    const color = await chart.locator('[data-end-label="dns"]').evaluate((e) => getComputedStyle(e).fill);
    expect(color).toBe('rgb(251, 146, 60)'); // #fb923c
  });

  test('설치 시트: 활동 요약 타일 「조회」 · 공격 체인 dns 는 「3 통신」(connect 앞)', async ({ page, backend }) => {
    backend.enableDns();
    await page.goto('/installs?id=ins-0012');
    const sheet = page.locator('[data-sheet="install"]');
    const act = sheet.getByTestId('activity');
    await expect(act).toContainText('조회');
    await expect(act.locator('[data-kind-tile="dns"] b')).toHaveText('4');
    const chain = sheet.getByTestId('attack-chain');
    await expect(chain.locator('[data-step="dns"]')).toHaveText('3 통신');
    const steps = await chain.locator('[data-step]').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.step));
    expect(steps.indexOf('dns')).toBeGreaterThan(steps.lastIndexOf('open'));
    expect(steps.indexOf('dns')).toBeLessThan(steps.indexOf('connect'));
    await expect(sheet.getByTestId('kernel-result')).toContainText('7건');
  });

  test('토폴로지 공격 체인에도 dns 단계 · 대응 가이드 egress 묶음에 runtime-dns-exfil · sandbox-dns', async ({ page, backend }) => {
    backend.enableDns();
    await page.goto('/topology');
    const chain = page.locator('[data-chain="pkg-reqeusts"] [data-testid="attack-chain"]');
    await expect(chain.locator('[data-step="dns"]').first()).toHaveText('3 통신');
    await expect(chain).toContainText('data.exfil.example');
    // 가이드
    backend.empty();
    await page.goto('/');
    await expect(page.locator('[data-part="assistant-fab"]')).toHaveAttribute('data-ready', 'true');
    // 실시간 연결이 선 뒤에 건을 연다 — StrictMode 가 닫는 첫 연결로 보내면 메시지가 사라진다(11/05 CI)
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    const c = backend.openCase({ level: 'alert', ruleIds: ['runtime-dns-exfil', 'sandbox-dns'] });
    await expect(page.locator('[data-part="guide"]')).toHaveAttribute('data-guide-case', c.id);
    const egress = page.locator('[data-part="guide"] [data-step="5"] [data-group="egress"]');
    await expect(egress).toHaveAttribute('data-follow', 'runtime-dns-exfil sandbox-dns');
    await expect(page.locator('[data-part="guide"] [data-step="5"] [data-follow]')).toHaveCount(1);
  });

  test('도메인 판단 꺼짐: 배너 · 설정 문구에 「DNS 질의 규칙(kind: dns)」', async ({ page, backend }) => {
    backend.info.dnsResolve = 'off';
    await page.goto('/settings');
    await expect(page.locator('[data-part="dns"]')).toContainText('DNS 질의 규칙(kind: dns)이 통과 처리됩니다');
    await expect(page.locator('[data-banner="dns"]')).toContainText('DNS 질의 규칙(kind: dns)');
  });
});
