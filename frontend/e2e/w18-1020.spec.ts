import { readFileSync } from 'node:fs';
import type { Page, Route } from '@playwright/test';
import type { Evidence, Rule, Scan, Verdict } from '../src/lib/types';
import { expect, noPageOverflow, test, closeSheet } from './fixtures';

// W18(10/20 사용자 확정) — 목업 「2026-10-20 2차 시안」 B · D · F · G · I 를 React 로.
// B 확인 대화상자(영향 · 사유 · 되돌리기) · F 새 기본 규칙 띠 · G 패키지 골라 차단 · I 증거 · D 목록 정리 · 조회자 숨김

const DIALOG = 'dialog[data-part="confirm"]';
const dialog = (page: Page) => page.locator(DIALOG);
const reqs = (b: { requests: { method: string; path: string; body?: string }[] }, method: string, re: RegExp) => b.requests.filter((r) => r.method === method && re.test(r.path));
const bodyOf = (r: { body?: string } | undefined) => JSON.parse(r?.body ?? '{}') as Record<string, unknown>;

// 판정을 대화상자로 끝낸다(사유 선택)
async function decide(page: Page, scope: string, which: '악성 확정' | '오탐', reason = '') {
  await page.getByTestId(scope).getByRole('button', { name: which }).click();
  const d = dialog(page);
  await expect(d).toBeVisible();
  if (reason) await d.locator('textarea[name="reason"]').fill(reason);
  await d.locator('[data-confirm="ok"]').click();
  await expect(d).toHaveCount(0);
}

test.describe('B 확인 대화상자 — 대상 · 함께 일어나는 일 · 사유 · 되돌리기', () => {
  test('악성 확정: 서버 판정 미리보기 effects 를 그대로 보이고, 사유는 판정 메모(note)로', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    const d = dialog(page);
    await expect(d).toBeVisible();
    await expect(d.locator('[data-part="confirm-target"]')).toContainText('pip ./reqeusts · 건 case-0004');
    const fx = d.locator('[data-part="confirm-effects"] li');
    await expect(fx.first()).toHaveAttribute('data-kind', 'blocklist');
    await expect(fx.first()).toHaveText('차단 목록 +2 (패키지 1 · 도메인 1)');
    await expect(d.locator('li[data-kind="package"]')).toContainText('pip:reqeusts');
    await expect(d.locator('li[data-kind="host"]')).toContainText('cdn.reqeusts-update.test');
    await expect(fx.last()).toHaveAttribute('data-kind', 'next');
    await expect(d.locator('[data-part="confirm-undo"]')).toContainText('되돌리기');
    const pv = reqs(backend, 'POST', /^\/cases\/case-0004\/preview$/);
    expect(pv).toHaveLength(1);
    expect(bodyOf(pv[0])).toEqual({ decision: 'malicious' });
    expect(reqs(backend, 'POST', /\/decide$/)).toHaveLength(0); // 열기만 해서는 판정하지 않는다
    await d.locator('textarea[name="reason"]').fill('requests 와 한 글자 다른 타이포스쿼팅');
    await d.locator('[data-confirm="ok"]').click();
    await expect(page.locator('[data-toast^="decide:"]')).toContainText('pip ./reqeusts 악성 확정');
    expect(bodyOf(reqs(backend, 'POST', /\/decide$/)[0])).toEqual({ decision: 'malicious', note: 'requests 와 한 글자 다른 타이포스쿼팅' });
    // 메모 칸은 대화상자로 옮겼다
    await expect(page.getByTestId('decision').locator('input')).toHaveCount(0);
  });

  test('오탐: 예외 effects · 취소 · 사유를 쓴 뒤 Esc 는 「버리고 닫기」를 묻는다 — 판정 없음', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0011');
    const box = page.getByTestId('decision');
    await box.getByRole('button', { name: '오탐' }).click();
    const d = dialog(page);
    await expect(d.locator('li[data-kind="exception"]')).toContainText('egress-allowlist');
    await d.locator('[data-confirm="cancel"]').click();
    await expect(d).toHaveCount(0);
    await box.getByRole('button', { name: '오탐' }).click();
    await d.locator('textarea[name="reason"]').fill('git 프로토콜은 정상');
    await page.keyboard.press('Escape');
    await expect(d.getByRole('alert')).toContainText('저장하지 않은 내용이 있습니다');
    await d.locator('[data-action="discard-close"]').click();
    await expect(d).toHaveCount(0);
    expect(reqs(backend, 'POST', /\/decide$/)).toHaveLength(0);
  });

  test('판정 미리보기가 없는 백엔드면 「계산하지 못함」 안내 — 판정은 그대로 된다', async ({ page, backend, allowConsole }) => {
    allowConsole(/404/);
    backend.unsupported.add('/cases/case-0004/preview');
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await expect(dialog(page).locator('[data-part="confirm-effects"]')).toContainText('영향을 계산하지 못했습니다');
    await dialog(page).locator('[data-confirm="ok"]').click();
    await expect(page.getByTestId('decision').locator('[data-decision="malicious"]')).toBeVisible();
  });

  test('제안 적용: 변경 · 미리보기 결과를 보이고 사유 → 변경 이력 reason → 감사 화면에 사유', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0012');
    await decide(page, 'decision', '악성 확정');
    await page.getByRole('button', { name: '제안 보기' }).click();
    const detail = page.getByTestId('proposal');
    await expect(detail.getByTestId('preview-summary')).toBeVisible();
    await detail.getByRole('button', { name: '적용', exact: true }).click();
    const d = dialog(page);
    await expect(d.locator('h3')).toHaveText('제안 적용');
    await expect(d.locator('[data-part="confirm-effects"]')).toContainText('차단 목록 +2 (패키지 1 · 도메인 1)');
    await expect(d.locator('[data-part="confirm-effects"]')).toContainText('과거 위반');
    await d.locator('textarea[name="reason"]').fill('C2 도메인 확인');
    await d.locator('[data-confirm="ok"]').click();
    await expect(detail.getByTestId('proposal-state')).toContainText('적용됨');
    expect(bodyOf(reqs(backend, 'POST', /\/apply$/)[0])).toEqual({ reason: 'C2 도메인 확인' });
    await expect(page.getByTestId('changes').locator('[data-change]').first()).toContainText('C2 도메인 확인');
    await page.goto('/audit?view=changes');
    const row = page.locator('[data-history^="chg:"]').first();
    await expect(row).toContainText('제안 적용');
    await expect(row.locator('[data-reason]')).toHaveText('사유: C2 도메인 확인');
  });

  test('제안 버림: 대화상자 · 사유 → 「제안 버림」 이력(정책 · 감사 화면)', async ({ page, backend }) => {
    await page.goto('/installs?id=ins-0011');
    await decide(page, 'decision', '오탐');
    await page.getByRole('button', { name: '제안 보기' }).click();
    await page.getByTestId('proposal').getByRole('button', { name: '버림', exact: true }).click();
    const d = dialog(page);
    await expect(d.locator('h3')).toHaveText('제안 버림');
    await expect(d.locator('[data-part="confirm-effects"]')).toContainText('정책 · 차단 목록은 바뀌지 않습니다');
    await d.locator('textarea[name="reason"]').fill('이번엔 그대로 둔다');
    await d.locator('[data-confirm="ok"]').click();
    await expect(page.getByTestId('proposal-state')).toContainText('버림');
    expect(bodyOf(reqs(backend, 'POST', /\/discard$/)[0])).toEqual({ reason: '이번엔 그대로 둔다' });
    const first = page.getByTestId('changes').locator('[data-change]').first();
    await expect(first).toContainText('제안 버림');
    await expect(first).toContainText('이번엔 그대로 둔다');
    await page.goto('/audit?view=changes');
    await expect(page.locator('[data-history^="chg:"]').first()).toContainText('제안 버림');
  });

  test('차단 해제: 대화상자(다시 설치 가능) · 사유 → DELETE 본문 {reason}', async ({ page, backend }) => {
    await page.goto('/policies');
    await page.getByTestId('blocklist').locator('[data-block="packages:pip:colourama"]').getByRole('button', { name: '해제' }).click();
    const d = dialog(page);
    await expect(d.locator('[data-part="confirm-target"]')).toHaveText('패키지 pip:colourama');
    await expect(d.locator('[data-part="confirm-effects"]')).toContainText('다시 설치할 수 있습니다');
    await d.locator('textarea[name="reason"]').fill('오탐 재확인');
    await d.locator('[data-confirm="ok"]').click();
    await expect(page.getByTestId('blocklist').locator('[data-block="packages:pip:colourama"]')).toHaveCount(0);
    const del = reqs(backend, 'DELETE', /^\/blocklist\/packages\//);
    expect(del).toHaveLength(1);
    expect(bodyOf(del[0])).toEqual({ reason: '오탐 재확인' });
  });

  test('정책 삭제 · 전체 교체: 대화상자(사유 칸 없음) — 두 번 누르기 버튼은 없다', async ({ page, backend }) => {
    await page.goto('/policies?id=egress-allowlist');
    await expect(page.getByRole('button', { name: '눌러서 삭제 확정' })).toHaveCount(0);
    await page.locator('[data-view="rule-editor"]').getByRole('button', { name: '삭제' }).click();
    const d = dialog(page);
    await expect(d.locator('[data-part="confirm-target"]')).toHaveText('egress-allowlist');
    await expect(d.locator('textarea')).toHaveCount(0);
    await d.locator('[data-confirm="ok"]').click();
    await expect(page.locator('[data-rule="egress-allowlist"]')).toHaveCount(0);
    expect(reqs(backend, 'DELETE', /^\/policies\/egress-allowlist$/)).toHaveLength(1);

    await page.goto('/policies?id=__yaml__');
    await page.getByRole('button', { name: '전체 교체 후 적용 ▶' }).click();
    await expect(d.locator('h3')).toHaveText('전체 정책 교체');
    await expect(d.locator('[data-part="confirm-effects"]')).toContainText('YAML 에 없는 정책은 지워집니다');
    await expect(d.locator('textarea')).toHaveCount(0);
    await d.locator('[data-confirm="ok"]').click();
    await expect(page.getByText('개 정책을 엔진에 적용함')).toBeVisible();
    expect(reqs(backend, 'PUT', /^\/policies$/)).toHaveLength(1);
  });
});

// ── F 새 기본 규칙 ──
const directIpRule: Rule = { id: 'runtime-direct-ip', description: '도메인 조회 없이 공인 IP로 바로 나가는 연결', kind: 'connect', action: 'alert', directIp: 'alert', allowCidrs: ['10.0.0.0/8'] };

function withDefaults(backend: { rules: Rule[]; policyDefaults: unknown }) {
  const cur = backend.rules.find((r) => r.id === 'sandbox-egress')!;
  // 사용자가 바꾼 값: 행동(alert) · 설명. 기본은 kill · directIp · github.com 추가
  Object.assign(cur, { action: 'alert', description: '내가 고친 설명' });
  const def: Rule = { id: 'sandbox-egress', description: '설치 중 외부 통신', kind: 'connect', action: 'kill', directIp: 'kill', containers: ['sg-install-*'], allowHosts: ['pypi.org', 'files.pythonhosted.org', 'github.com'] };
  backend.policyDefaults = { missing: [directIpRule], differs: [{ id: 'sandbox-egress', default: def, current: { ...cur } }] };
}

test.describe('F 정책 「새 기본 규칙 있음」 띠', () => {
  test('새 규칙: 펼치기 → 미리보기 후 추가 → 바로 저장 전 확인 → 저장', async ({ page, backend }) => {
    withDefaults(backend);
    await page.goto('/policies');
    const band = page.locator('[data-part="defaults-banner"]');
    await expect(band).toContainText('기본 정책에 새 규칙 1개 · 바뀐 규칙 1개가 있습니다');
    await expect(band).toContainText('사용자가 바꾼 규칙은 덮어쓰지 않습니다');
    await expect(band.locator('[data-default]')).toHaveCount(0);
    await band.locator('[data-action="defaults-toggle"]').click();
    await expect(band.locator('[data-default]')).toHaveCount(2);
    await noPageOverflow(page); // 띠를 펼쳐도 페이지는 넘치지 않는다(목록 · 편집기만 스크롤)
    await band.locator('[data-default="runtime-direct-ip"] [data-action="default-preview"]').click();
    await expect(page.locator('[data-part="save-check"]')).toBeVisible();
    await page.locator('[data-part="save-check"]').getByRole('button', { name: '저장 후 적용' }).click();
    await expect.poll(() => reqs(backend, 'POST', /^\/policies$/).length).toBe(1);
    const saved = bodyOf(reqs(backend, 'POST', /^\/policies$/)[0]);
    expect(saved).toMatchObject({ id: 'runtime-direct-ip', kind: 'connect', action: 'alert', directIp: 'alert', allowCidrs: ['10.0.0.0/8'] });
    await expect(page).toHaveURL(/id=runtime-direct-ip/);
  });

  test('바뀐 규칙: 덮어쓰지 않고 기본에만 있는 값만 더한 사본(목록 합치기 · 빈 옵션 채우기)', async ({ page, backend }) => {
    withDefaults(backend);
    await page.goto('/policies');
    const band = page.locator('[data-part="defaults-banner"]');
    await band.locator('[data-action="defaults-toggle"]').click();
    await expect(band.locator('[data-default="sandbox-egress"]')).toContainText('directIp');
    await band.locator('[data-default="sandbox-egress"] [data-action="default-preview"]').click();
    await expect(page.getByTestId('editor')).toContainText('빠진 값만 더함');
    await page.locator('[data-part="save-check"]').getByRole('button', { name: '저장 후 적용' }).click();
    await expect.poll(() => reqs(backend, 'POST', /^\/policies$/).length).toBe(1);
    const saved = bodyOf(reqs(backend, 'POST', /^\/policies$/)[0]);
    expect(saved).toMatchObject({ id: 'sandbox-egress', action: 'alert', description: '내가 고친 설명', directIp: 'kill', containers: ['sg-install-*'] });
    expect(saved.allowHosts).toEqual(['pypi.org', 'files.pythonhosted.org', 'github.com']);
  });

  test('이번엔 숨기기: 이 브라우저에 남고, 기본 규칙 내용이 바뀌면 다시 보인다', async ({ page, backend }) => {
    withDefaults(backend);
    await page.goto('/policies');
    const band = page.locator('[data-part="defaults-banner"]');
    await band.locator('[data-action="defaults-toggle"]').click();
    await band.locator('[data-default="runtime-direct-ip"] [data-action="default-hide"]').click();
    await expect(band).toContainText('기본 정책에 바뀐 규칙 1개가 있습니다');
    await page.reload();
    await expect(band).toContainText('기본 정책에 바뀐 규칙 1개가 있습니다');
    await band.locator('[data-action="defaults-toggle"]').click();
    await band.locator('[data-default="sandbox-egress"] [data-action="default-hide"]').click();
    await expect(band).toHaveCount(0);
    (backend.policyDefaults as { missing: Rule[] }).missing = [{ ...directIpRule, allowCidrs: ['10.0.0.0/8', '192.168.0.0/16'] }];
    await page.reload();
    await expect(band).toContainText('기본 정책에 새 규칙 1개가 있습니다');
  });

  test('라우트가 없으면(404 · 405) 띠를 그리지 않는다', async ({ page, backend, allowConsole }) => {
    allowConsole(/40[45]/);
    withDefaults(backend);
    backend.unsupported.add('/policies/defaults');
    await page.goto('/policies');
    await expect(page.getByTestId('rules').locator('[data-rule]').first()).toBeVisible();
    await expect(page.locator('[data-part="defaults-banner"]')).toHaveCount(0);
    backend.unsupported.clear();
    await page.route(/\/api\/policies\/defaults$/, (r) => r.fulfill({ status: 405, contentType: 'text/plain', body: 'Method Not Allowed' }));
    await page.reload();
    await expect(page.getByTestId('rules').locator('[data-rule]').first()).toBeVisible();
    await expect(page.locator('[data-part="defaults-banner"]')).toHaveCount(0);
  });

  test('조회자는 띠를 보되 「미리보기 후 추가」 버튼이 없다', async ({ page, backend }) => {
    withDefaults(backend);
    backend.auth.asViewer();
    await page.goto('/policies');
    const band = page.locator('[data-part="defaults-banner"]');
    await band.locator('[data-action="defaults-toggle"]').click();
    await expect(band.locator('[data-default]')).toHaveCount(2);
    await expect(band.locator('[data-action="default-preview"]')).toHaveCount(0);
    await expect(band.locator('[data-action="default-hide"]')).toHaveCount(2);
  });
});

// ── G 공급망 검사 「패키지 골라 차단」 ──
const iso = new Date().toISOString();
const baseScan: Omit<Scan, 'id' | 'target' | 'verdict' | 'packages'> = {
  status: 'done', startedAt: iso, finishedAt: iso, risk: { score: 3.2, label: 'medium_risk' }, engines: [{ name: 'GuardDog', version: '3.2.0' }],
  findings: [], vulns: [], files: {}, caseId: null, threats: 0, capabilities: 0, vulnCount: 3, vulnMax: 7.5,
};
const repoScan: Scan = {
  ...baseScan, id: 'scan-0002', verdict: 'vulnerable',
  target: { kind: 'repo', name: 'app', url: 'https://github.com/o/app', label: 'github.com/o/app' },
  packages: [
    { manager: 'pip', name: 'urllib3', version: '1.26.4', ecosystem: 'PyPI', source: 'requirements.txt', direct: true, vulns: 2 },
    { manager: 'pip', name: 'urllib3', version: '1.26.4', ecosystem: 'PyPI', source: 'poetry.lock', direct: false, vulns: 2 },
    { manager: 'pip', name: 'urllib3', version: '2.0.0', ecosystem: 'PyPI', source: 'tools/requirements.txt', direct: true, vulns: 0 },
    { manager: 'npm', name: 'lodash', version: '4.17.20', ecosystem: 'npm', source: 'package-lock.json', direct: false, vulns: 1 },
    { manager: 'pip', name: 'colourama', version: '0.1', ecosystem: 'PyPI', source: 'requirements.txt', direct: true, vulns: 0 },
    { manager: '', name: 'golang.org/x/text', version: '0.3.0', ecosystem: 'Go', source: 'go.mod', direct: true, vulns: 0 },
  ],
};
const pkgScan: Scan = { ...baseScan, id: 'scan-0001', verdict: 'malicious', threats: 2, target: { kind: 'package', manager: 'pip', name: 'reqeusts', label: 'pip reqeusts' }, packages: [] };

async function scansApi(page: Page, scans: Scan[], blocks: { path: string; body: string }[], proposalId: () => string) {
  await page.route(/\/api\/scans(\/|$|\?)/, (route: Route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace(/^\/api/, '');
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
    const bm = path.match(/^\/scans\/([^/]+)\/block$/);
    if (req.method() === 'POST' && bm) {
      blocks.push({ path, body: req.postData() ?? '' });
      return json({ proposalId: proposalId() });
    }
    if (path === '/scans') return json(scans.map(({ packages, ...s }) => (void packages, { ...s, packages: null })));
    const m = path.match(/^\/scans\/([^/]+)$/);
    const s = m && scans.find((x) => x.id === m[1]);
    return s ? json(s) : json({ error: '검사 없음' }, 404);
  });
}

test.describe('G 공급망 검사 — 패키지 골라 차단', () => {
  test('같은 매니저+이름+버전은 한 줄 + 출처 나열 · 차단됨 · 미지원 생태계는 체크 없음', async ({ page, backend }) => {
    void backend;
    await scansApi(page, [repoScan], [], () => '');
    await page.goto('/scans?id=scan-0002');
    const sec = page.locator('[data-sheet="scan"] [data-part="packages"]');
    await expect(sec.locator('tbody tr')).toHaveCount(5);
    const u = sec.locator('tr[data-pkg="pip:urllib3@1.26.4"]');
    await expect(u).toHaveAttribute('data-sources', '2');
    await expect(u).toContainText('requirements.txt');
    await expect(u).toContainText('poetry.lock');
    await expect(sec.locator('tr[data-pkg="pip:urllib3@2.0.0"]')).toHaveAttribute('data-sources', '1');
    await expect(sec.locator('tr[data-pkg="pip:colourama@0.1"] input[type="checkbox"]')).toHaveCount(0);
    await expect(sec.locator('tr[data-pkg="pip:colourama@0.1"]')).toContainText('차단됨');
    await expect(sec.locator('tr[data-pkg="Go:golang.org/x/text@0.3.0"] input[type="checkbox"]')).toHaveCount(0);
    // 취약이 많은 것부터
    await expect(sec.locator('tbody tr').first()).toHaveAttribute('data-pkg', 'pip:urllib3@1.26.4');
  });

  test('고르면 「선택한 N개 차단 목록에 올리기」 → 대화상자 사유 → POST block {packages, reason} → 제안으로', async ({ page, backend }) => {
    const { p } = backend.scanCase({ decided: true });
    const blocks: { path: string; body: string }[] = [];
    await scansApi(page, [repoScan], blocks, () => p!.id);
    await page.goto('/scans?id=scan-0002');
    const sec = page.locator('[data-sheet="scan"] [data-part="packages"]');
    await expect(sec.locator('[data-action="block-selected"]')).toHaveCount(0);
    await sec.locator('tr[data-pkg="pip:urllib3@1.26.4"] input[type="checkbox"]').check();
    await sec.locator('tr[data-pkg="npm:lodash@4.17.20"] input[type="checkbox"]').check();
    await sec.locator('[data-action="block-selected"]').click();
    const d = dialog(page);
    await expect(d.locator('[data-part="confirm-target"]')).toContainText('github.com/o/app · scan-0002');
    await expect(d.locator('[data-part="confirm-effects"]')).toContainText('pip:urllib3');
    await expect(d.locator('[data-confirm="ok"]')).toHaveText('2개 올리기');
    await d.locator('textarea[name="reason"]').fill('취약 버전 고정 전까지');
    await d.locator('[data-confirm="ok"]').click();
    await expect(page).toHaveURL(new RegExp(`/policies\\?proposal=${p!.id}`));
    expect(blocks).toHaveLength(1);
    expect(JSON.parse(blocks[0].body)).toEqual({
      packages: [{ manager: 'pip', name: 'urllib3', version: '1.26.4' }, { manager: 'npm', name: 'lodash', version: '4.17.20' }],
      reason: '취약 버전 고정 전까지',
    });
  });

  test('모두 고르기는 고를 수 있는 것만', async ({ page, backend }) => {
    void backend;
    await scansApi(page, [repoScan], [], () => '');
    await page.goto('/scans?id=scan-0002');
    const sec = page.locator('[data-sheet="scan"] [data-part="packages"]');
    await sec.getByLabel('모두 고르기').check();
    await expect(sec.locator('[data-action="block-selected"]')).toHaveText(/선택한 3개 차단 목록에 올리기/);
  });

  test('패키지 검사의 「차단 목록에 올리기」도 대화상자에서 사유 → 본문 {reason}', async ({ page, backend }) => {
    const { p } = backend.scanCase({ decided: true });
    const blocks: { path: string; body: string }[] = [];
    await scansApi(page, [pkgScan], blocks, () => p!.id);
    await page.goto('/scans?id=scan-0001');
    await page.locator('[data-sheet="scan"]').getByRole('button', { name: '차단 목록에 올리기' }).click();
    const d = dialog(page);
    await expect(d.locator('[data-part="confirm-target"]')).toContainText('pip reqeusts · scan-0001');
    await d.locator('textarea[name="reason"]').fill('악성 코드 3곳');
    await d.locator('[data-confirm="ok"]').click();
    await expect(page).toHaveURL(new RegExp(`proposal=${p!.id}`));
    expect(JSON.parse(blocks[0].body)).toEqual({ reason: '악성 코드 3곳' });
  });

  test('조회자는 체크 칸 · 차단 버튼이 없다', async ({ page, backend }) => {
    backend.auth.asViewer();
    await scansApi(page, [repoScan, pkgScan], [], () => '');
    await page.goto('/scans?id=scan-0002');
    const sec = page.locator('[data-sheet="scan"] [data-part="packages"]');
    await expect(sec.locator('tbody tr')).toHaveCount(5);
    await expect(sec.locator('input[type="checkbox"]')).toHaveCount(0);
    await page.goto('/scans?id=scan-0001');
    await expect(page.locator('[data-sheet="scan"] [data-part="verdict"]')).toBeVisible();
    await expect(page.locator('[data-sheet="scan"]').getByRole('button', { name: '차단 목록에 올리기' })).toHaveCount(0);
  });
});

// ── I 증거 · 직접 IP ──
function evidenceFor(backend: { installs: { id: string; container: string }[]; audit: { id: number; enforced?: boolean; event: { containerName: string; containerId: string } }[] }) {
  const ctr = backend.installs.find((s) => s.id === 'ins-0012')!.container;
  const row = backend.audit.find((a) => a.event.containerName === ctr && a.enforced)!;
  const cid = row.event.containerId;
  const t = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
  const list: Evidence[] = [
    { id: 'ev-3', containerId: cid, containerName: ctr, image: 'python:3.12-slim', collectedAt: t(10), logs: 'Collecting reqeusts\nRunning setup.py', partial: true, durationMs: 700, error: 'docker top: 컨테이너가 이미 멈춤',
      changes: [{ kind: 'A', path: '/tmp/p.sh' }, { kind: 'C', path: '/root/.bashrc' }, { kind: 'D', path: '/var/log/pip.log' }], processes: [] },
    { id: 'ev-2', containerId: cid, containerName: ctr, image: 'python:3.12-slim', collectedAt: t(11), logs: 'first', partial: false, durationMs: 120, changes: [], processes: [{ pid: 1, user: 'root', cmd: 'pip install ./reqeusts' }] },
    { id: 'ev-1', containerId: 'f'.repeat(64), containerName: ctr, image: 'python:3.12-slim', collectedAt: t(60), logs: 'older run', partial: false, durationMs: 90, changes: [], processes: [{ pid: 7, user: 'root', cmd: 'sh' }] },
  ];
  return { ctr, row, list };
}

test.describe('I 증거 · 도메인 조회 없는 IP 직접 연결', () => {
  test('감사 상세 「증거」 탭: 컨테이너 ID 별로 묶음 · 로그 · 파일 변경 A/C/D · 프로세스 · 일부만 모음 · 오류', async ({ page, backend }) => {
    const { ctr, row, list } = evidenceFor(backend);
    backend.evidence = list;
    await page.goto(`/audit?id=${row.id}`);
    const sheet = page.locator('[data-sheet="audit"]');
    await sheet.getByRole('tab', { name: '증거' }).click();
    await expect(page).toHaveURL(/tab=evidence/);
    // 10/20: 탭을 그린 뒤 요청이 나가므로 한 번만 보면 CI(작업자 2)에서 빈 배열로 잡혔다 — 나갈 때까지 기다린다
    await expect.poll(() => [...new Set(reqs(backend, 'GET', /^\/evidence\?/).map((r) => r.path))]).toEqual([`/evidence?container=${encodeURIComponent(ctr)}`]); // 개발 모드 이중 호출은 같은 주소
    const groups = sheet.locator('[data-evidence-group]');
    await expect(groups).toHaveCount(2);
    await expect(groups.first()).toHaveAttribute('data-current', 'true');
    await expect(groups.first().locator('[data-evidence]')).toHaveCount(2);
    const ev3 = groups.first().locator('[data-evidence="ev-3"]');
    await expect(ev3.locator('[data-part="evidence-partial"]')).toHaveText('일부만 모음');
    await expect(ev3.locator('[data-part="evidence-error"]')).toContainText('docker top: 컨테이너가 이미 멈춤');
    await expect(ev3.locator('[data-part="evidence-logs"]')).toContainText('Running setup.py');
    await expect(ev3.locator('[data-part="evidence-changes"] [data-change-kind]')).toHaveText(['C', 'A', 'D']); // R1 11/04: 여러 폴더(/root · /tmp · /var)라 파일 트리 — 폴더 이름순
    await expect(groups.first().locator('[data-evidence="ev-2"] [data-part="evidence-procs"]')).toContainText('pip install ./reqeusts');
    await expect(groups.nth(1)).toContainText('older run');
    await noPageOverflow(page);
    // 상세 탭으로 돌아가기
    await sheet.getByRole('tab', { name: '상세' }).click();
    await expect(sheet.getByTestId('audit-reason')).toBeVisible();
  });

  test('증거가 없으면 안내 한 줄', async ({ page, backend }) => {
    const { row } = evidenceFor(backend);
    await page.goto(`/audit?id=${row.id}&tab=evidence`);
    await expect(page.locator('[data-sheet="audit"] [data-part="evidence-empty"]')).toContainText('증거가 없습니다');
  });

  test('「증거 보기」 링크 — 설치 시트 · 토폴로지 판정 카드 → 감사 상세 증거 탭', async ({ page, backend }) => {
    const { ctr, list } = evidenceFor(backend);
    backend.evidence = list;
    await page.goto('/installs?id=ins-0012');
    await page.locator('[data-sheet="install"]').getByRole('link', { name: '증거 보기' }).click();
    // 컨테이너 필터는 state 로 넘기고 주소에는 tab · id 만(10/21)
    await expect(page).toHaveURL(/\/audit\?tab=evidence&id=\d+$/);
    await expect(page.getByRole('textbox', { name: '컨테이너' })).toHaveValue(ctr);
    await expect(page.locator('[data-sheet="audit"] [data-evidence="ev-3"]')).toBeVisible();

    await page.goto('/topology?container=pkg-reqeusts&node=c%3Apkg-reqeusts');
    await expect(page).toHaveURL(/\/topology\?node=c%3Apkg-reqeusts$/);
    await page.getByTestId('topology-decision').getByRole('link', { name: '증거 보기' }).click();
    await expect(page).toHaveURL(/\/audit\?tab=evidence/);
    await expect(page.getByRole('textbox', { name: '컨테이너' })).toHaveValue('pkg-reqeusts');
    await expect(page.locator('[data-sheet="audit"] [role="tab"][aria-selected="true"]')).toHaveText('증거');
    await expect(page.locator('[data-sheet="audit"] [data-part="evidence-empty"]')).toBeVisible();
  });

  test('이벤트 · 감사 상세의 「도메인 조회」 줄 — 직접 IP 연결 · trace_dns 확인 · 내부 주소', async ({ page, backend }) => {
    const base = backend.recent.find((v) => v.event.containerName === 'pkg-reqeusts' && v.event.kind === 'connect')!;
    const direct: Verdict = { ...base, event: { ...base.event, dstIp: '198.51.100.7', dstPort: 443, dstHost: undefined, dnsTraced: true, timestamp: new Date().toISOString() } };
    const priv: Verdict = { ...base, event: { ...base.event, dstIp: '10.1.2.3', dstPort: 5432, dstHost: undefined, dnsTraced: true, timestamp: new Date().toISOString() } };
    backend.recent.unshift(direct, priv);
    backend.audit.unshift({ ...direct, id: 999, caseId: null, install: null });
    await page.goto('/events');
    await page.locator('li[data-key]', { hasText: '198.51.100.7' }).click();
    const dd = page.locator('[data-sheet="event"] [data-dns]');
    await expect(dd).toHaveAttribute('data-dns', 'direct');
    await expect(dd).toContainText('도메인 조회 없는 IP 직접 연결');
    await closeSheet(page); // 11/05 슬라이드 패널: 열린 동안 뒤 화면은 어두운 배경에 가려 눌리지 않는다 — 먼저 닫는다
    await page.locator('li[data-key]', { hasText: '10.1.2.3' }).click();
    await expect(dd).toHaveAttribute('data-dns', 'private');
    await closeSheet(page); // 11/05 슬라이드 패널: 열린 동안 뒤 화면은 어두운 배경에 가려 눌리지 않는다 — 먼저 닫는다
    await page.locator('li[data-key]', { hasText: 'cdn.reqeusts-update.test' }).first().click();
    await expect(dd).toHaveAttribute('data-dns', 'traced');
    await page.goto('/audit?id=999');
    await expect(page.locator('[data-sheet="audit"] [data-dns="direct"]')).toContainText('도메인 조회 없는 IP 직접 연결');
  });
});

// ── D 목록 정리 ──
// 첫 응답을 붙잡아 두는 route(나중에 등록한 것이 먼저) — release() 뒤에 원래 가짜 백엔드로 넘긴다
async function hold(page: Page, re: RegExp) {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  await page.route(re, async (route) => {
    await gate;
    await route.fallback();
  });
  return release;
}
// on 인 동안 500 — 개발 모드(StrictMode)의 이중 호출 횟수에 기대지 않으려고 횟수 대신 스위치로 끈다
async function failWhile(page: Page, re: RegExp) {
  const sw = { on: true };
  await page.route(re, (route) => (sw.on ? route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: '저장소 응답 없음' }) }) : route.fallback()));
  return sw;
}

test.describe('D 목록 정리 — 스켈레톤 · 오류 + 다시 시도 · 빈 상태 · 필터 칩 · CSV · 키보드', () => {
  test('첫 로드 스켈레톤(설치 검사 · 감사 로그 · 공급망 검사 · 이벤트)', async ({ page, backend }) => {
    await scansApi(page, [repoScan], [], () => '');
    for (const [path, re, row] of [
      ['/installs', /\/api\/installs\?limit=500/, 'tr[data-install]'],
      ['/audit', /\/api\/audit\?/, 'tr[data-audit]'],
      ['/scans', /\/api\/scans$/, 'tr[data-scan]'],
      ['/events', /\/api\/events\/recent/, 'li[data-key]'],
    ] as const) {
      const release = await hold(page, re);
      await page.goto(path);
      await expect(page.locator('[data-part="skeleton"]'), path).toBeVisible();
      release();
      await expect(page.locator(row).first(), path).toBeVisible();
      await expect(page.locator('[data-part="skeleton"]'), path).toHaveCount(0);
      await page.unroute(re);
    }
    void backend;
  });

  test('오류 → 「다시 시도」 버튼으로 다시 부른다(설치 검사 · 감사 로그 · 공급망 검사 · 이벤트)', async ({ page, backend, allowConsole }) => {
    allowConsole(/500/);
    await scansApi(page, [repoScan], [], () => '');
    for (const [path, re, row] of [
      ['/installs', /\/api\/installs\?limit=500/, 'tr[data-install]'],
      ['/audit', /\/api\/audit\?/, 'tr[data-audit]'],
      ['/scans', /\/api\/scans$/, 'tr[data-scan]'],
      ['/events', /\/api\/events\/recent/, 'li[data-key]'],
    ] as const) {
      const sw = await failWhile(page, re); // 이벤트는 실시간 연결의 첫 조회도 함께 실패
      await page.goto(path);
      const err = page.locator('[data-part="error"]');
      await expect(err, path).toContainText('저장소 응답 없음');
      sw.on = false;
      await err.locator('[data-action="retry"]').click();
      await expect(page.locator(row).first(), path).toBeVisible();
      await expect(err, path).toHaveCount(0);
      await page.unroute(re);
    }
    void backend;
  });

  test('오류 동안은 30초마다 조용히 한 번 다시 부른다(시계 조작)', async ({ page, backend, allowConsole }) => {
    allowConsole(/500/);
    await page.clock.install();
    const sw = await failWhile(page, /\/api\/installs\?limit=500/);
    await page.goto('/installs');
    const err = page.locator('[data-part="error"]');
    await expect(err).toBeVisible();
    // 실패 응답은 이 파일의 route 가 먼저 받아 가짜 백엔드 기록에 없다 — 브라우저 요청으로 센다
    let calls = 0;
    page.on('request', (r) => /\/api\/installs\?limit=500/.test(r.url()) && calls++);
    await page.clock.fastForward(20_000);
    await page.waitForTimeout(200);
    expect(calls).toBe(0); // 5초 갱신도 오류 동안은 멈춘다
    await page.clock.fastForward(11_000);
    await expect.poll(() => calls).toBe(1);
    await expect(err).toBeVisible(); // 두 번째도 실패 — 스켈레톤 없이 오류 그대로
    await expect(page.locator('[data-part="skeleton"]')).toHaveCount(0);
    sw.on = false;
    await page.clock.fastForward(30_000);
    await expect.poll(() => calls).toBeGreaterThanOrEqual(2);
    await expect(page.locator('tr[data-install]').first()).toBeVisible();
    await expect(err).toHaveCount(0);
    expect(reqs(backend, 'GET', /^\/installs\?limit=500/).length).toBeGreaterThan(0); // 스위치를 끈 뒤에야 가짜 백엔드까지 갔다
  });

  // 11/05: 참고 대시보드처럼 아이콘 없는 빈 상태(10/20 「아이콘 있는 빈 상태」 대체) — 가운데 · 보조색 14px · 높이 180
  test('빈 상태: 아이콘 없이 글자만', async ({ page, backend }) => {
    backend.empty();
    backend.recent = [];
    backend.audit = [];
    await scansApi(page, [], [], () => '');
    for (const path of ['/installs', '/audit', '/scans', '/events']) {
      await page.goto(path);
      const empty = page.locator('[data-part="empty"]');
      await expect(empty, path).toBeVisible();
      await expect(empty.locator(':scope > svg'), path).toHaveCount(0); // 동작 단추 안 아이콘은 그대로
      expect(await empty.evaluate((e) => [getComputedStyle(e).textAlign, getComputedStyle(e).fontSize, e.getBoundingClientRect().height >= 180]), path).toEqual(['center', '14px', true]);
    }
  });

  test('적용된 필터 칩 + 모두 해제(주소에 남지 않음, 10/21) — 이벤트 · 감사 로그 · 설치 검사 · 공급망 검사', async ({ page, backend }) => {
    void backend;
    await scansApi(page, [repoScan, pkgScan], [], () => '');
    // 예전 북마크 · 바깥 링크의 쿼리는 초기 필터로 한 번 적용하고 주소에서 지운다
    await page.goto('/events?kind=exec&level=kill&container=pkg');
    let chips = page.locator('[data-part="filter-chips"]');
    await expect(chips.locator('[data-chip]')).toHaveCount(3);
    await expect(page).toHaveURL(/\/events$/);
    await chips.locator('[data-chip="kind"] button').click();
    await expect(chips.locator('[data-chip]')).toHaveCount(2);
    await expect(page.getByLabel('탐지 결과')).toHaveValue('kill');
    await chips.locator('[data-action="clear-filters"]').click();
    await expect(chips).toHaveCount(0);
    await expect(page).toHaveURL(/\/events$/);

    await page.goto('/audit?kind=connect&rule=egress&since=2026-01-01T00:00&until=2030-01-01T00:00');
    chips = page.locator('[data-part="filter-chips"]');
    await expect(chips.locator('[data-chip]')).toHaveCount(3); // 기간은 칩 하나(목업과 같게)
    await expect(chips.locator('[data-chip="period"]')).toContainText('기간: 2026-01-01 00:00 ~ 2030-01-01 00:00');
    await expect(page).toHaveURL(/\/audit$/);
    await chips.locator('[data-action="clear-filters"]').click();
    await expect(page.getByLabel('기간 시작')).toHaveValue('');
    await expect(chips).toHaveCount(0);

    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await page.locator('[data-chip="npm"]').click();
    chips = page.locator('[data-part="filter-chips"]');
    await expect(chips.locator('[data-chip]')).toHaveCount(2);
    await chips.locator('[data-chip="manager"] button').click();
    await expect(chips.locator('[data-chip]')).toHaveCount(1);
    await expect(page.locator('[data-chip="all"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(page).toHaveURL(/\/installs$/);

    await page.goto('/scans');
    await page.locator('[data-chip="malicious"]').click();
    await expect(page.locator('tr[data-scan]')).toHaveCount(1);
    await expect(page).toHaveURL(/\/scans$/);
    chips = page.locator('[data-part="filter-chips"]');
    await expect(chips.locator('[data-chip="verdict"]')).toContainText('악성 의심');
    await chips.locator('[data-action="clear-filters"]').click();
    await expect(page.locator('tr[data-scan]')).toHaveCount(2);
  });

  test('감사 로그 CSV 내보내기 — 기간 필수, 지금 필터(화면 상태) 그대로, BOM', async ({ page, backend }) => {
    await page.goto('/audit');
    await page.getByLabel('종류').selectOption('exec');
    await page.locator('[data-action="export-csv"]').click();
    await expect(page.locator('[data-part="export-error"]')).toContainText('기간');
    // datetime-local 값은 브라우저 시간대(timezoneId Asia/Seoul)로 만든다 — Node(CI 는 UTC)에서 만들면 9시간 어긋나 0건(11/05 CI)
    const [since, until] = await page.evaluate(() => {
      const local = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
      return [local(new Date(Date.now() - 3600_000)), local(new Date(Date.now() + 3600_000))];
    });
    await page.getByLabel('기간 시작').fill(since);
    await page.getByLabel('기간 끝').fill(until);
    expect(new URL(page.url()).search).toBe('');
    const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('[data-action="export-csv"]').click()]);
    expect(dl.suggestedFilename()).toMatch(/^supplyguard-audit-\d{8}-\d{8}\.csv$/);
    const text = readFileSync((await dl.path())!, 'utf8');
    expect(text.charCodeAt(0)).toBe(0xfeff);
    const lines = text.slice(1).trim().split('\n');
    expect(lines[0]).toBe('id,시각,컨테이너,이미지,종류,상세,규칙,탐지 결과,판정,사유');
    const want = backend.audit.filter((a) => a.event.kind === 'exec');
    expect(lines).toHaveLength(want.length + 1);
    expect(lines.slice(1).every((l) => l.split(',')[4] === 'exec')).toBe(true);
  });

  test('모든 행을 Tab 으로 닿고 Enter · Space 로 연다', async ({ page, backend }) => {
    void backend;
    await scansApi(page, [repoScan], [], () => '');
    await page.goto('/scans');
    await page.locator('tr[data-scan="scan-0002"]').focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('[data-sheet="scan"]')).toBeVisible();
    await page.goto('/installs');
    await page.locator('[data-chip="all"]').click();
    await page.locator('tr[data-install="ins-0010"]').focus();
    await page.keyboard.press(' ');
    await expect(page.locator('[data-sheet="install"]')).toBeVisible();
    await page.goto('/audit');
    await page.locator('tr[data-audit]').first().focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('[data-sheet="audit"]')).toBeVisible();
  });
});

test.describe('조회자 — 보이는데 못 누르는 버튼 없음', () => {
  test('이벤트 · 감사 상세에 「이 행동 막기 / 허용」 링크가 없고, 정책 화면에 해제 · 삭제 · 교체 버튼이 없다', async ({ page, backend }) => {
    backend.auth.asViewer();
    await page.goto('/events?container=pkg-reqeusts');
    await page.locator('li[data-key]').first().click();
    await expect(page.locator('[data-sheet="event"]')).toBeVisible();
    await expect(page.locator('[data-action="block-this"], [data-action="allow-this"]')).toHaveCount(0);
    await page.goto('/audit?id=200');
    await expect(page.locator('[data-sheet="audit"]')).toBeVisible();
    await expect(page.locator('[data-action="block-this"], [data-action="allow-this"]')).toHaveCount(0);
    await page.goto('/policies?id=__yaml__');
    await expect(page.getByTestId('blocklist').locator('[data-block]').first()).toBeVisible();
    await expect(page.getByTestId('blocklist').getByRole('button', { name: '해제' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /전체 교체/ })).toHaveCount(0);
    await page.goto('/policies?id=egress-allowlist');
    await expect(page.locator('[data-view="rule-editor"]').getByRole('button', { name: '삭제' })).toHaveCount(0);
  });
});
