import { expect, SHOTS, test } from './fixtures';

// 2026-10-15 추가 확정: 자동 미리보기(3) · 패키지 표기(4) · 계약 추가(6)

test.describe('정책 제안 — 자동 미리보기', () => {
  test('제안을 열면 미리보기가 자동으로 계산되고 적용이 바로 켜진다', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0011');
    await page.getByTestId('decision').getByRole('button', { name: '오탐' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await page.getByRole('button', { name: '제안 보기' }).click();
    const detail = page.getByTestId('proposal');
    await expect(detail.getByTestId('preview-summary')).toBeVisible();
    await expect(detail.locator('[data-to-normal="2"]')).toBeVisible();
    await expect(detail.getByRole('button', { name: '적용' })).toBeEnabled();
    expect(backend.requests.filter((r) => r.path.startsWith('/proposals/') && r.path.endsWith('/preview'))).toHaveLength(1); // W18: 판정 미리보기(/cases/…/preview)는 따로
  });
});

test.describe('패키지 표기 — 화면은 친 그대로, 차단 목록 · 변경 내용만 정규화 이름', () => {
  test('대시보드 · 제안 목록 · 제목은 「pip ./reqeusts」, 변경 내용 · 차단 목록은 「pip:reqeusts」', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    const row = page.locator('[data-case="case-0004"]');
    await expect(row).toContainText('pip ./reqeusts');
    await expect(row).not.toContainText('pip:reqeusts');
    await expect(page.locator('[data-case="case-0003"]')).toContainText('npm tiny-git-dep');

    await row.click();
    await expect(page.locator('[data-sheet="install"]')).toHaveAttribute('aria-label', 'pip ./reqeusts');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await expect(page.locator('[data-toast^="decide:"]')).toContainText('pip ./reqeusts 악성 확정');
    await page.getByRole('button', { name: '제안 보기' }).click();

    const item = page.getByTestId('proposals').locator('[data-proposal]').first();
    await expect(item).toContainText('pip ./reqeusts');
    const detail = page.getByTestId('proposal');
    await expect(detail.locator('header')).toContainText('pip ./reqeusts');
    await expect(detail.getByTestId('proposal-changes')).toContainText('패키지 차단 pip:reqeusts');
    await detail.getByRole('button', { name: '적용' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await expect(page.getByTestId('blocklist').locator('[data-block="packages:pip:reqeusts"]')).toContainText('pip:reqeusts');
  });
});

test.describe('계약 추가 (10/15)', () => {
  test('변경 이력 kind blocklist_remove → 「차단 해제」 (정책 · 감사 로그)', async ({ page, backend }) => {
    await page.goto('/policies');
    const entry = page.getByTestId('blocklist').locator('[data-block="packages:pip:colourama"]');
    await entry.getByRole('button', { name: '해제' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await expect(page.getByTestId('changes').locator('[data-change]').first()).toContainText('차단 해제');
    expect(backend.changes[0].kind).toBe('blocklist_remove');
    await page.goto('/audit?view=changes');
    await expect(page.getByTestId('history').locator(`[data-history="chg:${backend.changes[0].id}"]`)).toContainText('차단 해제');
  });

  test('Proposal notes 표시 — 실행 규칙은 자동 예외 없음 안내', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '오탐' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await page.getByRole('button', { name: '제안 보기' }).click();
    const notes = page.getByTestId('proposal-notes');
    await expect(notes).toContainText('pipe-to-shell');
    await expect(notes).toContainText('정책 탭에서 직접 수정'); // 백엔드 review/cases.go 안내문 그대로
  });

  test('Preview nextOnly → 「다음 설치 · 기동부터 적용」 목록', async ({ page, backend }) => {
    void backend;
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await page.getByRole('button', { name: '제안 보기' }).click();
    const next = page.getByTestId('next-only');
    await expect(next).toContainText('다음 설치 · 기동부터 적용');
    await expect(next.locator('li')).toHaveText([/패키지 pip:reqeusts/]);
    await page.screenshot({ path: `${SHOTS}/1440-09-proposal-auto-preview.png` });
  });

  test('설치 목록은 violationCount 로 위반 수를 보인다(목록 응답에 violations 없음)', async ({ page, backend }) => {
    backend.listOmitsDetail = true;
    await page.goto('/installs?status=all');
    // 11/04: 「설치 결과」 다음에 「정적 검사」 열이 들어와 위반 열이 한 칸 뒤로(5 → 6)
    await expect(page.locator('tr[data-install="ins-0012"] td').nth(6)).toHaveText('6');
    await expect(page.locator('tr[data-install="ins-0011"] td').nth(6)).toHaveText('2');
    expect(backend.requests.some((r) => r.path.startsWith('/installs?'))).toBe(true);
  });

  test('경고 이벤트는 열린 런타임 건에 묶인다(감사 로그 판정 열)', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit?container=pkg-reqeusts&rule=egress-allowlist'); // AI 도우미 답 링크 모양 — 적용 뒤 주소에서 지운다(10/21)
    await expect(page.locator('tr[data-audit]')).toHaveCount(1);
    await expect(page).toHaveURL(/\/audit$/);
    await expect(page.locator('tr[data-audit] [data-col="decision"] [data-decision="pending"]')).toBeVisible();
  });

  // 10/16 정정: 금지 포트(denyPorts)는 허용 대역보다 먼저 판정되므로 reverse-shell-ports 는 예외 대신 안내(백엔드 rules/engine.go matchConnect)
  test('오탐 예외: 규칙에 allowHosts 가 원래 없으면 allowCidrs IP/32 제안, 금지 포트 규칙은 안내만', async ({ page, backend }) => {
    await page.goto('/topology?container=pkg-reqeusts&node=c%3Apkg-reqeusts');
    await page.getByTestId('topology-decision').getByRole('button', { name: '오탐' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    const p = backend.proposals[0];
    expect(p.changes).toContainEqual({ op: 'except', ruleId: 'egress-allowlist', field: 'allowCidrs', value: '203.0.113.7/32' });
    expect(p.changes.some((c) => c.op === 'except' && c.ruleId === 'reverse-shell-ports')).toBe(false);
    await page.goto(`/policies?proposal=${p.id}`);
    await expect(page.getByTestId('proposal-changes')).toContainText('egress-allowlist 허용 대역 += 203.0.113.7/32');
    await expect(page.getByTestId('proposal-notes')).toContainText('reverse-shell-ports 은 금지 목록');
  });

  test('차단 이미지 재기동은 새 건을 열지 않는다', async ({ page, backend }) => {
    await page.goto('/topology?container=pkg-reqeusts&node=c%3Apkg-reqeusts');
    await page.getByTestId('topology-decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await page.getByRole('button', { name: '제안 보기' }).click();
    await page.getByTestId('proposal').getByRole('button', { name: '적용' }).click();
    await page.locator('dialog[data-part="confirm"] [data-confirm="ok"]').click(); // W18: 확인 대화상자
    await expect(page.getByTestId('proposal-state')).toContainText('적용됨');
    const before = backend.cases.length;
    backend.runtimeKill('pkg-reqeusts', 'demo/reqeusts:1.0.2'); // 같은 이미지로 다시 뜸 → 시작 즉시 격리(blocked-image)
    await page.goto('/');
    await expect(page.getByTestId('pending-count')).toHaveText('2');
    expect(backend.cases.length).toBe(before);
    expect(backend.recent[0].ruleId).toBe('blocked-image');
  });
});
