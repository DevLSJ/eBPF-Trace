import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Locator, Page, Route } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';

// 11/09 저녁 묶음 사이 이음새(INTEG) — 묶음 B(오류 문장) · C(칸 이름표 lib/fieldNames.ts) · D(쉬운 말)가 만난 자리
//   실패 알림 = 「~하지 못했습니다.」 + 서버 문장(괄호에 넣지 않음 · 마침표 한 번) · 연결 실패 고정 문장은 lib/api.ts 한 곳
//   보고서 · 이벤트 「규칙」 칸 → 「정책」 · 공급망 검사 「매니저」 → 「패키지 관리자」 · 셸 머리 「초당 N건」 · 설정 이름 보조 글 12px 이상
// 화면 사진은 UI_SHOTS(없으면 SHOTS)에
const OUT = process.env.UI_SHOTS ?? SHOTS;
const NET = '서버에 연결하지 못했습니다. 네트워크를 확인한 뒤 다시 시도하세요.';
const NET_CONSOLE = /Failed to load resource|ERR_FAILED/;
const DIALOG = 'dialog[data-part="confirm"]';
const abort = (r: Route) => r.abort('failed');
const src = (f: string) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');

// 「~하지 못했습니다. 서버에 연결하지 못했습니다. …」 — 괄호 겹침 · 마침표 두 번 · 할 일 두 번이 없다
async function failLine(loc: Locator, head: string) {
  await expect(loc).toContainText(`${head} ${NET}`);
  const t = (await loc.innerText()).replace(/\s+/g, ' ');
  expect(t, t).not.toContain('(서버에 연결하지');
  expect(t, t).not.toMatch(/\.\s*\./);
  expect(t, t).not.toMatch(/\)\./);
  expect(t.match(/시도하세요\./g)?.length ?? 0, t).toBe(1);
}

test.describe('실패 알림 — 「~하지 못했습니다.」 + 서버 문장(괄호 없음)', () => {
  test('셸 띠: 이벤트를 불러오지 못했습니다. + 연결 실패 문장 + 영향 한 문장', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.route(/\/api\/events\/recent/, abort);
    await page.goto('/');
    const banner = page.locator('[data-banner="load"]');
    await failLine(banner, '이벤트를 불러오지 못했습니다.');
    await expect(banner).toContainText(`${NET} 지금 보이는 목록`);
  });

  test('패널 불러오기 실패: 「[무엇]을(를) 불러오지 못했습니다.」(조사) + 다음 줄에 이유', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.route(/\/api\/integration$/, abort);
    await page.goto('/integration');
    const note = page.locator('[data-part="integration"][data-state="error"] [role="note"]');
    await expect(note.locator('[data-part="load-error-head"]')).toHaveText('연동 상태를 불러오지 못했습니다.');
    await expect(note.locator('[data-part="load-error-text"]')).toHaveText(NET);
    await expect(note).not.toContainText('불러오기 실패');
    await expect(note).not.toContainText('을(를)');
    // 두 줄 — 이유는 머리 아래
    const [h, b] = await Promise.all([note.locator('[data-part="load-error-head"]').boundingBox(), note.locator('[data-part="load-error-text"]').boundingBox()]);
    expect(b!.y).toBeGreaterThan(h!.y + h!.height - 1);
  });

  test('설정: 테스트 알림 토스트', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.goto('/settings');
    await page.route(/\/api\/notify\/test$/, abort);
    await page.locator('[data-part="notify"]').getByRole('button', { name: '테스트 발송' }).click();
    await failLine(page.locator('[data-toast="notify-test"]'), '테스트 알림을 보내지 못했습니다.');
  });

  test('시연: 시작 실패 띠', async ({ page, backend, allowConsole }) => {
    allowConsole(NET_CONSOLE);
    backend.enableDemo();
    await page.route(/\/api\/demo\/run$/, abort);
    await page.goto('/demo');
    await page.locator('[data-part="demo-page"]').getByRole('button', { name: '시연 시작' }).click();
    await failLine(page.locator('[data-part="demo-error"]'), '시연을 시작하지 못했습니다.');
  });

  test('연동: 연결 테스트 시작 실패 토스트', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.goto('/integration');
    await expect(page.locator('[data-part="integration"][data-state="ready"]')).toBeVisible();
    await page.route(/\/api\/integration\/test$/, abort);
    await page.locator('[data-part="test-step"] [data-part="test-start"]').click();
    await failLine(page.locator('[data-toast="int-test"]'), '연결 테스트를 시작하지 못했습니다.');
  });

  test('판정 실패 토스트: 이유 한 문장 + 할 일은 한 번', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.route(/\/api\/cases\/[^/]+\/decide$/, abort);
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator(`${DIALOG} [data-confirm="ok"]`).click();
    await failLine(page.locator('[data-toast="decide:case-0004"]'), '판정하지 못했습니다.');
  });

  test('판정 실패(서버 문장, 마침표 없음) → 마침표를 붙여 한 문장 + 할 일', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/status of 500/);
    await page.route(/\/api\/cases\/[^/]+\/decide$/, (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: '모의 오류' }) }));
    await page.goto('/installs?id=ins-0012');
    await page.getByTestId('decision').getByRole('button', { name: '악성 확정' }).click();
    await page.locator(`${DIALOG} [data-confirm="ok"]`).click();
    await expect(page.locator('[data-toast="decide:case-0004"]')).toContainText('판정하지 못했습니다. 모의 오류. 잠시 뒤 다시 시도하세요.');
  });

  test('차단 목록: 해제 실패 토스트', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.goto('/policies/blocklist');
    const t = page.getByTestId('blocklist');
    await page.route(/\/api\/blocklist\/hosts\//, abort);
    await t.locator('tr[data-block="hosts:cdn.colourama.test"]').getByRole('button', { name: /^해제/ }).click();
    const d = page.locator(DIALOG);
    await d.getByRole('textbox', { name: /사유/ }).fill('오탐');
    await d.locator('[data-confirm="ok"]').click();
    await failLine(page.locator('[data-toast="unblock:cdn.colourama.test"]'), '차단을 해제하지 못했습니다.');
  });

  test('정책 변경 이력: 되돌리기 실패 토스트', async ({ page, backend, allowConsole }) => {
    allowConsole(NET_CONSOLE);
    backend.seedPolicyHistory();
    await page.goto('/policies?id=sensitive-files&tab=changes');
    const list = page.locator('[data-testid="policy-changes"]');
    await page.route(/\/api\/policies\/[^/]+\/revert$/, abort);
    await list.getByRole('button', { name: '되돌리기(chg-0012)' }).click();
    const d = page.locator(DIALOG);
    await d.getByRole('textbox', { name: '사유' }).fill('오탐 증가');
    await d.getByRole('checkbox').check();
    await d.locator('[data-confirm="ok"]').click();
    await failLine(page.locator('[data-toast="revert-fail:chg-0012"]'), '되돌리지 못했습니다.');
  });

  test('YAML 일괄 적용: 불러오기 실패 · 적용 실패', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.goto('/policies');
    await page.route(/\/api\/policies\/export$/, abort);
    await page.getByRole('button', { name: 'YAML 일괄 적용' }).click();
    await failLine(page.getByRole('dialog').getByRole('alert'), 'YAML 을 불러오지 못했습니다.');
    await page.getByRole('dialog').locator('button.sg-btn-secondary', { hasText: '닫기' }).click();
    await page.unroute(/\/api\/policies\/export$/);
    await page.route(/\/api\/policies$/, (r) => (r.request().method() === 'PUT' ? r.abort('failed') : r.fallback()));
    await page.getByRole('button', { name: 'YAML 일괄 적용' }).click();
    const modal = page.getByRole('dialog').first();
    await expect(modal.locator('textarea')).not.toHaveValue('불러오는 중…');
    await modal.getByRole('button', { name: '전체 교체 후 적용' }).click();
    await page.locator(DIALOG).getByRole('checkbox').check();
    await page.locator(`${DIALOG} [data-confirm="ok"]`).click();
    await failLine(modal.getByRole('alert'), '적용하지 못했습니다.');
  });

  test('감사 로그: 내보내기 실패 줄', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.goto('/audit');
    await expect(page.locator('table[data-table="audit"]')).toBeVisible();
    const [since, until] = await page.evaluate(() => {
      const local = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
      return [local(new Date(Date.now() - 3600_000)), local(new Date(Date.now() + 3600_000))];
    });
    await page.getByLabel('기간 시작').fill(since);
    await page.getByLabel('기간 끝').fill(until);
    await page.route(/\/api\/audit(\?|$)/, abort);
    await page.locator('[data-table-tools="audit"] [data-action="table-export"]').click();
    await failLine(page.locator('[data-part="export-error"]'), '내보내지 못했습니다.');
  });

  test('소스: 오류 문장을 괄호에 넣는 곳이 없다(errorText · 서버 오류 · 「불러오기 실패:」)', () => {
    const root = new URL('../src/', import.meta.url).pathname;
    const files: string[] = [];
    const walk = (d: string) => {
      for (const n of readdirSync(d)) {
        const p = join(d, n);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|tsx)$/.test(n)) files.push(p);
      }
    };
    walk(root);
    const bad: string[] = [];
    const patterns = [
      /\(\$\{errorText\(/, // `…(${errorText(e)}).`
      /\(\{errorText\(/, // JSX …({errorText(e)})
      /못했습니다\(\$\{/, // `…못했습니다(${…}).`
      /못했습니다\(\{/, // JSX …못했습니다({…}).
      /못했습니다<\/b>\(/,
      /\(\$\{e\.message\}\)/,
      /불러오기 실패:/,
    ];
    for (const f of files) {
      const lines = readFileSync(f, 'utf8').split('\n');
      lines.forEach((l, i) => {
        if (patterns.some((re) => re.test(l))) bad.push(`${f.slice(root.length)}:${i + 1}`);
      });
    }
    expect(bad, bad.join('\n')).toEqual([]);
  });

  test('연결 실패 고정 문장은 lib/api.ts 한 곳 — 세션 확인도 errorText 로', () => {
    expect(src('lib/api.ts')).toContain(`'${NET}'`);
    const auth = src('hooks/auth-context.tsx');
    expect(auth).not.toContain('서버에 연결하지 못했습니다');
    expect(auth).toMatch(/errorText/);
  });

  test('세션 확인이 프록시 오류(502 텍스트)면 상태별 고정 문장 — 연결 실패 문장 아님', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(/status of 502/);
    await page.route(/\/api\/auth\/me$/, (r) => r.fulfill({ status: 502, contentType: 'text/html', body: '<html>Bad Gateway</html>' }));
    await page.goto('/');
    const box = page.locator('[data-part="auth-check-error"]');
    await expect(box.locator('[data-part="auth-check-message"]')).toHaveText('서버가 응답하지 않습니다. 잠시 뒤 다시 시도하세요.');
    await expect(box).not.toContainText('Bad Gateway');
  });
});

test.describe('칸 이름 — 통일표(lib/fieldNames.ts) 한 곳', () => {
  test('건 보고서 위반 표 · Markdown 「정책」 칸', async ({ page, backend, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    backend.enableIsolation();
    await page.goto('/report?install=ins-0012');
    const rep = page.getByTestId('report');
    await expect(rep.locator('[data-section="violations"] tbody tr').first()).toBeVisible();
    expect(await rep.locator('[data-section="violations"] thead th').allTextContents()).toEqual(['시각', '종류', '정책', '상세', '판정']);
    await page.getByRole('button', { name: 'Markdown 복사' }).click();
    await expect(page.locator('[data-toast="report-copy"]')).toContainText('복사');
    const md = await page.evaluate(() => navigator.clipboard.readText());
    expect(md).toContain('| 시각 | 종류 | 정책 | 상세 | 판정 |');
    expect(md).not.toContain('| 규칙 |');
  });

  test('이벤트 표(넓은 폭) 머리 「정책」', async ({ page, backend }) => {
    void backend;
    await page.goto('/events');
    const head = page.locator('[data-part="feed-head"]');
    await expect(head).toBeVisible();
    await expect(head.getByText('정책', { exact: true })).toBeVisible();
    await expect(head.getByText('규칙', { exact: true })).toHaveCount(0);
  });

  test('공급망 검사: 검사할 대상의 패키지 관리자 칸 이름', async ({ page, backend }) => {
    void backend;
    await page.route(/\/api\/scans(\/|$|\?)/, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
    await page.goto('/scans');
    await expect(page.locator('select[data-field="manager"]')).toHaveAccessibleName('패키지 관리자');
    await expect(page.getByLabel('매니저', { exact: true })).toHaveCount(0);
  });

  test('필터 해제 「조건 지우기」 · 칸 이름은 통일표에서 읽는다', () => {
    expect(src('components/list/state-copy.ts')).toMatch(/clear: FIELD\.clearFilters/);
    for (const f of ['features/report/ReportPage.tsx', 'lib/report.ts', 'components/EventFeed.tsx', 'features/scans/ScansPage.tsx']) {
      const s = src(f);
      expect(s, f).toMatch(/\/fieldNames'/);
      expect(s, f).toMatch(/FIELD\.(policy|manager)/);
    }
  });
});

test.describe('쉬운 말 · 글자 크기', () => {
  test('셸 머리 「초당 N건」(evt 없음)', async ({ page, backend }) => {
    void backend;
    await page.goto('/events');
    const st = page.getByRole('status').filter({ hasText: '초당' });
    await expect(st).toHaveText(/초당\s*[\d.,]+건/);
    await expect(st).not.toContainText('evt');
  });

  test('설정 이름 보조 글(data-part="setting-name")은 12px 이상 — 서버 · 알림 · AI 도우미', async ({ page, backend }) => {
    void backend;
    await page.goto('/settings');
    await expect(page.locator('[data-part="settings-tabs"]')).toBeVisible();
    const names = page.locator('main [data-part="setting-name"]');
    await expect(names.first()).toBeVisible();
    const sizes = await names.evaluateAll((els) => els.filter((e) => e.getClientRects().length).map((e) => `${e.textContent!.trim()}:${getComputedStyle(e).fontSize}`));
    expect(sizes.length).toBeGreaterThan(3);
    const small = sizes.filter((s) => parseFloat(s.split(':').pop()!) < 12 - 0.01);
    expect(small, small.join(' | ')).toEqual([]);
    expect(sizes.some((s) => s.startsWith('NOTIFY_WEBHOOK'))).toBe(true);
  });
});

test.describe('사진(다크 · 390)', () => {
  // 화면 들어오기 움직임이 끝난 뒤 찍는다(흐린 사진 방지)
  const shoot = async (page: Page, name: string) => {
    await page.evaluate(() =>
      Promise.all(
        document
          .getAnimations()
          .filter((a) => Number.isFinite(Number(a.effect?.getComputedTiming().endTime))) // 깜빡임 같은 끝없는 움직임은 빼고
          .map((a) => a.finished.catch(() => undefined)),
      ),
    );
    await page.screenshot({ path: `${OUT}/ui-integ-${name}.png` });
  };
  test('다크: 셸 띠 실패 문장', async ({ page, backend, allowConsole }) => {
    void backend;
    allowConsole(NET_CONSOLE);
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await page.route(/\/api\/events\/recent/, abort);
    await page.goto('/');
    await failLine(page.locator('[data-banner="load"]'), '이벤트를 불러오지 못했습니다.');
    await shoot(page, 'banner-dark');
  });

  test.describe('390', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('390: 패널 불러오기 실패 두 줄', async ({ page, backend, allowConsole }) => {
      void backend;
      allowConsole(NET_CONSOLE);
      await page.route(/\/api\/integration$/, abort);
      await page.goto('/integration');
      await expect(page.locator('[data-part="load-error-head"]')).toHaveText('연동 상태를 불러오지 못했습니다.');
      await shoot(page, 'load-error-390');
    });
  });
});
