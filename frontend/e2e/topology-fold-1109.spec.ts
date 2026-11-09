import type { Page } from '@playwright/test';
import type { Event, Verdict } from '../src/lib/types';
import { expect, SHOTS, test } from './fixtures';
import type { MockBackend } from './mock-backend';

// 11/09 사용자 결정 「정상 컨테이너 접기 + 최소 배율」 — 실제 가젯(전체 감시)에서 위반 없는 컨테이너의 /proc · /lib · /sys 열기가
// 노드를 세로로 쌓아 화면 맞춤이 약 0.35배(글자 약 4px)까지 줄던 문제(메인 실측: 컨테이너 3 · 노드 33 · 선 48).
// - 위반 있는 컨테이너는 지금처럼 펼침 · 위반 없는 컨테이너는 한 노드(이름 + 「파일 N · 연결 M」)로 접힘, 누르거나 Enter 로 펼침 · 다시 접힘
// - 컨테이너를 고르면 그 컨테이너는 펼친 상태 · 위반이 생기면 자동으로 펼침
// - 화면 맞춤은 노드 글자(12px)가 9px 아래로 보이지 않는 배율(0.75) 아래로 줄이지 않음 — 다 안 들어가면 위험 컨테이너(맨 위 · 왼쪽)부터
const READABLE = 0.75; // 12px × 0.75 = 9px
const SHOT_DIR = `${SHOTS}/topology-1109`;

// 위반 없는 「다른 프로젝트 DB」 컨테이너 — 프로세스 3개, 파일 files 개(/proc · /lib · /sys), 내부 연결 dests 개
const NORMAL = [
  { name: 'db-main', image: 'postgres:17', files: 20, dests: 2 },
  { name: 'db-replica', image: 'postgres:17', files: 14, dests: 1 },
  { name: 'cache-redis', image: 'redis:7', files: 9, dests: 0 },
  { name: 'metrics', image: 'prom/prometheus:v2', files: 12, dests: 3 },
];
const PROCS: Record<string, string[]> = {
  'db-main': ['postgres', 'pg_isready', 'sh'],
  'db-replica': ['postgres', 'pg_basebackup', 'sh'],
  'cache-redis': ['redis-server', 'redis-cli', 'sh'],
  metrics: ['prometheus', 'promtool', 'sh'],
};

function ev(name: string, image: string, at: number, e: Partial<Event> & Pick<Event, 'kind' | 'comm'>): Event {
  return { timestamp: new Date(at).toISOString(), containerId: `${name.replace(/[^a-z0-9]/g, '')}0123456789abcdef`, containerName: name, imageName: image, pid: 4300, ...e };
}

function seedNormal(b: MockBackend) {
  const now = Date.now();
  const out: Verdict[] = [];
  for (const c of NORMAL) {
    const procs = PROCS[c.name];
    for (let i = 0; i < c.files; i++) {
      const comm = procs[i % procs.length];
      const path = i % 3 === 0 ? `/proc/${100 + i}/stat` : i % 3 === 1 ? `/usr/lib/x86_64-linux-gnu/lib${c.name}-${i}.so.1` : `/sys/fs/cgroup/${c.name}/cpu.stat.${i}`;
      for (let k = 0; k <= i % 3; k++) out.push({ event: ev(c.name, c.image, now - 3_000 - i * 40 - k, { kind: 'open', comm, path }), matched: false });
    }
    for (let j = 0; j < c.dests; j++)
      out.push({ event: ev(c.name, c.image, now - 2_500 - j * 30, { kind: 'connect', comm: procs[0], dstIp: `10.0.1.${j + 1}`, dstPort: 5432, dnsTraced: true }), matched: false });
  }
  b.recent.unshift(...out);
}

const flow = (page: Page) => page.getByTestId('topology').locator('.react-flow');
const node = (page: Page, id: string) => page.locator(`.react-flow__node[data-id="${id}"]`);
const nodesOf = (page: Page, prefix: string) => page.locator(`.react-flow__node[data-id^="${prefix}"]`);
const folded = (page: Page) => page.locator('.react-flow__node[data-fold="folded"]');

// React Flow viewport transform 의 배율 — 맞춤이 끝나 300ms 동안 같은 값일 때까지 기다려 읽는다
async function settledScale(page: Page): Promise<number> {
  const read = () => page.locator('.react-flow__viewport').evaluate((el) => new DOMMatrixReadOnly(getComputedStyle(el).transform).a);
  let prev = -1;
  for (let i = 0; i < 40; i++) {
    const s = await read();
    if (Math.abs(s - prev) < 1e-4) return s;
    prev = s;
    await page.waitForTimeout(150);
  }
  return prev;
}

// 노드가 그래프 칸 안에 보이는지(위 · 왼쪽 기준)
async function inPane(page: Page, id: string) {
  const pane = (await flow(page).boundingBox())!;
  const box = (await node(page, id).boundingBox())!;
  return box.y >= pane.y - 1 && box.y + box.height <= pane.y + pane.height + 1 && box.x >= pane.x - 1 && box.x < pane.x + pane.width;
}

const lum = ([r, g, b]: number[]) => {
  const c = [r, g, b].map((v) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const rgbOf = (s: string) => (s.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number);
const contrast = (a: string, b: string) => {
  const [x, y] = [lum(rgbOf(a)), lum(rgbOf(b))].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

test.describe('토폴로지 — 정상 컨테이너 접기 + 최소 배율 (11/09)', () => {
  test('① 위반 없는 컨테이너는 기본 접힘(이름 + 파일 · 연결 수) · 위반 있는 컨테이너는 펼침', async ({ page, backend }) => {
    seedNormal(backend);
    await page.goto('/topology');
    await expect(node(page, 'c:pkg-reqeusts')).toBeVisible();
    // 정상 6개(web-api · worker + 다른 프로젝트 4개) 접힘, 위반 컨테이너는 접히지 않음
    await expect(folded(page)).toHaveCount(6);
    await expect(node(page, 'c:pkg-reqeusts')).not.toHaveAttribute('data-fold', /.*/);
    await expect(node(page, 'f:pkg-reqeusts:/etc/shadow')).toBeVisible();
    await expect(nodesOf(page, 'p:pkg-reqeusts:')).toHaveCount(3);
    // 접힌 노드: 이름 + 요약 숫자(창 안의 전체 — 정상 말단 상한 6 과 무관), 안쪽 노드는 그리지 않음
    const db = node(page, 'c:db-main');
    await expect(db).toHaveAttribute('data-fold', 'folded');
    await expect(db).toHaveAttribute('aria-expanded', 'false');
    await expect(db).toContainText('db-main');
    await expect(db.locator('[data-part="fold-summary"]')).toHaveText('파일 20 · 연결 2');
    await expect(node(page, 'c:cache-redis').locator('[data-part="fold-summary"]')).toHaveText('파일 9 · 연결 0');
    await expect(node(page, 'c:web-api').locator('[data-part="fold-summary"]')).toHaveText('파일 1 · 연결 1');
    await expect(nodesOf(page, 'p:db-main:')).toHaveCount(0);
    await expect(nodesOf(page, 'f:db-main:')).toHaveCount(0);
    // 범례에 접힘 안내
    await expect(page.getByTestId('topology')).toContainText('위반 없는 컨테이너는 접힘');
  });

  test('② 누르면 펼침 · 다시 누르면 접힘 — Enter 도 같음, 접고 펼 때 상세 패널은 열리지 않음', async ({ page, backend }) => {
    seedNormal(backend);
    await page.goto('/topology');
    const db = node(page, 'c:db-main');
    await expect(db).toHaveAttribute('data-fold', 'folded');
    await db.click();
    await expect(db).toHaveAttribute('data-fold', 'open');
    await expect(db).toHaveAttribute('aria-expanded', 'true');
    await expect(nodesOf(page, 'p:db-main:')).toHaveCount(3);
    await expect(page.locator('.react-flow__node[data-id^="f:db-main:"], .react-flow__node[data-id^="d:db-main:"]')).toHaveCount(6); // 정상 말단 상한 6 그대로
    await expect(page.locator('.sg-sheet-layer')).toHaveCount(0);
    await db.click();
    await expect(db).toHaveAttribute('data-fold', 'folded');
    await expect(nodesOf(page, 'p:db-main:')).toHaveCount(0);
    // 키보드: 노드에 초점 → Enter
    const rep = node(page, 'c:db-replica');
    await rep.focus();
    await page.keyboard.press('Enter');
    await expect(rep).toHaveAttribute('data-fold', 'open');
    await expect(nodesOf(page, 'p:db-replica:')).toHaveCount(3);
    await rep.focus();
    await page.keyboard.press('Enter');
    await expect(rep).toHaveAttribute('data-fold', 'folded');
    await expect(page.locator('.sg-sheet-layer')).toHaveCount(0);
    // 위반 컨테이너 노드는 그대로 상세 패널
    await node(page, 'c:pkg-reqeusts').click();
    await expect(page.getByTestId('node-detail')).toContainText('pkg-reqeusts');
  });

  test('③ 컨테이너를 고르면 그 컨테이너는 펼친 상태 · 노드를 누르면 상세 패널', async ({ page, backend }) => {
    seedNormal(backend);
    await page.goto('/topology');
    await expect(node(page, 'c:db-main')).toBeVisible();
    await page.getByRole('combobox', { name: /^컨테이너/ }).selectOption('db-main');
    await expect(nodesOf(page, 'p:db-main:')).toHaveCount(3);
    await expect(folded(page)).toHaveCount(0);
    await node(page, 'c:db-main').click();
    await expect(page.getByTestId('node-detail')).toContainText('db-main');
  });

  test('④ 위반이 생기면 자동으로 펼침', async ({ page, backend }) => {
    seedNormal(backend);
    await page.goto('/topology');
    await expect(node(page, 'c:db-main')).toHaveAttribute('data-fold', 'folded');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    backend.send({
      type: 'verdict',
      data: { event: ev('db-main', 'postgres:17', Date.now(), { kind: 'open', comm: 'sh', path: '/root/.aws/credentials' }), matched: true, ruleId: 'sensitive-files', action: 'alert', reason: '자격 증명 파일 접근' },
    });
    await expect(node(page, 'f:db-main:/root/.aws/credentials')).toBeVisible();
    await expect(node(page, 'c:db-main')).not.toHaveAttribute('data-fold', /.*/);
    await expect(nodesOf(page, 'p:db-main:')).toHaveCount(3);
    await expect(page.locator('[data-chain="db-main"]')).toBeVisible();
    await expect(folded(page)).toHaveCount(5);
  });

  test('⑤ 화면 맞춤 배율은 하한(0.75 = 글자 9px) 이상 — 다 안 들어가면 위험 컨테이너가 먼저 보임', async ({ page, backend }) => {
    seedNormal(backend);
    await page.goto('/topology');
    await expect(node(page, 'c:pkg-reqeusts')).toBeVisible();
    const s0 = await settledScale(page);
    expect(s0, `처음 맞춤 배율 ${s0}`).toBeGreaterThanOrEqual(READABLE);
    const font = await node(page, 'c:pkg-reqeusts').evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
    expect(font * s0, '노드 글자 화면 크기(px)').toBeGreaterThanOrEqual(9);
    expect(await inPane(page, 'c:pkg-reqeusts')).toBe(true);
    // 접힌 상태는 한 화면에 다 들어가고 가로 가운데(맞춤이 실제로 돈 것 — 기본 시점이면 왼쪽에 붙는다)
    const fit = await page.evaluate(() => {
      const pane = document.querySelector('[data-testid="topology"] .react-flow')!.getBoundingClientRect();
      const boxes = [...document.querySelectorAll('.react-flow__node')].map((e) => e.getBoundingClientRect());
      const l = Math.min(...boxes.map((b) => b.left)), r = Math.max(...boxes.map((b) => b.right));
      const t = Math.min(...boxes.map((b) => b.top)), btm = Math.max(...boxes.map((b) => b.bottom));
      return { left: l - pane.left, right: pane.right - r, top: t - pane.top, bottom: pane.bottom - btm };
    });
    expect(Math.min(fit.left, fit.right, fit.top, fit.bottom), `전부 칸 안 ${JSON.stringify(fit)}`).toBeGreaterThanOrEqual(0);
    expect(Math.abs(fit.left - fit.right), `가로 가운데 ${JSON.stringify(fit)}`).toBeLessThanOrEqual(4);
    // 정상 컨테이너를 모두 펼쳐 칸을 넘치게 한 뒤 「화면 맞춤」 — 하한은 지키고 맨 위 위험 컨테이너가 보임
    // 펼칠 때마다 그 묶음이 보이게 옮기므로 다른 접힌 노드는 칸 밖일 수 있다 — 화면 위치와 무관하게 click 이벤트로
    for (const c of ['web-api', 'worker', ...NORMAL.map((n) => n.name)]) {
      await node(page, `c:${c}`).dispatchEvent('click');
      await expect(node(page, `c:${c}`)).toHaveAttribute('data-fold', 'open');
    }
    await page.locator('.react-flow__controls-fitview').click();
    const s1 = await settledScale(page);
    expect(s1, `모두 펼친 뒤 맞춤 배율 ${s1}`).toBeGreaterThanOrEqual(READABLE);
    expect(await inPane(page, 'c:pkg-reqeusts'), '위험 컨테이너가 칸 안').toBe(true);
    expect(await inPane(page, 'f:pkg-reqeusts:/etc/shadow'), '위험 컨테이너의 파일도 칸 안').toBe(true);
  });

  test('⑥ 다크 모드 — 접힌 노드가 바탕과 구분되고 글자 대비 4.5 이상', async ({ page, backend }) => {
    seedNormal(backend);
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await page.goto('/topology');
    await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    const db = node(page, 'c:db-main');
    await expect(db).toHaveAttribute('data-fold', 'folded');
    await expect(db.locator('[data-part="fold-summary"]')).toBeVisible();
    const c = await db.evaluate((el) => {
      const s = getComputedStyle(el);
      const name = el.querySelector('[data-part="fold-name"]')!;
      const sum = el.querySelector('[data-part="fold-summary"]')!;
      const pane = getComputedStyle(el.closest('[data-testid="topology"]')!);
      return { bg: s.backgroundColor, border: s.borderTopColor, name: getComputedStyle(name).color, sum: getComputedStyle(sum).color, pane: pane.backgroundColor };
    });
    expect(lum(rgbOf(c.bg)), '어두운 바탕').toBeLessThan(0.05);
    expect(c.bg, '접힌 노드 바탕 ≠ 그래프 칸 바탕').not.toBe(c.pane);
    expect(contrast(c.name, c.bg), '이름 대비').toBeGreaterThanOrEqual(4.5);
    expect(contrast(c.sum, c.bg), '요약 대비').toBeGreaterThanOrEqual(4.5);
  });

  test.describe('390 — 좁은 화면', () => {
    test.use({ viewport: { width: 390, height: 844 } });
    test('⑦ 배율 하한을 지키고 왼쪽(컨테이너 열)부터 보임', async ({ page, backend }) => {
      seedNormal(backend);
      await page.goto('/topology');
      await expect(node(page, 'c:pkg-reqeusts')).toBeVisible();
      const s = await settledScale(page);
      expect(s, `390 맞춤 배율 ${s}`).toBeGreaterThanOrEqual(READABLE);
      expect(await inPane(page, 'c:pkg-reqeusts')).toBe(true);
      await expect(node(page, 'c:db-main')).toHaveAttribute('data-fold', 'folded');
      await page.screenshot({ path: `${SHOT_DIR}/390-folded.png` });
    });
  });

  test('⑧ 스크린샷 1440×900 — 밝은 · 어두운, 접힘 · 펼침', async ({ page, backend }) => {
    seedNormal(backend);
    for (const theme of ['light', 'dark'] as const) {
      await page.addInitScript((t) => localStorage.setItem('supplyguard.theme', t), theme);
      await page.goto('/topology');
      await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
      await expect(node(page, 'c:db-main')).toHaveAttribute('data-fold', 'folded');
      await settledScale(page);
      await page.screenshot({ path: `${SHOT_DIR}/${theme}-folded.png` });
      await node(page, 'c:db-main').click();
      await expect(nodesOf(page, 'p:db-main:')).toHaveCount(3);
      await settledScale(page);
      await page.screenshot({ path: `${SHOT_DIR}/${theme}-open.png` });
    }
  });
});
