import { readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';

// 11/09 P2 — 공통 부품(다음 차례 정책 · 다른 목록 화면이 그대로 가져다 쓴다). 무대 e2e/table-kit-harness.tsx 위에서 본다.
//   ① 표 도구줄(총 N건 · 새로고침 · 칸 고르기 · CSV)  ② 칸 고르기 · 저장 · 칸 기본으로  ③ 저장 실패 · 깨진 저장본
//   ④ 칸 폭 끌기 · 키보드  ⑤ 칸 순서 끌기 · Alt+←/→  ⑥ 정렬 꺾쇠 · 쪽 넘김  ⑦ 필터 Select  ⑧ 검색칸 · 조건 지우기
//   ⑨ 주소 쿼리 목록 상태  ⑩ 시트 부제 · 배지 · 탭 · 초점 가둠  ⑪ 큰 2단 창  ⑫ 미저장 경고
// 무대 뒤 화면은 주소 쿼리를 읽지 않는 「연동」(/integration).

type Stage = { unmount: () => void };
const BASE = '/integration';
async function stage(page: Page, kind: 'list' | 'modal', props: Record<string, unknown> = {}) {
  await page.evaluate(
    async ([k, p]) => {
      const w = window as unknown as { __tk?: { mount: (k: string, p: unknown) => Promise<Stage> }; __tkst?: Stage };
      const harness = '/e2e/table-kit-harness.tsx'; // 브라우저(Vite 개발 서버)에서 불러온다
      if (!w.__tk) await import(/* @vite-ignore */ harness);
      w.__tkst?.unmount();
      w.__tkst = await w.__tk!.mount(k as string, p);
    },
    [kind, props] as const,
  );
}
async function openList(page: Page, query = '') {
  await page.goto(`${BASE}${query}`);
  await expect(page.locator('main')).toBeVisible();
  await stage(page, 'list');
  await expect(page.locator('[data-tk-stage="list"] table[data-table="demo"]')).toBeVisible();
}
const T = 'table[data-table="demo"]';
const heads = (page: Page) => page.locator(`${T} thead th`).evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.col));
const thW = (page: Page, col: string) => page.locator(`${T} th[data-col="${col}"]`).evaluate((e) => e.getBoundingClientRect().width);
const q = (page: Page) => Object.fromEntries(new URL(page.url()).searchParams);
const KEY = 'supplyguard.grid.tk-demo.v1';
const saved = (page: Page) => page.evaluate((k) => localStorage.getItem(k), KEY);
const total = (page: Page) => page.locator('[data-table-tools="demo"] [data-part="total"]');
const DEFAULT_HEADS = ['pick', 'name', 'kind', 'action', 'owner', 'hits', 'act'];

test.describe('① 표 도구줄', () => {
  test('「총 N건」 · 새로고침 · 칸 고르기 · CSV 아이콘 단추 — CSV 는 보이는 이름 있는 칸 · 조건 전체 · BOM', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const bar = page.locator('[data-table-tools="demo"]');
    await expect(total(page)).toHaveText('총 45건');
    for (const [act, name] of [
      ['table-refresh', '새로고침'],
      ['table-columns', '칸 고르기'],
      ['table-export', 'CSV 내려받기'],
    ]) {
      const b = bar.locator(`[data-action="${act}"]`);
      await expect(b).toHaveAttribute('aria-label', name);
      await expect(b.locator('svg')).toHaveCount(1);
    }
    await bar.locator('[data-action="table-refresh"]').click();
    await expect(page.locator('[data-tk-refreshes]')).toHaveAttribute('data-tk-refreshes', '1');

    const [dl] = await Promise.all([page.waitForEvent('download'), bar.locator('[data-action="table-export"]').click()]);
    expect(dl.suggestedFilename()).toBe('tk-demo.csv');
    const text = readFileSync((await dl.path())!, 'utf8');
    expect(text.charCodeAt(0)).toBe(0xfeff);
    const lines = text.slice(1).trim().split('\n');
    expect(lines[0], '숨긴 칸 · 이름 없는 칸은 빠진다').toBe('정책,종류,판정,담당,위반');
    expect(lines, '지금 쪽(20)이 아니라 조건 전체(45)').toHaveLength(46);
    expect(lines[1]).toBe('policy-01,exec,allow,owner-a,0');
  });
});

test.describe('② 칸 고르기', () => {
  test('이름 있는 칸만 · 기본 숨김 · 마지막 하나는 못 끔 · localStorage 저장 · 다시 열어도 그대로 · 「칸 기본으로」', async ({ page, backend }) => {
    void backend;
    await openList(page);
    expect(await heads(page)).toEqual(DEFAULT_HEADS);
    const btn = page.locator('[data-action="table-columns"]');
    await expect(btn).toHaveAttribute('aria-expanded', 'false');
    await btn.click();
    await expect(btn).toHaveAttribute('aria-expanded', 'true');
    const pop = page.locator('[data-part="column-picker"]');
    await expect(pop).toBeVisible();
    await expect(pop).toHaveAttribute('role', 'dialog');
    const items = pop.locator('label[data-col]');
    expect(await items.allInnerTexts(), '이름 없는 칸(체크 · 행 동작)은 목록에 없다').toEqual(['정책', '종류', '판정', '담당', '위반', '메모']);
    const box = (name: string) => pop.getByRole('checkbox', { name });
    await expect(box('메모')).not.toBeChecked();
    await box('메모').check();
    expect(await heads(page)).toEqual([...DEFAULT_HEADS.slice(0, 6), 'note', 'act']);
    expect(JSON.parse((await saved(page))!).vis.note).toBe(true);
    for (const n of ['정책', '종류', '판정', '담당', '위반']) await box(n).uncheck();
    await expect(box('메모'), '마지막 하나').toBeDisabled();
    await expect(box('메모')).toBeChecked();
    expect(await heads(page)).toEqual(['pick', 'note', 'act']);
    // Esc 로 닫히고 초점은 단추로
    await page.keyboard.press('Escape');
    await expect(pop).toHaveCount(0);
    await expect(btn).toBeFocused();

    await page.reload();
    await stage(page, 'list');
    expect(await heads(page), '저장본을 다시 읽는다').toEqual(['pick', 'note', 'act']);
    await btn.click();
    await pop.locator('[data-action="columns-reset"]').click();
    expect(await heads(page)).toEqual(DEFAULT_HEADS);
    expect(await saved(page), '기본으로 돌리면 저장본을 지운다').toBeNull();
    // 바깥을 누르면 닫힌다
    await page.mouse.click(700, 600);
    await expect(pop).toHaveCount(0);
  });
});

test.describe('③ 저장 실패 · 깨진 저장본', () => {
  test('깨진 JSON · 모르는 칸 · 모양이 다른 값은 버리고 기본 칸으로', async ({ page, backend }) => {
    void backend;
    await page.addInitScript((k) => {
      if (!sessionStorage.getItem('tk-seeded')) {
        sessionStorage.setItem('tk-seeded', '1');
        localStorage.setItem(k, '{bad');
      }
    }, KEY);
    await openList(page);
    expect(await heads(page)).toEqual(DEFAULT_HEADS);
    await page.evaluate((k) => localStorage.setItem(k, JSON.stringify({ vis: { ghost: true, kind: 'no' }, w: { kind: 'wide' }, order: ['ghost', 3] })), KEY);
    await stage(page, 'list');
    expect(await heads(page)).toEqual(DEFAULT_HEADS);
  });

  test('localStorage 가 막혀도(읽기 · 쓰기 예외) 기본 칸으로 그리고, 이번 화면에서는 고른 대로', async ({ page, backend }) => {
    void backend;
    await page.addInitScript(() => {
      const P = Storage.prototype;
      for (const m of ['getItem', 'setItem', 'removeItem'] as const) {
        const orig = P[m] as (...a: unknown[]) => unknown;
        (P as unknown as Record<string, unknown>)[m] = function (this: Storage, ...a: unknown[]) {
          if (String(a[0]).startsWith('supplyguard.grid.')) throw new Error('blocked');
          return orig.apply(this, a);
        };
      }
    });
    await openList(page);
    expect(await heads(page)).toEqual(DEFAULT_HEADS);
    await page.locator('[data-action="table-columns"]').click();
    await page.locator('[data-part="column-picker"]').getByRole('checkbox', { name: '메모' }).check();
    expect(await heads(page)).toContain('note');
  });
});

test.describe('④ 칸 폭', () => {
  test('머리 경계 끌기 · 최소 48 · 칸별 최대 · ←/→ · Alt+←/→ ±16 · 두 번 누르면 기본 · 저장', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const h = page.locator(`${T} th[data-col="kind"] [data-part="col-resize"]`);
    await expect(h).toHaveAttribute('role', 'separator');
    await expect(h).toHaveAttribute('aria-orientation', 'vertical');
    await expect(page.locator(`${T} th[data-col="pick"] [data-part="col-resize"]`), '이름 없는 칸은 폭 고정').toHaveCount(0);
    const drag = async (col: string, dx: number) => {
      const b = (await page.locator(`${T} th[data-col="${col}"] [data-part="col-resize"]`).boundingBox())!;
      await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2);
      await page.mouse.down();
      await page.mouse.move(b.x + b.width / 2 + dx / 2, b.y + b.height / 2, { steps: 3 });
      await page.mouse.move(b.x + b.width / 2 + dx, b.y + b.height / 2, { steps: 3 });
      await page.mouse.up();
    };
    const w0 = await thW(page, 'kind');
    await drag('kind', 60);
    expect(Math.abs((await thW(page, 'kind')) - (w0 + 60))).toBeLessThanOrEqual(2);
    expect(JSON.parse((await saved(page))!).w.kind).toBeGreaterThan(w0);
    await expect(page.locator(`${T} th[data-col="name"] .th-sort`), '폭 끌기는 정렬을 바꾸지 않는다').toBeVisible();
    expect(await page.locator(`${T} th[data-col="kind"]`).getAttribute('aria-sort')).toBe('none');
    await drag('kind', -1000);
    expect(Math.round(await thW(page, 'kind'))).toBe(48);
    await drag('owner', 1000);
    expect(Math.round(await thW(page, 'owner')), '칸별 최대(240)').toBe(240);
    await h.focus();
    await page.keyboard.press('ArrowRight');
    expect(Math.round(await thW(page, 'kind'))).toBe(64);
    await page.keyboard.press('Alt+ArrowRight');
    expect(Math.round(await thW(page, 'kind'))).toBe(80);
    await page.keyboard.press('Alt+ArrowLeft');
    expect(Math.round(await thW(page, 'kind'))).toBe(64);
    await expect(h).toHaveAttribute('aria-valuenow', '64');
    await h.dblclick();
    expect(Math.abs((await thW(page, 'kind')) - w0)).toBeLessThanOrEqual(2);
    expect(JSON.parse((await saved(page))!).w.kind).toBeUndefined();
    // 좁힌 칸의 글은 잘리고 말줄임
    await drag('owner', -1000);
    const cell = await page.locator(`${T} tbody tr`).first().locator('td[data-col="owner"]').evaluate((e) => ({ w: e.getBoundingClientRect().width, of: getComputedStyle(e).textOverflow }));
    expect(Math.round(cell.w)).toBe(48);
    expect(cell.of).toBe('ellipsis');
  });
});

test.describe('⑤ 칸 순서', () => {
  test('머리 끌어 옮기기(정렬 안 바뀜) · Alt+←/→ · 고정 칸 제자리 · 저장 · 칸 기본으로', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const center = async (col: string, fx = 0.5) => {
      const b = (await page.locator(`${T} th[data-col="${col}"]`).boundingBox())!;
      return { x: b.x + b.width * fx, y: b.y + b.height / 2 };
    };
    const a = await center('kind', 0.3);
    const to = await center('owner', 0.8);
    await page.mouse.move(a.x, a.y);
    await page.mouse.down();
    await page.mouse.move(a.x + 20, a.y, { steps: 3 });
    await page.mouse.move(to.x, to.y, { steps: 6 });
    await expect(page.locator(`${T} th[data-drop]`)).toHaveCount(1);
    await page.mouse.up();
    expect(await heads(page)).toEqual(['pick', 'name', 'action', 'owner', 'kind', 'hits', 'act']);
    expect(await page.locator(`${T} th[data-col="kind"]`).getAttribute('aria-sort'), '끌기는 정렬이 아니다').toBe('none');
    expect(await page.locator(`${T} th[data-col="name"]`).getAttribute('aria-sort')).toBe('ascending');
    // 키보드: 머리 단추에서 Alt+→ 한 칸, 초점 유지
    const nameBtn = page.locator(`${T} th[data-col="name"] .th-sort`);
    await nameBtn.focus();
    await page.keyboard.press('Alt+ArrowRight');
    expect(await heads(page)).toEqual(['pick', 'action', 'name', 'owner', 'kind', 'hits', 'act']);
    await expect(nameBtn).toBeFocused();
    await page.keyboard.press('Alt+ArrowLeft');
    await page.keyboard.press('Alt+ArrowLeft');
    expect(await heads(page), '맨 앞 이름 칸 앞으로는 못 감(체크 칸 제자리)').toEqual(['pick', 'name', 'action', 'owner', 'kind', 'hits', 'act']);
    expect(JSON.parse((await saved(page))!).order).toEqual(['name', 'action', 'owner', 'kind', 'hits', 'note']);
    await page.reload();
    await stage(page, 'list');
    expect(await heads(page)).toEqual(['pick', 'name', 'action', 'owner', 'kind', 'hits', 'act']);
    await page.locator('[data-action="table-columns"]').click();
    await page.locator('[data-action="columns-reset"]').click();
    expect(await heads(page)).toEqual(DEFAULT_HEADS);
  });
});

test.describe('⑥ 정렬 표시 · 쪽 넘김', () => {
  test('늘 보이는 꺾쇠(글자 화살표 없음) · 정렬 중인 칸만 강조 · 처음/끝 단추 · 11/05 문구', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const ico = (col: string) => page.locator(`${T} th[data-col="${col}"] [data-part="sort-ico"]`);
    for (const c of ['name', 'kind', 'action', 'owner', 'hits']) await expect(ico(c).locator('svg')).toHaveCount(1);
    await expect(page.locator(`${T} th[data-col="note"]`)).toHaveCount(0);
    const look = (col: string) =>
      page.locator(`${T} th[data-col="${col}"] .th-sort`).evaluate((b) => {
        const i = b.querySelector('[data-part="sort-ico"]')!;
        return { after: getComputedStyle(b, '::after').content, op: Number(getComputedStyle(i).opacity), color: getComputedStyle(i).color, dir: i.getAttribute('data-dir') };
      });
    const accent = await page.evaluate(() => {
      const e = document.createElement('i');
      e.style.color = 'var(--accent)';
      document.body.append(e);
      const c = getComputedStyle(e).color;
      e.remove();
      return c;
    });
    const off = await look('kind');
    expect(['none', 'normal']).toContain(off.after);
    expect(off.op).toBeGreaterThan(0.3);
    expect(off.op).toBeLessThan(1);
    expect(off.dir).toBe('none');
    const on = await look('name');
    expect(on).toMatchObject({ op: 1, color: accent, dir: 'asc' });
    await page.locator(`${T} th[data-col="hits"] .th-sort`).click();
    await page.locator(`${T} th[data-col="hits"] .th-sort`).click();
    expect(await look('hits')).toMatchObject({ dir: 'desc', color: accent });
    expect((await look('name')).dir).toBe('none');
    expect(q(page).sort).toBe('hits,desc');
    const foot = page.locator('[data-table-foot="demo"]');
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 1/3 페이지');
    await expect(foot.locator('[data-page="first"]')).toBeDisabled();
    await foot.locator('[data-page="last"]').click();
    await expect(foot.locator('[data-part="range"]')).toHaveText('총 45건 · 3/3 페이지');
    await expect(foot.locator('[data-page="last"]')).toBeDisabled();
  });
});

test.describe('⑦ 필터 Select', () => {
  test('「○○ 전체」 첫 선택지 · 고른 항목 강조 + ✓ · ↑↓ Enter Esc · aria · 10개 넘으면 검색칸', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const trig = page.locator('[data-tk-stage] [data-filter="kind"]');
    await expect(trig).toHaveAttribute('role', 'combobox');
    await expect(trig).toHaveAttribute('aria-haspopup', 'listbox');
    await expect(trig).toHaveAttribute('aria-expanded', 'false');
    await expect(trig).toHaveText('종류 전체');
    await trig.click();
    const lb = page.getByRole('listbox', { name: '종류' });
    await expect(lb).toBeVisible();
    await expect(trig).toHaveAttribute('aria-expanded', 'true');
    expect(await trig.getAttribute('aria-controls')).toBe(await lb.getAttribute('id'));
    const opts = lb.getByRole('option');
    await expect(opts).toHaveCount(6);
    await expect(opts.first()).toHaveText('종류 전체');
    await expect(opts.first()).toHaveAttribute('aria-selected', 'true');
    await expect(opts.first().locator('svg'), '고른 항목 ✓').toHaveCount(1);
    await expect(page.locator('[data-tk-stage] input[type="search"], [data-overlay] input')).toHaveCount(0);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('ArrowDown');
    const activeId = await page.evaluate(() => document.activeElement?.getAttribute('aria-activedescendant'));
    expect(activeId).toBe(await opts.nth(2).getAttribute('id'));
    await page.keyboard.press('Enter');
    await expect(lb).toHaveCount(0);
    await expect(trig).toBeFocused();
    await expect(trig).toHaveText('open');
    expect(q(page).kind).toBe('open');
    await expect(total(page)).toHaveText('총 9건');
    // 다시 열면 고른 항목이 강조(주 색 글자 + ✓)
    await page.keyboard.press('ArrowDown');
    await expect(lb).toBeVisible();
    const sel = lb.locator('[role="option"][aria-selected="true"]');
    await expect(sel).toHaveText('open');
    await expect(sel.locator('svg')).toHaveCount(1);
    await expect(lb.locator('[role="option"][aria-selected="false"] svg')).toHaveCount(0);
    const w = await sel.evaluate((e) => Number(getComputedStyle(e).fontWeight));
    expect(w).toBeGreaterThanOrEqual(600);
    // Esc: 닫고 그대로
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Escape');
    await expect(lb).toHaveCount(0);
    await expect(trig).toBeFocused();
    await expect(trig).toHaveText('open');
    // 12개(+전체) → 맨 위 검색칸, 입력이 그쪽으로
    const owner = page.locator('[data-tk-stage] [data-filter="owner"]');
    await owner.click();
    const olb = page.getByRole('listbox', { name: '담당' });
    const search = page.getByRole('searchbox', { name: '담당 항목 검색' });
    await expect(search).toBeFocused();
    await page.keyboard.type('owner-k');
    await expect(olb.getByRole('option')).toHaveCount(1);
    await page.keyboard.press('Enter');
    await expect(owner).toHaveText('owner-k');
    await owner.click();
    await page.keyboard.type('zzz');
    await expect(olb.getByRole('option')).toHaveCount(0);
    await expect(olb.locator('..')).toContainText('일치 항목 없음');
    await page.mouse.click(700, 700);
    await expect(olb).toHaveCount(0);
  });
});

test.describe('⑧ 검색칸', () => {
  test('Enter · 칸 벗어날 때 적용 · Esc 되돌림 · 「조건 지우기」', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const box = page.getByRole('searchbox', { name: '정책 검색' });
    await expect(page.locator('[data-action="clear-conditions"]')).toHaveCount(0);
    await box.fill('policy-1');
    await expect(total(page), '쓰는 중에는 적용 안 함').toHaveText('총 45건');
    expect(q(page).q).toBeUndefined();
    await box.press('Enter');
    await expect(total(page)).toHaveText('총 10건');
    expect(q(page).q).toBe('policy-1');
    await box.pressSequentially('9x');
    await box.press('Escape');
    await expect(box).toHaveValue('policy-1');
    await expect(total(page)).toHaveText('총 10건');
    await box.fill('policy-2');
    await page.locator('[data-table-tools="demo"]').click();
    await expect(total(page), '칸을 벗어나면 적용').toHaveText('총 10건');
    expect(q(page).q).toBe('policy-2');
    await page.locator('[data-tk-stage] [data-filter="action"]').click();
    await page.getByRole('listbox', { name: '판정' }).getByRole('option', { name: 'kill' }).click();
    const clear = page.locator('[data-action="clear-conditions"]');
    await expect(clear).toHaveText('조건 지우기');
    await clear.click();
    await expect(box).toHaveValue('');
    await expect(total(page)).toHaveText('총 45건');
    expect(q(page)).toEqual({});
    await expect(clear).toHaveCount(0);
  });
});

test.describe('⑨ 주소 쿼리 목록 상태', () => {
  test('필터 · 쪽 · 정렬 · 상세 · 탭이 주소에 — 기본값은 지우고, 필터 · 정렬이 바뀌면 첫 쪽, 기록은 늘지 않음', async ({ page, backend }) => {
    void backend;
    await openList(page, '?sort=hits,desc&page=2');
    expect(await page.locator(`${T} th[data-col="hits"]`).getAttribute('aria-sort')).toBe('descending');
    const range = page.locator('[data-table-foot="demo"] [data-part="range"]');
    await expect(range).toHaveText('총 45건 · 2/3 페이지');
    const len0 = await page.evaluate(() => history.length);
    await page.locator('[data-table-foot="demo"] [data-page="3"]').click();
    expect(q(page)).toEqual({ sort: 'hits,desc', page: '3' });
    await page.locator('[data-table-foot="demo"] [data-part="page-size"]').selectOption('50');
    expect(q(page), '쪽 크기를 바꾸면 첫 쪽').toEqual({ sort: 'hits,desc', size: '50' });
    await page.locator('[data-table-foot="demo"] [data-part="page-size"]').selectOption('20');
    await page.locator('[data-table-foot="demo"] [data-page="2"]').click();
    await page.locator('[data-tk-stage] [data-filter="kind"]').click();
    await page.getByRole('listbox', { name: '종류' }).getByRole('option', { name: 'dns' }).click();
    expect(q(page), '필터가 바뀌면 첫 쪽').toEqual({ sort: 'hits,desc', kind: 'dns' });
    await page.locator(`${T} th[data-col="name"] .th-sort`).click();
    expect(q(page), '기본 정렬(정책 오름)은 주소에서 지움').toEqual({ kind: 'dns' });
    await page.locator(`${T} tbody tr`).first().click();
    const id = q(page).id;
    expect(id).toMatch(/^r\d\d$/);
    expect(q(page).tab, '첫 탭은 주소에 없음').toBeUndefined();
    await page.locator('[data-sheet="demo"] [role="tab"][data-tab="changes"]').click();
    expect(q(page)).toEqual({ kind: 'dns', id, tab: 'changes' });
    await page.reload();
    await stage(page, 'list');
    await expect(page.locator('[data-sheet="demo"] [role="tab"][data-tab="changes"]')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('[data-tk-stage] [data-filter="kind"]')).toHaveText('dns');
    await page.locator('[data-sheet="demo"] [role="tab"][data-tab="detail"]').click();
    expect(q(page)).toEqual({ kind: 'dns', id });
    await page.keyboard.press('Escape');
    await expect(page.locator('[data-sheet="demo"]')).toHaveCount(0);
    expect(q(page)).toEqual({ kind: 'dns' });
    expect(await page.evaluate(() => history.length), '바꿀 때마다 기록을 늘리지 않음(replace)').toBe(len0);
  });

  test('틀린 값(정렬 칸 · 쪽 · 쪽 크기 · 필터 · 탭)은 기본값으로 읽고 주소에서 지운다', async ({ page, backend }) => {
    void backend;
    await openList(page, '?sort=bogus%3Bdrop,up&page=-3&size=7&kind=nope&tab=zzz&id=r02&other=keep');
    expect(await page.locator(`${T} th[data-col="name"]`).getAttribute('aria-sort')).toBe('ascending');
    await expect(page.locator('[data-table-foot="demo"] [data-part="range"]')).toHaveText('총 45건 · 1/3 페이지');
    await expect(page.locator('[data-tk-stage] [data-filter="kind"]')).toHaveText('종류 전체');
    await expect(page.locator('[data-sheet="demo"] [role="tab"][data-tab="detail"]')).toHaveAttribute('aria-selected', 'true');
    await expect.poll(() => q(page), '목록과 상관없는 키는 그대로').toEqual({ id: 'r02', other: 'keep' });
  });
});

test.describe('⑩ 시트 확장', () => {
  test('부제 · 배지 · 탭(←→) · aria-modal · 열면 고른 탭에 초점 · Tab 은 시트 안에서만 · 닫으면 연 행으로 · n / m ‹ › · ↑↓ 그대로', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const row = page.locator(`${T} tbody tr[data-row="r01"]`);
    await row.click();
    const sh = page.locator('[data-sheet="demo"]');
    await expect(sh).toBeVisible();
    await expect(sh).toHaveAttribute('role', 'dialog');
    await expect(sh).toHaveAttribute('aria-modal', 'true');
    await expect(sh.locator('[data-part="sheet-subtitle"]')).toHaveText('r01');
    await expect(sh.locator('[data-part="sheet-badges"] .sg-pill')).toHaveText('allow');
    const tabs = sh.getByRole('tablist').getByRole('tab');
    await expect(tabs).toHaveCount(3);
    await expect(tabs.nth(1)).toContainText('차단 이력');
    await expect(tabs.nth(1).locator('[data-part="tab-count"]')).toHaveText('3');
    await expect(tabs.first()).toHaveAttribute('aria-selected', 'true');
    await expect(tabs.first()).toBeFocused();
    const panel = sh.getByRole('tabpanel');
    expect(await panel.getAttribute('aria-labelledby')).toBe(await tabs.first().getAttribute('id'));
    await page.keyboard.press('ArrowRight');
    await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
    await expect(tabs.nth(1)).toBeFocused();
    expect(q(page).tab).toBe('blocks');
    await page.keyboard.press('End');
    await expect(tabs.nth(2)).toBeFocused();
    expect(q(page).tab).toBe('changes');
    await page.keyboard.press('Home');
    expect(q(page).tab).toBeUndefined();
    // 초점 가둠: Tab 을 여러 번 눌러도 시트 밖으로 나가지 않는다
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press('Tab');
      expect(await sh.evaluate((s) => s.contains(document.activeElement))).toBe(true);
    }
    await sh.getByTestId('inside-1').focus();
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press('Shift+Tab');
      expect(await sh.evaluate((s) => s.contains(document.activeElement))).toBe(true);
    }
    // 앞뒤 넘김(11/05) 그대로
    await expect(sh.locator('[data-part="sheet-pos"]')).toHaveText('1 / 20');
    await sh.getByTestId('inside-1').focus();
    await page.keyboard.press('ArrowDown');
    await expect(sh.locator('[data-part="sheet-subtitle"]')).toHaveText('r02');
    await page.keyboard.press('Escape');
    await expect(page.locator('.sg-sheet-layer')).toHaveCount(0);
    await expect(row, '닫으면 연 자리로 초점').toBeFocused();
  });

  test('선택 props 없이 쓰는 기존 시트(감사 로그)는 머리 52 · 탭 줄 없음 그대로, aria-modal 만 더해짐', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    await page.locator('tr[data-audit]').first().click();
    const sh = page.locator('[data-sheet="audit"]');
    await expect(sh).toBeVisible();
    await expect(sh).toHaveAttribute('aria-modal', 'true');
    expect(Math.round(await sh.locator('.sg-sheet-head').evaluate((e) => e.getBoundingClientRect().height))).toBe(52);
    await expect(sh.locator('[data-part="sheet-subtitle"]')).toHaveCount(0);
  });
});

test.describe('⑪ 큰 2단 창', () => {
  test('폭 min(1180, 100vw−40) · 오른쪽 clamp(340, 36%, 460) · 두 칸 따로 스크롤 · 바닥 버튼 줄 · 바깥 클릭으로 안 닫힘 · 768 미만 1단', async ({ page, backend }) => {
    void backend;
    await page.goto(BASE);
    await stage(page, 'modal');
    const d = page.locator('dialog[data-part="tk-form"]');
    await expect(d).toBeVisible();
    await expect(d).toHaveAttribute('data-size', 'xl');
    const m = async () =>
      d.evaluate((el) => {
        const r = (s: string) => el.querySelector(s)!.getBoundingClientRect();
        const main = el.querySelector<HTMLElement>('[data-part="modal-main"]')!;
        const side = el.querySelector<HTMLElement>('[data-part="modal-side"]')!;
        const body = el.querySelector<HTMLElement>('[data-part="modal-body"]')!;
        return {
          w: el.getBoundingClientRect().width,
          bodyW: body.clientWidth,
          side: r('[data-part="modal-side"]'),
          main: r('[data-part="modal-main"]'),
          mainScroll: getComputedStyle(main).overflowY,
          sideScroll: getComputedStyle(side).overflowY,
          mainOver: main.scrollHeight > main.clientHeight,
          sideOver: side.scrollHeight > side.clientHeight,
          foot: getComputedStyle(el.querySelector('[data-part="modal-foot"]')!).borderTopWidth,
          h: el.getBoundingClientRect().height,
        };
      });
    let x = await m();
    expect(Math.round(x.w)).toBe(1180);
    const want = (bw: number) => Math.min(460, Math.max(340, bw * 0.36));
    expect(Math.abs(x.side.width - want(x.bodyW))).toBeLessThanOrEqual(1.5);
    expect(x.mainScroll).toBe('auto');
    expect(x.sideScroll).toBe('auto');
    expect(x.mainOver && x.sideOver, '두 칸 모두 넘쳐서 각자 스크롤').toBe(true);
    expect(x.foot).toBe('1px');
    expect(x.h).toBeLessThanOrEqual(900 - 40 + 1);
    await d.locator('[data-part="modal-main"]').evaluate((e) => (e.scrollTop = 300));
    expect(await d.locator('[data-part="modal-side"]').evaluate((e) => e.scrollTop), '왼쪽만 스크롤').toBe(0);
    await page.mouse.click(10, 10);
    await expect(d, '바깥 클릭으로 닫히지 않음').toBeVisible();
    await page.setViewportSize({ width: 1000, height: 800 });
    x = await m();
    expect(Math.round(x.w)).toBe(960);
    expect(Math.abs(x.side.width - want(x.bodyW))).toBeLessThanOrEqual(1.5);
    await page.setViewportSize({ width: 390, height: 800 });
    x = await m();
    expect(x.side.top, '좁으면 오른쪽 칸이 아래로').toBeGreaterThanOrEqual(x.main.bottom - 1);
    expect(Math.abs(x.side.width - x.main.width)).toBeLessThanOrEqual(1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBe(0);
  });
});

test.describe('⑫ 미저장 경고', () => {
  test('값 스냅숏이 같으면 바로 닫힘 · 바꾸면 ✕ · Esc · 취소 때 「버리고 닫기 / 계속 편집」 확인 창', async ({ page, backend }) => {
    void backend;
    await page.goto(BASE);
    await stage(page, 'modal');
    const d = page.locator('dialog[data-part="tk-form"]');
    const ask = page.locator('dialog[data-part="unsaved"]');
    // 그대로면 바로 닫힘
    await d.getByRole('button', { name: '닫기' }).click();
    await expect(page.locator('[data-tk-closed="1"]')).toHaveCount(1);
    await stage(page, 'modal');
    const name = d.locator('input[name="name"]');
    await name.fill('policy-99');
    await d.getByRole('button', { name: '닫기' }).click();
    await expect(ask).toBeVisible();
    await expect(ask.getByRole('button')).toHaveText(['계속 편집', '버리고 닫기']);
    await expect(ask.getByRole('button', { name: '계속 편집' })).toBeFocused();
    await ask.getByRole('button', { name: '계속 편집' }).click();
    await expect(ask).toHaveCount(0);
    await expect(d).toBeVisible();
    await expect(name).toHaveValue('policy-99');
    // Esc → 묻기, 다시 Esc → 묻기만 닫힘
    await name.focus();
    await page.keyboard.press('Escape');
    await expect(ask).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(ask).toHaveCount(0);
    await expect(d).toBeVisible();
    // 바닥 「취소」도 같은 길
    await d.locator('[data-action="form-cancel"]').click();
    await expect(ask).toBeVisible();
    await ask.locator('[data-action="discard-close"]').click();
    await expect(page.locator('[data-tk-closed="1"]')).toHaveCount(1);
    // 되돌려 같아지면 묻지 않는다
    await stage(page, 'modal');
    await name.fill('policy-99');
    await name.fill('policy-01');
    await d.locator('[data-action="form-cancel"]').click();
    await expect(ask).toHaveCount(0);
    await expect(page.locator('[data-tk-closed="1"]')).toHaveCount(1);
  });
});
