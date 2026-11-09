import { readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';
import { actionTone } from '../src/lib/actionTone';
import * as copy from '../src/lib/screenCopy';
import { expect, test } from './fixtures';

// 11/09 P2 — 공통 부품(다음 차례 정책 · 다른 목록 화면이 그대로 가져다 쓴다). 무대 e2e/table-kit-harness.tsx 위에서 본다.
//   ① 표 도구줄(총 N건 · 새로고침 · 칸 고르기 · CSV)  ② 칸 고르기 · 저장 · 칸 기본으로  ③ 저장 실패 · 깨진 저장본
//   ④ 칸 폭 끌기 · 키보드  ⑤ 칸 순서 끌기 · Alt+←/→  ⑥ 정렬 꺾쇠 · 쪽 넘김  ⑦ 필터 Select  ⑧ 검색칸 · 조건 지우기
//   ⑨ 목록 상태(10/21 유지 — 필터 · 쪽 · 정렬은 화면 상태, 주소에는 id · tab · 링크용 키만)  ⑩ 시트 부제 · 배지 · 탭 · 초점 가둠  ⑪ 큰 2단 창  ⑫ 미저장 경고
// 2차(SPEC-1109 §2~4 — 참고 제품 답변 반영): ⑬ 시트 움직임  ⑭ 창 · 팝오버 움직임  ⑮ 행 상태  ⑯ 꺼진 단추 · 재조회 · 폭 손잡이 · 줄 끝 고정
//   ⑰ 칸 도우미(두 줄 · 「—」 · 시각 형식 · 칸 폭 표준 · CSV 화면 글)  ⑱ 화면 제목 700 · 로그인 반경(11/05 값)
// 3차(SPEC-1109 §7 화면 문구 — 공통 부품 몫): ⑲ 확인 창  ⑳ 화면 상태 기본 문구  ㉑ 아이콘 단추 이름 · 꺼진 사유  ㉒ 표 아래 안내 한 줄
//   ㉓ 동작 끝말 → 색(lib/actionTone.ts)  ㉔ 화면 설명 저장소(lib/screenCopy.ts)
// 무대 뒤 화면은 주소 쿼리를 읽지 않는 「연동」(/integration).

type Stage = { unmount: () => void };
const BASE = '/integration';
async function stage(page: Page, kind: 'list' | 'modal' | 'confirm' | 'states', props: Record<string, unknown> = {}) {
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
    expect(await items.allInnerTexts(), '이름 없는 칸(체크 · 행 동작)은 목록에 없다').toEqual(['정책', '종류', '판정', '담당', '위반', '메모', '시각']);
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
    // 기본 폭 = 내용 폭(정해 둔 폭 없음) — 다른 칸의 폭에 따라 남는 자리 나눔이 달라 px 로는 비교하지 않는다
    expect(await page.locator(`${T} th[data-col="kind"]`).evaluate((e) => (e as HTMLElement).style.width)).toBe('');
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
    expect(JSON.parse((await saved(page))!).order).toEqual(['name', 'action', 'owner', 'kind', 'hits', 'note', 'seen']);
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
    expect(q(page).sort, '정렬은 주소에 남지 않음(10/21)').toBeUndefined();
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
    expect(q(page).kind, '필터는 주소에 남지 않음(10/21)').toBeUndefined();
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
    expect(q(page).q, '검색어는 주소 · 방문 기록에 남지 않음(10/21)').toBeUndefined();
    await box.pressSequentially('9x');
    await box.press('Escape');
    await expect(box).toHaveValue('policy-1');
    await expect(total(page)).toHaveText('총 10건');
    await box.fill('policy-2');
    await page.locator('[data-table-tools="demo"]').click();
    await expect(total(page), '칸을 벗어나면 적용').toHaveText('총 10건');
    await expect(page.locator(`${T} tbody tr`).first()).toHaveAttribute('data-row', 'r20');
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

test.describe('⑨ 목록 상태(10/21 유지)', () => {
  test('필터 · 검색 · 쪽 · 정렬은 화면 상태(주소에 없음) · 주소에는 id · tab(첫 탭 생략)만 · 새로고침하면 필터 · 쪽 · 정렬은 기본값 · 기록은 늘지 않음', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const range = page.locator('[data-table-foot="demo"] [data-part="range"]');
    const len0 = await page.evaluate(() => history.length);
    await page.locator(`${T} th[data-col="hits"] .th-sort`).click();
    await page.locator(`${T} th[data-col="hits"] .th-sort`).click();
    await page.locator('[data-table-foot="demo"] [data-page="3"]').click();
    await expect(range).toHaveText('총 45건 · 3/3 페이지');
    expect(q(page), '정렬 · 쪽은 주소에 없음').toEqual({});
    await page.locator('[data-table-foot="demo"] [data-part="page-size"]').selectOption('50');
    await expect(range, '쪽 크기를 바꾸면 첫 쪽').toHaveText('총 45건 · 1/1 페이지');
    await page.locator('[data-table-foot="demo"] [data-part="page-size"]').selectOption('20');
    await page.locator('[data-table-foot="demo"] [data-page="2"]').click();
    await page.locator('[data-tk-stage] [data-filter="kind"]').click();
    await page.getByRole('listbox', { name: '종류' }).getByRole('option', { name: 'dns' }).click();
    await expect(range, '필터가 바뀌면 첫 쪽').toHaveText('총 9건 · 1/1 페이지');
    await page.getByRole('searchbox', { name: '정책 검색' }).fill('policy-0');
    await page.getByRole('searchbox', { name: '정책 검색' }).press('Enter');
    await expect(total(page)).toHaveText('총 2건');
    expect(q(page), '필터 · 검색어도 주소에 없음').toEqual({});
    await page.locator(`${T} tbody tr`).first().click();
    const id = q(page).id;
    expect(id).toMatch(/^r\d\d$/);
    expect(q(page), '열린 상세만 주소에 · 첫 탭은 주소에 없음').toEqual({ id });
    await page.locator('[data-sheet="demo"] [role="tab"][data-tab="changes"]').click();
    expect(q(page)).toEqual({ id, tab: 'changes' });
    await page.reload();
    await stage(page, 'list');
    await expect(page.locator('[data-sheet="demo"] [role="tab"][data-tab="changes"]'), 'id · tab 은 새로고침에도 남음').toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('[data-tk-stage] [data-filter="kind"]'), '새로고침하면 필터는 기본값').toHaveText('종류 전체');
    await expect(page.getByRole('searchbox', { name: '정책 검색' })).toHaveValue('');
    await expect(total(page)).toHaveText('총 45건');
    expect(await page.locator(`${T} th[data-col="name"]`).getAttribute('aria-sort'), '정렬도 기본값').toBe('ascending');
    await expect(range).toHaveText('총 45건 · 1/3 페이지');
    await page.locator('[data-sheet="demo"] [role="tab"][data-tab="detail"]').click();
    expect(q(page)).toEqual({ id });
    await page.keyboard.press('Escape');
    await expect(page.locator('[data-sheet="demo"]')).toHaveCount(0);
    expect(q(page)).toEqual({});
    expect(await page.evaluate(() => history.length), '바꿀 때마다 기록을 늘리지 않음(replace)').toBe(len0);
  });

  test('옛 주소의 필터 · 쪽 · 정렬은 한 번 적용한 뒤 주소에서 지운다 — id · tab · 목록과 상관없는 키는 남김, 다시 열면 기본값', async ({ page, backend }) => {
    void backend;
    await openList(page, '?kind=dns&sort=hits,desc&page=1&id=r04&tab=changes&other=keep');
    await expect(total(page), '옛 주소 필터 적용').toHaveText('총 9건');
    expect(await page.locator(`${T} th[data-col="hits"]`).getAttribute('aria-sort')).toBe('descending');
    await expect(page.locator('[data-tk-stage] [data-filter="kind"]')).toHaveText('dns');
    await expect(page.locator('[data-sheet="demo"] [role="tab"][data-tab="changes"]')).toHaveAttribute('aria-selected', 'true');
    await expect.poll(() => q(page), '필터 · 정렬 · 쪽 키만 지움').toEqual({ id: 'r04', tab: 'changes', other: 'keep' });
    await page.reload();
    await stage(page, 'list');
    await expect(total(page), '한 번만 — 새로고침하면 기본값').toHaveText('총 45건');
    await expect(page.locator('[data-sheet="demo"] [role="tab"][data-tab="changes"]')).toHaveAttribute('aria-selected', 'true');
    // 옛 주소의 쪽도 한 번 적용
    await openList(page, '?page=2');
    await expect(page.locator('[data-table-foot="demo"] [data-part="range"]')).toHaveText('총 45건 · 2/3 페이지');
    await expect.poll(() => q(page)).toEqual({});
  });

  test('다른 화면 링크의 state.filters 가 옛 주소 필터보다 먼저 · 적용 뒤 state 를 비운다', async ({ page, backend }) => {
    void backend;
    await page.goto(`${BASE}?kind=dns`);
    await expect(page.locator('main')).toBeVisible();
    await page.evaluate(() => history.replaceState({ usr: { filters: { kind: 'exec', q: 'policy-1' } }, key: 'tk-link', idx: 0 }, '', `${location.pathname}?kind=dns&id=r11`));
    await stage(page, 'list');
    await expect(page.locator('[data-tk-stage] [data-filter="kind"]')).toHaveText('exec');
    await expect(page.getByRole('searchbox', { name: '정책 검색' })).toHaveValue('policy-1');
    await expect(total(page)).toHaveText('총 2건');
    await expect.poll(() => q(page)).toEqual({ id: 'r11' });
    expect(await page.evaluate(() => (history.state as { usr?: unknown } | null)?.usr ?? null), 'state 비움').toBeNull();
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

// ── 11/09 2차: SPEC-1109 §2 움직임 · §3 상태별 모양 · §4 표 ──
const cssVar = (page: Page, name: string, prop: 'color' | 'backgroundColor' | 'fontFamily' = 'color') =>
  page.evaluate(
    ([n, p]) => {
      const e = document.createElement('i');
      e.style.setProperty(p === 'color' ? 'color' : p === 'fontFamily' ? 'font-family' : 'background-color', `var(${n})`);
      document.body.append(e);
      const v = getComputedStyle(e)[p];
      e.remove();
      return v;
    },
    [name, prop] as const,
  );
// 시트 층의 열림 효과가 끝날 때까지(무대 뒤 「연동」 화면은 흐름 그림이 계속 움직여 문서 전체로는 재지 않는다)
const settle = (page: Page) =>
  page.waitForFunction(() => {
    const l = document.querySelector('.sg-sheet-layer');
    return !!l && l.getAnimations({ subtree: true }).every((a) => a.playState !== 'running');
  });

test.describe('⑬ 시트 움직임', () => {
  test('열림만 효과(뒤 어둡게 120ms · 밀려 들어옴 180ms 들어옴 곡선) · 열린 채 다른 줄 = 같은 시트에 내용만 교체(받는 동안 시트 안 스켈레톤) · 닫힘은 효과 없이 바로', async ({ page, backend }) => {
    void backend;
    await openList(page);
    await page.locator(`${T} tbody tr[data-row="r01"]`).click();
    const sh = page.locator('[data-sheet="demo"]');
    await expect(sh).toBeVisible();
    const anim = await page.evaluate(() => {
      const l = document.querySelector('.sg-sheet-layer')!;
      const a = getComputedStyle(l);
      const b = getComputedStyle(l.querySelector('.sg-sheet')!);
      return [a.animationName, a.animationDuration, b.animationName, b.animationDuration, b.animationTimingFunction];
    });
    expect(anim).toEqual(['sg-scrim-in', '0.12s', 'sg-slide-in', '0.18s', 'cubic-bezier(0.16, 1, 0.3, 1)']);
    await settle(page);
    await sh.evaluate((e) => ((e as HTMLElement & { tkMark?: number }).tkMark = 1));
    await sh.getByTestId('inside-1').focus();
    await page.keyboard.press('ArrowDown');
    await expect(sh.locator('[data-part="skeleton"]'), '받는 동안 시트 안 스켈레톤').toBeVisible();
    expect(
      await sh.evaluate((e) => [(e as HTMLElement & { tkMark?: number }).tkMark, e.getAnimations().filter((a) => a.playState === 'running').length]),
      '같은 시트 · 다시 미끄러지지 않음',
    ).toEqual([1, 0]);
    await expect(sh.locator('[data-part="skeleton"]')).toHaveCount(0);
    await expect(sh.locator('[data-part="sheet-subtitle"]')).toHaveText('r02');
    await page.keyboard.press('Escape');
    await expect(page.locator('.sg-sheet-layer'), '닫힘 효과 없음').toHaveCount(0, { timeout: 150 });
  });
});

test.describe('⑭ 창 · 팝오버 움직임', () => {
  test('큰 창 · 확인 창 = 뒤 어둡게만 150ms(창 상자는 그대로) · 칸 고르기 · 선택 목록 · 알림 · 계정 메뉴 = 같은 열림 120ms', async ({ page, backend }) => {
    void backend;
    await page.goto(BASE);
    const pop = (sel: string) => page.locator(sel).evaluate((e) => [getComputedStyle(e).animationName, getComputedStyle(e).animationDuration]);
    await page.locator('[data-part="bell"]').click();
    expect(await pop('[data-part="notices"]')).toEqual(['tk-pop-in', '0.12s']);
    await page.keyboard.press('Escape');
    await page.locator('[data-part="account"]').click();
    expect(await pop('[data-part="account-menu"]')).toEqual(['tk-pop-in', '0.12s']);
    await page.keyboard.press('Escape');
    await stage(page, 'modal');
    const back = (sel: string) =>
      page.locator(sel).evaluate((e) => [getComputedStyle(e).animationName, getComputedStyle(e, '::backdrop').animationName, getComputedStyle(e, '::backdrop').animationDuration]);
    expect(await back('dialog[data-part="tk-form"]')).toEqual(['none', 'tk-fade', '0.15s']);
    await page.locator('dialog[data-part="tk-form"] input[name="name"]').fill('x');
    await page.keyboard.press('Escape');
    expect(await back('dialog[data-part="unsaved"]')).toEqual(['none', 'tk-fade', '0.15s']);
    await page.goto(BASE);
    await stage(page, 'list');
    await page.locator('[data-action="table-columns"]').click();
    expect(await pop('[data-part="column-picker"]')).toEqual(['tk-pop-in', '0.12s']);
    await page.keyboard.press('Escape');
    await page.locator('[data-tk-stage] [data-filter="kind"]').click();
    expect(await pop('[data-overlay="select"]')).toEqual(['tk-pop-in', '0.12s']);
  });
});

test.describe('⑮ 행 상태', () => {
  test('고른 줄 · 열린 줄 = 같은 연한 강조 바탕, 열린 줄만 왼쪽 3px 주 색 · 위험 막대는 그대로 · hover 는 표 hover 회색 · 전환 0 · 흐리게 하지 않음', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const soft = await cssVar(page, '--accent-soft', 'backgroundColor');
    const hover = await cssVar(page, '--row-hover', 'backgroundColor');
    const accent = await cssVar(page, '--accent');
    const danger = await cssVar(page, '--danger');
    const look = (id: string) =>
      page.locator(`${T} tbody tr[data-row="${id}"]`).evaluate((tr) => {
        const c = getComputedStyle(tr);
        return { bg: c.backgroundColor, tr: c.transitionDuration, op: c.opacity, bar: getComputedStyle((tr as HTMLTableRowElement).cells[0]).boxShadow };
      });
    await page.locator(`${T} tbody tr[data-row="r05"] td[data-col="hits"]`).hover();
    expect(await look('r05')).toMatchObject({ bg: hover, tr: '0s', op: '1', bar: 'none' });
    await page.locator(`${T} tbody tr[data-row="r02"] input[type="checkbox"]`).check();
    await expect(page.locator(`${T} tbody tr[data-row="r02"]`)).toHaveAttribute('data-checked', '');
    await page.mouse.move(5, 5);
    expect(await look('r02'), '고른 줄 — 막대 없음').toMatchObject({ bg: soft, bar: 'none' });
    expect((await look('r03')).bar, '위험(격리 판정) 줄 막대').toContain(danger);
    await page.locator(`${T} tbody tr[data-row="r01"]`).click();
    await expect(page.locator(`${T} tbody tr[data-row="r01"]`)).toHaveAttribute('data-open', '');
    const open = await look('r01');
    expect(open.bg).toBe(soft);
    expect(open.bar).toContain(accent);
    expect(open.bar).toMatch(/3px 0px 0px 0px inset|inset 3px 0px 0px 0px/);
    expect(await page.locator(`${T} tbody tr`).evaluateAll((els) => els.every((e) => getComputedStyle(e).opacity === '1'))).toBe(true);
  });
});

test.describe('⑯ 꺼진 단추 · 재조회 · 폭 손잡이 · 줄 끝 고정', () => {
  test('aria-disabled + 사유(초점은 감) · 재조회는 이전 줄 유지 + 맨 위 진행 띠 · 손잡이 늘 .7 · 올리면 주 색 · 가로 스크롤이 남았을 때만 줄 끝 그림자', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const accent = await cssVar(page, '--accent', 'backgroundColor');
    // 꺼진 「칸 기본으로」 — 진짜 disabled 가 아니라 aria-disabled + 사유, 초점은 간다
    await page.locator('[data-action="table-columns"]').click();
    const reset = page.locator('[data-action="columns-reset"]');
    await expect(reset).toHaveAttribute('aria-disabled', 'true');
    await expect(reset).toHaveAttribute('title', '이미 기본 칸입니다'); // §7 꺼진 사유 = 문장 · 마침표 없음
    expect(await reset.evaluate((e) => (e as HTMLButtonElement).disabled)).toBe(false);
    await reset.focus();
    await expect(reset).toBeFocused();
    await page.keyboard.press('Escape');
    // 재조회: 줄은 그대로, 진행 띠 · 새로고침은 사유와 함께 꺼짐
    const rows = page.locator(`${T} tbody tr`);
    const refresh = page.locator('[data-action="table-refresh"]');
    await refresh.click();
    const busy = page.locator('[data-table-tools="demo"] [data-part="busy"]');
    await expect(busy).toBeVisible();
    await expect(rows).toHaveCount(20);
    await expect(refresh).toHaveAttribute('aria-disabled', 'true');
    await expect(refresh).toHaveAttribute('title', '불러오는 중입니다');
    await expect(busy).toBeHidden();
    await expect(refresh).not.toHaveAttribute('aria-disabled', 'true');
    // 폭 손잡이: 늘 보임 .7 · 올리면 주 색
    const h = page.locator(`${T} th[data-col="kind"] [data-part="col-resize"]`);
    expect(await h.evaluate((e) => getComputedStyle(e, '::after').opacity)).toBe('0.7');
    await h.hover();
    await expect.poll(() => h.evaluate((e) => getComputedStyle(e, '::after').backgroundColor)).toBe(accent);
    // 줄 끝 조작 칸: 오른쪽 고정, 가로 스크롤이 없으면 그림자 없음(폭 1000 에서 정책 칸을 최대로 넓혀 넘치게)
    await page.setViewportSize({ width: 1000, height: 900 });
    const scroll = page.getByTestId('tk-scroll');
    const act = page.locator(`${T} tbody tr`).first().locator('td[data-col="act"]');
    expect(await act.evaluate((e) => [getComputedStyle(e).position, getComputedStyle(e).boxShadow])).toEqual(['sticky', 'none']);
    await expect(scroll).not.toHaveAttribute('data-hscroll', /.*/);
    const nh = page.locator(`${T} th[data-col="name"] [data-part="col-resize"]`);
    for (let i = 0; i < 60; i++) await nh.press('ArrowRight');
    await expect(scroll).toHaveAttribute('data-hscroll', '');
    expect(await act.evaluate((e) => getComputedStyle(e).boxShadow)).not.toBe('none');
    await scroll.evaluate((e) => (e.scrollLeft = e.scrollWidth));
    await expect(scroll, '오른쪽 끝까지 밀면 그림자 없음').not.toHaveAttribute('data-hscroll', /.*/);
    expect(await act.evaluate((e) => getComputedStyle(e).boxShadow)).toBe('none');
  });
});

test.describe('⑰ 칸 도우미', () => {
  test('두 줄 칸(13.5/500 · 12 고정폭 흐림 · 줄간격 1.3) · 빈 값 「—」 · 시각 3형식(상대 시각 없음) · 시각 칸 표준 폭 160 · CSV = 화면 글', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const muted = await cssVar(page, '--text-3');
    const mono = await cssVar(page, '--mono', 'fontFamily');
    await page.locator('[data-action="table-columns"]').click();
    const pop = page.locator('[data-part="column-picker"]');
    await pop.getByRole('checkbox', { name: '메모' }).check();
    await pop.getByRole('checkbox', { name: '시각' }).check();
    await expect(pop, '여러 칸을 연달아 켜도 열린 채').toBeVisible();
    await page.keyboard.press('Escape');
    expect(Math.round(await thW(page, 'seen'))).toBe(160);
    const empty = page.locator(`${T} tbody tr[data-row="r04"] td[data-col="note"]`);
    await expect(empty).toHaveText('—');
    expect(await empty.locator('.tk-empty').evaluate((e) => getComputedStyle(e).color)).toBe(muted);
    const seen = page.locator(`${T} tbody tr[data-row="r01"] td[data-col="seen"] time`);
    await expect(seen).toHaveText('2026-11-09 12:04:05');
    expect(await seen.evaluate((e) => getComputedStyle(e).fontFamily)).toBe(mono);
    const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('[data-action="table-export"]').click()]);
    const lines = readFileSync((await dl.path())!, 'utf8').slice(1).trim().split('\n');
    expect(lines[0]).toBe('정책,종류,판정,담당,위반,메모,시각');
    expect(lines[4], '빈 값도 화면 글(—) 그대로').toBe('policy-04,dns,allow,owner-d,21,—,2026-11-09 12:04:05');
    // 시트 안 두 줄 칸 · 시각 형식
    await page.locator(`${T} tbody tr[data-row="r01"]`).click();
    const sh = page.locator('[data-sheet="demo"]');
    const two = await sh.getByTestId('two').evaluate((e) => {
      const t = getComputedStyle(e.querySelector('.tk-2l-top')!);
      const b = getComputedStyle(e.querySelector('.tk-2l-sub')!);
      return [t.fontSize, t.fontWeight, t.lineHeight, b.fontSize, b.lineHeight, b.color, b.fontFamily];
    });
    expect(two).toEqual(['13.5px', '500', '17.55px', '12px', '15.6px', muted, mono]);
    const t = (id: string) => sh.getByTestId(id).evaluate((e) => [e.tagName, e.textContent, e.getAttribute('title'), e.getAttribute('datetime')]);
    expect(await t('t-log')).toEqual(['TIME', '2026-11-09 12:04:05', null, '2026-11-09T03:04:05.000Z']);
    expect(await t('t-status')).toEqual(['TIME', '11-09 12:04', '2026-11-09 12:04:05', '2026-11-09T03:04:05.000Z']);
    expect(await t('t-day')).toEqual(['TIME', '2026-11-09', '2026-11-09 12:04:05', '2026-11-09T03:04:05.000Z']);
    await expect(sh, '상대 시각 없음').not.toContainText(/분 전|시간 전|일 전/);
  });
});

test.describe('⑱ 화면 제목 · 로그인(11/05 값)', () => {
  test('화면 제목 굵기 700 · 로그인 카드 반경 12 · 로그인 입력창 반경 6', async ({ page, backend, allowConsole }) => {
    await page.goto(BASE);
    expect(await page.getByTestId('page-title').evaluate((e) => getComputedStyle(e).fontWeight)).toBe('700');
    allowConsole(/^Failed to load resource: the server responded with a status of 401 /);
    backend.auth.loggedOut();
    await page.goto('/');
    const auth = page.locator('[data-part="auth"]');
    await expect(auth).toHaveAttribute('data-step', 'login');
    expect(await page.locator('[data-part="auth"] > div').first().evaluate((e) => getComputedStyle(e).borderRadius)).toBe('12px');
    expect(await auth.getByLabel('아이디').evaluate((e) => getComputedStyle(e).borderRadius)).toBe('6px');
  });
});

// ── 11/09 3차: SPEC-1109 §7 화면 문구(공통 부품 몫) ──
// 확인 창 · 화면 상태 기본 문구 · 꺼진 단추 사유(마침표 없음) · 아이콘 단추 이름 · 표 아래 안내 · 동작 끝말 색 · 화면 설명 저장소

test.describe('⑲ 확인 창', () => {
  test('제목 「~할까요?」 · 본문 · 영향 범위 줄 · 확인 체크 · 위험 단추 — 체크 전 확인은 aria-disabled + 사유(마침표 없음)', async ({ page, backend }) => {
    void backend;
    await page.goto(BASE);
    const impact = ['이 정책을 쓰는 컨테이너 3개의 판정이 바뀝니다.', '차단 이력 12건은 그대로 남습니다.'];
    await stage(page, 'confirm', {
      title: '정책 no-shell-download 을 삭제할까요?',
      body: '삭제한 정책은 더 이상 판정하지 않습니다.',
      impact,
      requireCheck: '삭제하면 되돌릴 수 없음을 확인했습니다',
      confirmLabel: '삭제',
      danger: true,
    });
    const d = page.locator('dialog[data-part="confirm"]');
    await expect(d).toHaveAttribute('aria-label', '정책 no-shell-download 을 삭제할까요?');
    await expect(d.locator('h3')).toHaveText('정책 no-shell-download 을 삭제할까요?');
    await expect(d.locator('[data-part="confirm-body"]')).toHaveText('삭제한 정책은 더 이상 판정하지 않습니다.');
    await expect(d.locator('[data-part="confirm-impact"] li')).toHaveText(impact);
    await expect(d.locator('[data-part="confirm-effects"]'), '영향 범위를 주면 옛 「함께 일어나는 일」 칸은 없음').toHaveCount(0);
    await expect(d.locator('[data-part="confirm-target"]')).toHaveCount(0);
    const ok = d.locator('[data-confirm="ok"]');
    await expect(ok).toHaveText('삭제');
    await expect(ok).toHaveClass(/sg-btn-danger/);
    await expect(ok).toHaveAttribute('aria-disabled', 'true');
    await expect(ok).toHaveAttribute('title', '확인 칸을 먼저 고르세요');
    await ok.click({ force: true }); // 꺼진 단추(aria-disabled)는 눌러도 아무 일 없음 — Playwright 는 꺼진 단추를 기다리므로 force
    await expect(page.locator('[data-tk-confirmed]')).toHaveCount(0);
    await d.getByRole('checkbox', { name: '삭제하면 되돌릴 수 없음을 확인했습니다' }).check();
    await expect(ok).not.toHaveAttribute('aria-disabled', 'true');
    await ok.click();
    await expect(page.locator('[data-tk-confirmed="1"]')).toHaveCount(1);
  });

  test('막는 사유가 있으면 확인이 꺼진다(사유 상자 · 툴팁은 마침표 없이) · 주 단추 모양', async ({ page, backend }) => {
    void backend;
    await page.goto(BASE);
    await stage(page, 'confirm', { title: '정책 sandbox-dns 를 삭제할까요?', blocked: '시스템 규칙은 지울 수 없습니다.', requireCheck: '삭제하면 되돌릴 수 없음을 확인했습니다', confirmLabel: '삭제', danger: true });
    const d = page.locator('dialog[data-part="confirm"]');
    await expect(d.locator('[data-part="confirm-blocked"]')).toHaveText('시스템 규칙은 지울 수 없습니다.');
    await expect(d.getByRole('checkbox'), '막혔으면 확인 체크도 없음').toHaveCount(0);
    const ok = d.locator('[data-confirm="ok"]');
    await expect(ok).toHaveAttribute('aria-disabled', 'true');
    await expect(ok).toHaveAttribute('title', '시스템 규칙은 지울 수 없습니다');
    await ok.click({ force: true });
    await expect(page.locator('[data-tk-confirmed]')).toHaveCount(0);
    await stage(page, 'confirm', { title: '정책 egress-allowlist 를 저장할까요?', body: '저장하면 바로 적용됩니다.', confirmLabel: '저장', danger: false });
    await expect(d.locator('[data-confirm="ok"]')).toHaveClass(/sg-btn-primary/);
    await expect(d.locator('[data-confirm="ok"]')).toHaveText('저장');
  });
});

test.describe('⑳ 화면 상태 기본 문구', () => {
  test('빈 「[무엇]이 없습니다.」 + 다음 할 일 + 1차 단추 · 검색 결과 없음 · 오류 · 권한 없음 · 로딩 읽기 라벨 — 아이콘 없음', async ({ page, backend }) => {
    void backend;
    await page.goto(BASE);
    await stage(page, 'states');
    const st = (k: string) => page.locator(`[data-tk-stage="states"] [data-state="${k}"]`);
    await expect(st('empty').locator('[data-part="empty"] > span').first()).toHaveText('정책이 없습니다.');
    await expect(st('empty')).toContainText('정책 생성으로 첫 정책을 만드세요.');
    await expect(st('empty').getByRole('button', { name: '정책 생성' })).toBeVisible();
    await expect(st('empty-log').locator('[data-part="empty"] > span').first()).toHaveText('감사 로그가 없습니다.');
    await expect(st('empty-default').locator('[data-part="empty"] > span').first()).toHaveText('데이터가 없습니다.');
    const nr = st('no-results').locator('[data-part="no-results"]');
    await expect(nr).toContainText('조건에 맞는 데이터가 없습니다');
    await expect(nr).toContainText('검색 조건을 바꾸거나 해제해 보세요.');
    await nr.getByRole('button', { name: '조건 지우기' }).click();
    await expect(page.locator('[data-tk-cleared="1"]')).toHaveCount(1);
    await expect(st('error').locator('[data-part="error"]')).toContainText('불러오지 못했습니다');
    await expect(st('error').getByRole('button', { name: '다시 시도' })).toBeVisible();
    await expect(st('denied').locator('[data-part="denied"]')).toHaveText('이 화면을 볼 권한이 없습니다.');
    const sk = st('loading').locator('[data-part="skeleton"]');
    await expect(sk).toHaveAttribute('aria-busy', 'true');
    await expect(sk).toHaveAttribute('aria-label', '불러오는 중');
    for (const k of ['empty', 'empty-default', 'no-results', 'denied']) await expect(st(k).locator('svg'), `${k} 아이콘 없음`).toHaveCount(0);
  });
});

test.describe('㉑ 아이콘 단추 이름 · 꺼진 단추 사유', () => {
  test('아이콘 단추는 title = aria-label 「동작 — 대상」 · 꺼진 사유는 마침표 없이(부품 기본 사유 포함)', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const act = (id: string) => page.locator(`${T} tbody tr[data-row="${id}"] td[data-col="act"] button`);
    await expect(act('r01')).toHaveAttribute('aria-label', '되돌리기 — r01');
    await expect(act('r01')).toHaveAttribute('title', '되돌리기 — r01');
    await expect(act('r03')).toHaveAttribute('aria-label', '되돌리기 — r03');
    await expect(act('r03')).toHaveAttribute('aria-disabled', 'true');
    await expect(act('r03')).toHaveAttribute('title', '시스템 규칙은 되돌릴 수 없습니다');
    const pairs = await page
      .locator('[data-table-tools="demo"] .tk-icon-btn, [data-table-foot="demo"] .tk-page[aria-label]')
      .evaluateAll((els) => els.map((e) => [e.getAttribute('title'), e.getAttribute('aria-label')]));
    expect(pairs.length).toBeGreaterThan(5);
    for (const [t, a] of pairs) expect(t, `${a} 의 title`).toBe(a);
    // 부품 기본 사유 — 마침표 없음
    await page.locator('[data-action="table-columns"]').click();
    await expect(page.locator('[data-action="columns-reset"]')).toHaveAttribute('title', '이미 기본 칸입니다');
    for (const n of ['종류', '판정', '담당', '위반']) await page.locator('[data-part="column-picker"]').getByRole('checkbox', { name: n }).uncheck();
    await expect(page.locator('[data-part="column-picker"] label[data-col="name"]')).toHaveAttribute('title', '칸은 하나 이상 보여야 합니다');
    await page.keyboard.press('Escape');
    await page.locator('[data-action="table-refresh"]').click();
    await expect(page.locator('[data-action="table-refresh"]')).toHaveAttribute('title', '불러오는 중입니다');
  });
});

test.describe('㉒ 표 아래 안내 한 줄', () => {
  test('작은 흐린 글 한 줄 · 넘치면 「…」 · 마우스 올리면 전체(title)', async ({ page, backend }) => {
    void backend;
    await openList(page);
    const note = page.locator('[data-tk-stage] [data-part="screen-note"]');
    const text = await note.textContent();
    expect(text!.length).toBeGreaterThan(100);
    await expect(note).toHaveAttribute('title', text!);
    const look = await note.evaluate((e) => {
      const c = getComputedStyle(e);
      return { fs: c.fontSize, ws: c.whiteSpace, of: c.overflow, to: c.textOverflow, color: c.color, cut: e.scrollWidth > e.clientWidth };
    });
    expect(look).toEqual({ fs: '12px', ws: 'nowrap', of: 'hidden', to: 'ellipsis', color: await cssVar(page, '--text-3'), cut: true });
  });
});

test.describe('㉓ 동작 끝말 → 색(lib/actionTone.ts)', () => {
  test('삭제 · 해제 · 정지 = 위험 / 적용 · 내보내기 · 반영 = 정보 / 수정 · 변경 · 되돌리기 · 되돌림 · 초기화 = 주의 / 등록 · 생성 · 추가 = 정상 / 그 밖 = 회색', async () => {
    const want: Record<string, string> = {
      '정책 삭제': 'danger', '차단 해제': 'danger', '감시 정지': 'danger',
      '정책 적용': 'info', 'CSV 내보내기': 'info', '설정 반영': 'info',
      '정책 수정': 'warn', '규칙 변경': 'warn', '정책 되돌리기': 'warn', '정책 되돌림': 'warn', '비밀번호 초기화': 'warn',
      '계정 등록': 'ok', '정책 생성': 'ok', '예외 추가': 'ok',
      로그인: 'neutral', '': 'neutral', '연결 테스트': 'neutral',
    };
    for (const [name, tone] of Object.entries(want)) expect(actionTone(name), name).toBe(tone);
    expect(actionTone('  정책 삭제  '), '앞뒤 공백 무시').toBe('danger');
  });
});

test.describe('㉔ 화면 설명 저장소(lib/screenCopy.ts)', () => {
  test('등록된 설명은 모두 「니다.」로 끝나는 20~50자 한 문장 · 마침표 앞 기호 없음 · 검사기는 틀린 문장을 잡는다', async () => {
    const m = copy;
    expect(m.checkScreenCopy('컨테이너 행동을 판정하는 정책을 만들고 적용 범위를 관리합니다.')).toEqual([]);
    expect(m.checkScreenCopy('정책을 관리합니다.')).toContain('length');
    expect(m.checkScreenCopy('컨테이너 행동을 판정하는 정책을 만들고 적용 범위를 관리함')).toContain('ending');
    expect(m.checkScreenCopy('컨테이너 행동을 판정하는 정책(규칙)을 만들고 적용 범위를 관리합니다.')).toContain('symbol');
    expect(m.checkScreenCopy('컨테이너 행동을 판정하는 정책을 만들고 · 적용 범위를 관리합니다.')).toContain('symbol');
    expect(m.checkScreenCopy('컨테이너 행동을 판정합니다. 적용 범위를 관리하고 기록을 봅니다.')).toContain('symbol');
    for (const [k, v] of Object.entries(m.SCREEN_COPY)) expect(m.checkScreenCopy(v), `SCREEN_COPY.${k}`).toEqual([]);
    for (const [k, v] of Object.entries(m.SCREEN_NOTE)) expect(v, `SCREEN_NOTE.${k}`).toMatch(/[^.…]\.$/);
    expect(m.screenCopy('없는-화면')).toBe('');
    expect(m.screenNote('없는-화면')).toBe('');
  });
});

test.describe('㉕ 꺼진 단추 모양 — aria-disabled 는 진짜 disabled 와 같다(평소 · 마우스 올림, 11/09 메인 실측)', () => {
  test('sg-btn 주 · 보조 · 위험 단추: aria-disabled="true" 의 바탕 · 글자 · 테두리 · 커서가 :disabled 와 같고 마우스를 올려도 그대로', async ({ page, backend }) => {
    void backend;
    await page.goto('/audit');
    await expect(page.locator('main')).toBeVisible();
    for (const cls of ['sg-btn sg-btn-primary', 'sg-btn sg-btn-secondary', 'sg-btn sg-btn-danger']) {
      await page.evaluate((c) => {
        for (const kind of ['real', 'aria']) {
          const b = document.createElement('button');
          b.className = c;
          b.textContent = '단추';
          b.dataset.zz = kind;
          if (kind === 'real') b.disabled = true;
          else b.setAttribute('aria-disabled', 'true');
          document.body.appendChild(b);
        }
      }, cls);
      const look = (kind: string) =>
        page.locator(`button[data-zz="${kind}"]`).last().evaluate((e) => {
          const s = getComputedStyle(e);
          return [s.backgroundColor, s.color, s.borderTopColor, s.cursor, s.boxShadow].join(' | ');
        });
      const real = await look('real');
      expect(await look('aria'), cls).toBe(real);
      await page.locator('button[data-zz="aria"]').last().hover();
      await expect.poll(() => look('aria'), { message: `${cls} hover` }).toBe(real);
      await page.mouse.move(0, 0);
      await page.evaluate(() => document.querySelectorAll('button[data-zz]').forEach((b) => b.remove()));
    }
  });
});
