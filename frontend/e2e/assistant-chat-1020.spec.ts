import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';

// 10/20 W13 — 도우미 패널 「AI 도우미」 탭(목업 mock/shared/chat.js · guide.js) + 공급망 검사 건(source scan) 출처 표기.
// 서버 계약: 메인 백엔드 api/chat.go — POST /api/chat {question, page, history:[{role, text}]} → SSE token… → facts → links → done | error.
// 기본 가짜 SSE 는 mock-backend(route.fulfill, 본문 한 번에). 조각을 하나씩 흘려야 하는 시나리오는 아래 manualChat(fetch 대체)로 조절한다.

const PANEL = '[data-part="assistant"]';
const CHAT = '[data-part="chat"]';
const panel = (p: Page) => p.locator(PANEL);
const chat = (p: Page) => p.locator(CHAT);
const msgs = (p: Page) => p.locator(`${CHAT} [data-part="chat-msg"]`);
const last = (p: Page) => msgs(p).last();
const input = (p: Page) => chat(p).getByRole('textbox', { name: '질문' });

async function ready(page: Page, path = '/') {
  await page.goto(path);
  await expect(page.getByText('실시간 연결됨')).toBeVisible();
  await expect(page.locator('[data-part="assistant-fab"]')).toHaveAttribute('data-ready', 'true');
}
async function openChat(page: Page) {
  if (await panel(page).isHidden()) await page.locator('[data-part="assistant-fab"]').click();
  await panel(page).getByRole('tab', { name: 'AI 도우미' }).click();
  await expect(chat(page)).toBeVisible();
}
async function ask(page: Page, q: string) {
  await input(page).fill(q);
  await input(page).press('Enter');
}
const chatBodies = (b: { requests: { method: string; path: string; body?: string }[] }) =>
  b.requests.filter((r) => r.method === 'POST' && r.path === '/chat').map((r) => JSON.parse(r.body ?? '{}'));

// fetch('/api/chat') 를 테스트가 조절하는 스트림으로 바꾼다 — window.__sse.push(text) · close() · aborted
async function manualChat(page: Page) {
  await page.addInitScript(() => {
    const orig = window.fetch.bind(window);
    const w = window as unknown as { __sse: unknown };
    w.__sse = null;
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (!url.includes('/api/chat')) return orig(input, init);
      let ctl!: ReadableStreamDefaultController<Uint8Array>;
      const stream = new ReadableStream<Uint8Array>({ start: (c) => void (ctl = c) });
      const enc = new TextEncoder();
      const s = {
        body: String(init?.body ?? ''),
        aborted: false,
        push: (t: string) => ctl.enqueue(enc.encode(t)),
        // 앱이 done 에서 읽기를 끝내며 스트림을 취소했을 수 있다
        close: () => {
          try {
            ctl.close();
          } catch {
            /* 이미 취소됨 */
          }
        },
      };
      w.__sse = s;
      init?.signal?.addEventListener('abort', () => {
        s.aborted = true;
        try {
          ctl.error(new DOMException('aborted', 'AbortError'));
        } catch {
          /* 이미 닫힘 */
        }
      });
      return new Response(stream, { status: 200, headers: { 'Content-Type': 'text/event-stream; charset=utf-8' } });
    };
  });
}
type Sse = { push: (t: string) => void; close: () => void; aborted: boolean; body: string };
const push = (page: Page, event: string, data: unknown) =>
  page.evaluate(([e, d]) => (window as unknown as { __sse: Sse }).__sse.push(`event: ${e}\ndata: ${JSON.stringify(d)}\n\n`), [event, data] as const);
const sseReady = (page: Page) => page.waitForFunction(() => !!(window as unknown as { __sse: Sse | null }).__sse);

test.describe('도우미 · AI 도우미 탭 (10/20 W13)', () => {
  test('1 탭 표시 조건: /api/info chat 이 false 면 가이드 탭 하나, true 면 「AI 도우미」 탭 · 머리 문구 · 추천 질문 4개 · 입력 포커스', async ({ page, backend }) => {
    await ready(page);
    await page.locator('[data-part="assistant-fab"]').click();
    // 11/02 결정: 꺼져 있어도 탭은 보이고 이유를 알린다(전엔 가이드 탭 하나)
    await expect(panel(page).getByRole('tab')).toHaveText(['대응 가이드', 'AI 도우미']);
    await panel(page).getByRole('tab', { name: 'AI 도우미' }).click();
    await expect(panel(page).locator('[data-part="chat-off"]')).toContainText('AI 도우미가 꺼져 있습니다');
    await expect(panel(page).locator('[data-part="chat-off"]')).toContainText('OLLAMA_URL');
    await expect(chat(page)).toHaveCount(0);

    backend.info.chat = true;
    await ready(page);
    await page.locator('[data-part="assistant-fab"]').click();
    await expect(panel(page).getByRole('tab')).toHaveText(['대응 가이드', 'AI 도우미']);
    await panel(page).getByRole('tab', { name: 'AI 도우미' }).click();
    await expect(panel(page).getByRole('tab', { name: 'AI 도우미' })).toHaveAttribute('aria-selected', 'true');
    await expect(chat(page)).toContainText('로컬 모델 qwen2.5:3b · 데이터는 서버 밖으로 나가지 않음');
    await expect(chat(page).locator('[data-part="chat-sugg"] button')).toHaveText(['판정 대기 요약해 줘', '오늘 가장 많이 걸린 정책은?', '이 화면은 뭘 하는 곳이야?', '최근 공급망 검사 결과 알려 줘']);
    await expect(input(page)).toBeFocused();
    await expect(msgs(page)).toHaveCount(0);
    await expect(chat(page).locator('[data-part="chat-greeting"]')).toBeVisible();
  });

  test('2 추천 질문 → 요청 본문(question · page · history) · 답 · 서버 확정 상태 칩 · 관련 화면 링크 · 추천 질문 숨김', async ({ page, backend }) => {
    backend.info.chat = true;
    await ready(page);
    await openChat(page);
    await chat(page).locator('[data-part="chat-sugg"] button', { hasText: '판정 대기 요약해 줘' }).click();
    await expect(last(page)).toContainText('판정 대기 건이 3개 있습니다. 각 건을 열어 판정하세요.');
    expect(chatBodies(backend)).toEqual([{ question: '판정 대기 요약해 줘', page: '/', history: [] }]);
    await expect(msgs(page)).toHaveCount(2);
    await expect(msgs(page).first()).toHaveAttribute('data-role', 'user');
    const chip = last(page).locator('[data-part="chat-status"]');
    await expect(chip).toContainText('판정 대기 3건');
    await expect(chip).toContainText('서버 확정');
    await expect(chip).toHaveAttribute('title', /모델 문장보다/);
    // 칩은 답 위
    const [cb, bb] = await Promise.all([chip.boundingBox(), last(page).locator('[data-part="chat-bubble"]').boundingBox()]);
    expect(cb!.y).toBeLessThan(bb!.y);
    await expect(last(page).locator('[data-part="chat-links"] a')).toHaveText(['감사 로그(판정 · 변경 이력) →']);
    await expect(chat(page).locator('[data-part="chat-sugg"]')).toBeHidden();
  });

  test('3 흐름 순서: 첫 글자 전 「생각하는 중… N초」 → 조각이 이어 붙음 → facts 칩 → links → done 에 보내기 복귀', async ({ page, backend }) => {
    backend.info.chat = true;
    await manualChat(page);
    await ready(page, '/installs');
    await openChat(page);
    await ask(page, '판정 대기 요약해 줘');
    await sseReady(page);
    const think = last(page).locator('[data-part="chat-thinking"]');
    await expect(think).toHaveText(/^생각하는 중… \d+초$/);
    await expect(think).toHaveText('생각하는 중… 1초', { timeout: 3000 });
    await expect(chat(page).getByRole('button', { name: '멈추기' })).toBeVisible();
    await expect(chat(page).getByRole('button', { name: '보내기' })).toHaveCount(0);
    await expect(input(page)).toHaveValue('');
    expect(JSON.parse(await page.evaluate(() => (window as unknown as { __sse: Sse }).__sse.body)).page).toBe('/installs');

    await push(page, 'token', '판정 ');
    await expect(think).toHaveCount(0);
    await expect(last(page).locator('[data-part="chat-bubble"]')).toHaveText('판정 ');
    await push(page, 'token', '대기 2건');
    await expect(last(page).locator('[data-part="chat-bubble"]')).toHaveText('판정 대기 2건');
    await expect(last(page).locator('[data-part="chat-status"]')).toHaveCount(0);
    await expect(last(page).locator('[data-part="chat-links"]')).toHaveCount(0);
    await push(page, 'facts', { intent: 'pending', tool: 'pending_cases', status: '판정 대기 7건', sentences: ['x'] });
    await expect(last(page).locator('[data-part="chat-status"]')).toContainText('판정 대기 7건');
    await push(page, 'links', [{ label: '설치 검사', href: '/installs?status=pending' }]);
    await expect(last(page).locator('[data-part="chat-links"] a')).toHaveText(['설치 검사 →']);
    await expect(last(page).locator('[data-part="chat-links"] a')).toHaveAttribute('href', '/installs'); // 필터는 state 로(10/21)
    await expect(chat(page).getByRole('button', { name: '멈추기' })).toBeVisible();
    await push(page, 'done', {});
    await page.evaluate(() => (window as unknown as { __sse: Sse }).__sse.close());
    await expect(chat(page).getByRole('button', { name: '보내기' })).toBeVisible(); // R1 11/04: 보내기 복귀 — 빈 입력이면 잠김(11/04f 채팅 결정)
    await expect(chat(page).getByRole('button', { name: '멈추기' })).toHaveCount(0);
    await expect(last(page).locator('[data-part="chat-error"]')).toHaveCount(0);
  });

  test('4 멈추기: 요청을 끊고(AbortController) 그동안 온 글자는 남긴다 · 「멈췄습니다」', async ({ page, backend }) => {
    backend.info.chat = true;
    await manualChat(page);
    await ready(page);
    await openChat(page);
    await ask(page, '정책 설명해 줘');
    await sseReady(page);
    await push(page, 'token', '정책은 ');
    await expect(last(page).locator('[data-part="chat-bubble"]')).toHaveText('정책은 ');
    await chat(page).getByRole('button', { name: '멈추기' }).click();
    await expect(last(page).locator('[data-part="chat-stopped"]')).toHaveText('멈췄습니다');
    await expect(last(page).locator('[data-part="chat-bubble"]')).toHaveText('정책은 ');
    expect(await page.evaluate(() => (window as unknown as { __sse: Sse }).__sse.aborted)).toBe(true);
    await expect(chat(page).getByRole('button', { name: '보내기' })).toBeVisible(); // R1 11/04: 보내기 복귀 — 빈 입력이면 잠김(11/04f 채팅 결정)
    await expect(last(page).locator('[data-part="chat-error"]')).toHaveCount(0);
  });

  test('5 429(다른 질문에 답하는 중): 입력을 그대로 두고 안내 한 줄 · 대화에 남기지 않는다', async ({ page, backend, allowConsole }) => {
    allowConsole(/status of 429/); // 브라우저가 남기는 네트워크 줄 — 앱 오류가 아니다
    backend.info.chat = true;
    backend.chatReply = { status: 429, error: '다른 질문에 답하는 중입니다. 잠시 뒤 다시 물어 주세요' };
    await ready(page);
    await openChat(page);
    await ask(page, '판정 대기 요약해 줘');
    await expect(chat(page).locator('[data-part="chat-notice"]')).toHaveText(/다른 질문에 답하는 중입니다/);
    await expect(input(page)).toHaveValue('판정 대기 요약해 줘');
    await expect(msgs(page)).toHaveCount(0);
    await expect(chat(page).getByRole('button', { name: '보내기' })).toBeEnabled();
    // 다시 보내면 안내는 사라지고 답한다
    backend.chatReply = null;
    await input(page).press('Enter');
    await expect(last(page)).toContainText('판정 대기 건이 3개');
    await expect(chat(page).locator('[data-part="chat-notice"]')).toHaveCount(0);
  });

  test('6 error 이벤트: 그동안 온 글자를 남기고 붉은 한 줄 + 「모델 없이 찾은 사실」 목록 · 상태 칩', async ({ page, backend }) => {
    backend.info.chat = true;
    backend.chatReply = {
      events: [
        ['token', '판정 대기는'],
        ['facts', { intent: 'pending', tool: 'pending_cases', status: '판정 대기 3건', sentences: ['pip ./reqeusts 는 판정 대기입니다.', 'pkg-reqeusts 는 격리됐습니다.'] }],
        ['links', []],
        ['error', 'AI 모델 답을 받지 못했습니다'],
      ],
    };
    await ready(page);
    await openChat(page);
    await ask(page, '판정 대기 요약해 줘');
    const err = last(page).locator('[data-part="chat-error"]');
    await expect(err).toHaveText('AI 모델 답을 받지 못했습니다');
    await expect(err).toHaveClass(/text-red-/);
    await expect(last(page).locator('[data-part="chat-bubble"]')).toHaveText('판정 대기는');
    const facts = last(page).locator('[data-part="chat-facts"]');
    await expect(facts).toContainText('모델 없이 찾은 사실');
    await expect(facts.locator('li')).toHaveText(['pip ./reqeusts 는 판정 대기입니다.', 'pkg-reqeusts 는 격리됐습니다.']);
    await expect(last(page).locator('[data-part="chat-status"]')).toContainText('판정 대기 3건');
    await expect(last(page).locator('[data-part="chat-links"]')).toHaveCount(0);
  });

  test('7 관련 화면 링크는 앱 안에서 이동(react-router) · 패널은 닫힌다', async ({ page, backend }) => {
    backend.info.chat = true;
    await ready(page);
    await openChat(page);
    await ask(page, '판정 대기 요약해 줘');
    const a = last(page).locator('[data-part="chat-links"] a');
    await expect(a).toHaveAttribute('href', '/audit?view=changes');
    const before = backend.requests.filter((r) => r.path === '/info').length;
    await a.click();
    await expect(page).toHaveURL(/\/audit\?view=changes$/);
    await expect(page.getByTestId('history')).toBeVisible();
    await expect(panel(page)).toBeHidden();
    // 전체 새로고침이 아니다(/api/info 를 다시 부르지 않음)
    expect(backend.requests.filter((r) => r.path === '/info').length).toBe(before);
  });

  test('8 대화는 이 탭(sessionStorage supplyguard.chat)에 최근 30개 · 새로고침 뒤에도 · 다음 질문은 앞 대화(최근 6턴)를 보낸다', async ({ page, backend }) => {
    backend.info.chat = true;
    await ready(page);
    await openChat(page);
    await ask(page, '판정 대기 요약해 줘');
    await expect(last(page).locator('[data-part="chat-links"] a')).toHaveCount(1);
    await page.reload();
    await expect(page.locator('[data-part="assistant-fab"]')).toHaveAttribute('data-ready', 'true');
    await openChat(page);
    await expect(msgs(page)).toHaveCount(2);
    await expect(last(page)).toContainText('판정 대기 건이 3개');
    await expect(last(page).locator('[data-part="chat-status"]')).toContainText('판정 대기 3건');
    await expect(last(page).locator('[data-part="chat-links"] a')).toHaveCount(1);
    await expect(chat(page).locator('[data-part="chat-sugg"]')).toBeHidden();

    await ask(page, '다시 알려 줘');
    await expect(msgs(page)).toHaveCount(4);
    await expect(chat(page).getByRole('button', { name: '보내기' })).toBeVisible(); // R1 11/04: 보내기 복귀 — 빈 입력이면 잠김(11/04f 채팅 결정)
    expect(chatBodies(backend).at(-1).history).toEqual([
      { role: 'user', text: '판정 대기 요약해 줘' },
      { role: 'assistant', text: '판정 대기 건이 3개 있습니다. 각 건을 열어 판정하세요.' },
    ]);

    // 40개를 넣어 두면 보낼 때는 6턴, 저장은 30개
    await page.evaluate(() => {
      const m = Array.from({ length: 40 }, (_, i) => ({ role: i % 2 ? 'assistant' : 'user', text: `m${i}` }));
      sessionStorage.setItem('supplyguard.chat', JSON.stringify(m));
    });
    await page.reload();
    await expect(page.locator('[data-part="assistant-fab"]')).toHaveAttribute('data-ready', 'true');
    await openChat(page);
    await expect(msgs(page)).toHaveCount(30);
    await ask(page, '세 번째 질문');
    await expect(chat(page).getByRole('button', { name: '보내기' })).toBeVisible(); // R1 11/04: 보내기 복귀 — 빈 입력이면 잠김(11/04f 채팅 결정)
    const h = chatBodies(backend).at(-1).history as { role: string; text: string }[];
    expect(h).toHaveLength(6);
    expect(h.at(-1)).toEqual({ role: 'assistant', text: 'm39' });
    const stored = await page.evaluate(() => JSON.parse(sessionStorage.getItem('supplyguard.chat') ?? '[]').length);
    expect(stored).toBe(30);
  });

  test('9 지우기: 대화 · 저장값을 비우고 인사 · 추천 질문으로 돌아간다', async ({ page, backend }) => {
    backend.info.chat = true;
    await ready(page);
    await openChat(page);
    await ask(page, '판정 대기 요약해 줘');
    await expect(msgs(page)).toHaveCount(2);
    await expect(chat(page).getByRole('button', { name: '보내기' })).toBeVisible(); // R1 11/04: 보내기 복귀 — 빈 입력이면 잠김(11/04f 채팅 결정)
    await chat(page).getByRole('button', { name: '대화 지우기' }).click();
    await expect(msgs(page)).toHaveCount(0);
    await expect(chat(page).locator('[data-part="chat-greeting"]')).toBeVisible();
    await expect(chat(page).locator('[data-part="chat-sugg"] button')).toHaveCount(4);
    const stored = await page.evaluate(() => JSON.parse(sessionStorage.getItem('supplyguard.chat') ?? '[]').length);
    expect(stored).toBe(0);
  });

  test('10 SSE 파서(lib/sse.ts): 조각 경계 · CRLF · 주석 · 여러 줄 data · 끝의 빈 줄 없음', async ({ page, backend }) => {
    void backend;
    await page.goto('/');
    const out = await page.evaluate(async () => {
      const path = '/src/lib/sse.ts';
      const { SSEParser } = (await import(/* @vite-ignore */ path)) as {
        SSEParser: new () => { push: (s: string) => { event: string; data: string }[]; end: () => { event: string; data: string }[] };
      };
      const p = new SSEParser();
      const got: { event: string; data: string }[] = [];
      for (const c of [': start\n\nevent: tok', 'en\ndata: "가"\n', '\nevent: token\r', '\ndata: "나"\r\n\r\n', ': ping\n\n', 'data: a\ndata: b\n\n', 'event: done\ndata: {}']) got.push(...p.push(c));
      got.push(...p.end());
      return got;
    });
    expect(out).toEqual([
      { event: 'token', data: '"가"' },
      { event: 'token', data: '"나"' },
      { event: 'message', data: 'a\nb' },
      { event: 'done', data: '{}' },
    ]);
  });
});

test.describe('공급망 검사 건 출처 표기 (10/20 W13)', () => {
  test('11 대시보드 판정 대기 · 정책 제안 근거 · 감사 판정 이력 · 대응 가이드 — 「공급망 검사」, 링크는 /scans?id=', async ({ page, backend }) => {
    const open = backend.scanCase();
    const decided = backend.scanCase({ decided: true });

    await ready(page);
    const row = page.locator(`a[data-case="${open.c.id}"]`);
    await expect(row).toContainText('공급망 검사');
    await expect(row).toHaveAttribute('href', '/scans?id=scan-0007');

    await page.goto(`/policies?proposal=${decided.p!.id}`);
    const detail = page.getByTestId('proposal');
    await expect(detail).toContainText('공급망 검사 pip evil-pkg 0.1.0');
    await expect(detail.getByRole('link', { name: '검사 결과 보기' })).toHaveAttribute('href', '/scans?id=scan-0007');

    await page.goto('/audit?view=changes');
    const h = page.getByTestId('history').locator(`[data-history="case:${decided.c.id}"]`);
    await expect(h).toContainText('공급망 검사 pip evil-pkg 0.1.0');
    await expect(h.getByRole('link', { name: '검사 결과 보기' })).toHaveAttribute('href', '/scans?id=scan-0007');

    await ready(page);
    await page.locator('[data-part="assistant-fab"]').click();
    await page.locator('[data-part="guide"] select').selectOption(open.c.id);
    await expect(page.locator('[data-part="guide"]')).toContainText(`공급망 검사 · pip evil-pkg 0.1.0`);
  });
});
