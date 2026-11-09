import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';

// 11/09 사용자 결정 — AI 도우미 Claude 기본 · 로컬 Ollama 예비. /api/info chatEngine {provider, model, backup?} 에 따라
// 채팅 패널 머리 · 아래 안내가 실제 모델을 말하고(「데이터는 서버 밖으로 나가지 않음」 고정 문구 제거), 설정 화면에 「밖으로 나가는 데이터」를 보인다.

const PANEL = '[data-part="assistant"]';
const CHAT = '[data-part="chat"]';
const panel = (p: Page) => p.locator(PANEL);
const chat = (p: Page) => p.locator(CHAT);

async function openChat(page: Page) {
  await page.goto('/');
  await expect(page.getByText('실시간 연결됨')).toBeVisible();
  await expect(page.locator('[data-part="assistant-fab"]')).toHaveAttribute('data-ready', 'true');
  await page.locator('[data-part="assistant-fab"]').click();
  await panel(page).getByRole('tab', { name: 'AI 도우미' }).click();
}

test.describe('AI 도우미 Claude 연결 (11/09)', () => {
  test('1 Claude + 예비 Ollama — 머리에 모델 · 「Anthropic API 로 전송됨」 · 예비, 아래 안내에 「1분」 없음', async ({ page, backend }) => {
    backend.info.chat = true;
    backend.info.chatEngine = { provider: 'claude', model: 'claude-opus-5-5', backup: 'ollama' };
    await openChat(page);
    const head = chat(page).locator('[data-part="chat-engine"]');
    await expect(head).toHaveAttribute('data-provider', 'claude');
    await expect(head).toHaveText('Claude claude-opus-5-5 · 질문과 조회한 사실이 Anthropic API 로 전송됨 · 예비 로컬 Ollama');
    await expect(chat(page)).not.toContainText('서버 밖으로 나가지 않음');
    await expect(chat(page)).toContainText('읽기 전용 — 판정 · 정책 변경은 하지 않습니다.');
    await expect(chat(page)).not.toContainText('1분 넘게');
  });

  test('2 Ollama 만 — 예전처럼 「로컬 모델 … · 데이터는 서버 밖으로 나가지 않음」 · 첫 질문 1분 안내', async ({ page, backend }) => {
    backend.info.chat = true;
    backend.info.chatEngine = { provider: 'ollama', model: 'qwen2.5:3b' };
    await openChat(page);
    await expect(chat(page).locator('[data-part="chat-engine"]')).toHaveText('로컬 모델 qwen2.5:3b · 데이터는 서버 밖으로 나가지 않음');
    await expect(chat(page)).toContainText('1분 넘게');
  });

  test('3 꺼짐 — 탭 안 안내에 ANTHROPIC_API_KEY · OLLAMA_URL 둘 다', async ({ page, backend }) => {
    expect(backend.info.chat).toBe(false); // 가짜 백엔드 기본값 = 꺼짐
    await openChat(page);
    const off = panel(page).locator('[data-part="chat-off"]');
    await expect(off).toContainText('ANTHROPIC_API_KEY');
    await expect(off).toContainText('OLLAMA_URL');
  });

  test('4 설정 · 서버 — 「AI 도우미」 절: 모델 · 예비 · 밖으로 나가는 / 보내지 않는 데이터 · CHAT_PROVIDER=ollama', async ({ page, backend }) => {
    backend.info.chat = true;
    backend.info.chatEngine = { provider: 'claude', model: 'claude-opus-5-5', backup: 'ollama' };
    await page.goto('/settings');
    const ai = page.locator('[data-view="server"] [data-part="ai"]');
    await expect(ai).toContainText('Claude claude-opus-5-5');
    await expect(ai).toContainText('CHAT_PROVIDER · CLAUDE_MODEL');
    await expect(ai).toContainText('로컬 Ollama');
    await expect(ai.locator('[data-part="ai-sent"] li')).toHaveCount(6);
    await expect(ai.locator('[data-part="ai-sent"]')).toContainText('질문 · 이 탭의 최근 대화 6턴');
    await expect(ai.locator('[data-part="ai-not-sent"]')).toContainText('증거 원문');
    await expect(ai.locator('[data-part="ai-not-sent"]')).toContainText('비밀번호');
    await expect(ai).toContainText('CHAT_PROVIDER=ollama');
    await expect(ai.locator('input, select, textarea, button')).toHaveCount(0); // 보기만

    backend.info.chatEngine = { provider: 'ollama', model: 'qwen2.5:3b' };
    await page.reload();
    await expect(ai).toContainText('로컬 모델 qwen2.5:3b');
    await expect(ai).toContainText('데이터는 서버 밖으로 나가지 않음');
    await expect(ai.locator('[data-part="ai-scope"]')).toHaveCount(0);

    backend.info.chat = false;
    delete backend.info.chatEngine;
    await page.reload();
    await expect(ai).toContainText('꺼짐');
    await expect(ai).toContainText('ANTHROPIC_API_KEY 나 OLLAMA_URL 이 있으면 켜짐');
  });

  test('5 답 속 **굵게** 는 굵은 글자로(별표를 그대로 보이지 않음) · 개조식 줄바꿈 유지 · 코드 블록은 그대로 코드 창', async ({ page, backend }) => {
    backend.info.chat = true;
    backend.info.chatEngine = { provider: 'claude', model: 'claude-opus-5-5' };
    backend.chatReply = {
      events: [
        ['token', '- **pkg-reqeusts** 격리됨\n- 정책 **pipe-to-shell** 위반임\n'],
        ['token', '```sh\ndocker logs **x**\n```'],
        ['facts', { intent: 'audit', tool: 'search_audit', sentences: [] }],
        ['links', []],
        ['done', {}],
      ],
    };
    await openChat(page);
    await chat(page).getByRole('textbox', { name: '질문' }).fill('pkg-reqeusts 는 왜 격리됐어?');
    await chat(page).getByRole('textbox', { name: '질문' }).press('Enter');
    const answer = chat(page).locator('[data-part="chat-msg"][data-role="assistant"]').last();
    await expect(answer.locator('strong')).toHaveText(['pkg-reqeusts', 'pipe-to-shell']);
    await expect(answer).toContainText('- pkg-reqeusts 격리됨');
    await expect(answer).not.toContainText('**pkg-reqeusts**');
    await expect(answer.locator('pre, code').first()).toContainText('docker logs **x**'); // 코드 안은 손대지 않는다
  });
});

