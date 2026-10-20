// SupplyGuard 목업 — 우측 하단 AI 도우미 [10/16 챗봇]. 실제 앱: POST /api/chat → 로컬 LLM(Ollama · qwen2.5:3b)이 읽기 전용 조회 도구로 답을 흘려보낸다.
// 목업은 모델 없이, 지금 목업 데이터로 만든 정해진 답을 한 글자씩 흘려보낸다(속도 · 모양 확인용). 대화는 이 탭(sessionStorage)에만 남는다.
// 「관련 화면」 링크 · 판정 상태처럼 틀리면 안 되는 것은 모델이 아니라 서버가 붙인다(실측: 3B 모델이 판정 상태를 지어냄)
(function () {
  'use strict';
  const U = window.UI;
  const { h, state, fmt } = U;
  const KEY = 'supplyguard.chat';
  const LV = { killed: '격리됨', held: '격리 대상', alert: '경고', normal: '정상' };
  const SRC = { install: '설치 검사', runtime: '런타임', scan: '공급망 검사' };
  const SUGGEST = ['판정 대기 요약해 줘', '오늘 가장 많이 걸린 정책은?', '이 화면은 뭘 하는 곳이야?', '최근 공급망 검사 결과 알려 줘'];

  // 모의 서버: 질문 → { text, links } (실제: 도구 호출 → 사실 줄 → 모델 답 + 서버가 붙인 링크)
  function answer(q, page) {
    const open = state.cases.filter((c) => c.state === 'open');
    if (/판정|대기|처리할/.test(q)) {
      if (!open.length) return { text: '지금 판정 대기 건은 없습니다. 새 격리 · 경고가 생기면 대시보드 맨 위에 올라옵니다.', links: [['대시보드', '#/']] };
      const lines = open.slice(0, 3).map((c) => `${SRC[c.source]} ${c.label || c.container}(${LV[c.level]}, 위반 ${c.violations}건 — ${c.ruleIds.slice(0, 2).join(', ')})`);
      return { text: `판정 대기 건이 ${open.length}개 있습니다. ${lines.join(' · ')}. 각 건을 열어 공격 체인을 보고 「악성 확정」 또는 「오탐」으로 판정하세요. 판정하면 정책에서 미리보기 뒤 적용합니다.`,
        links: open.slice(0, 3).map((c) => [`${c.label || c.container} 판정하기`, c.source === 'install' ? `#/installs?id=${c.installId}` : `#/topology?container=${encodeURIComponent(c.container)}`]) };
    }
    const ctr = (q.match(/([a-z0-9][a-z0-9_.-]+)/i) || [])[1];
    if (/격리|왜/.test(q) && ctr) {
      const rows = state.audit.filter((a) => a.event.containerName.includes(ctr)).slice(0, 5);
      if (!rows.length) return { text: `「${ctr}」 에 대한 위반 기록을 찾지 못했습니다. 컨테이너 이름을 확인해 주세요.`, links: [['감사 로그', '#/audit']] };
      const rules = [...new Set(rows.map((a) => a.ruleId))];
      const c = state.cases.find((x) => x.container === rows[0].event.containerName && x.state !== 'closed');
      return { text: `${rows[0].event.containerName} 은(는) ${rules.join(', ')} 정책에 걸려 ${rows.some((a) => a.enforced) ? '격리됐습니다' : '경고가 났습니다'}. 예: ${U.detailOf(rows[0].event)}. ${c ? `지금 ${c.decision === 'pending' ? '판정 대기' : '판정됨'} 상태입니다 — 공격 체인을 보고 판정하세요.` : ''}`,
        links: [['감사 로그에서 보기', `#/audit?container=${encodeURIComponent(rows[0].event.containerName)}`], ['토폴로지', `#/topology?container=${encodeURIComponent(rows[0].event.containerName)}`]] };
    }
    if (/정책|규칙|위반/.test(q)) {
      const o = state.audit.reduce((m, a) => (m.set(a.ruleId, (m.get(a.ruleId) || 0) + 1), m), new Map());
      const top = [...o.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
      return { text: top.length ? `가장 많이 걸린 정책은 ${top.map(([r, n]) => `${r}(${n}건)`).join(', ')} 입니다. 오탐이 많다면 정책 화면에서 예외를 더하고, 저장 전 확인에서 과거 기록이 어떻게 바뀌는지 보세요.` : '아직 걸린 정책이 없습니다.',
        links: top.map(([r]) => [`${r} 정책`, `#/policies?id=${encodeURIComponent(r)}`]) };
    }
    if (/검사|scan|패키지/.test(q)) {
      const sc = state.scans[0];
      if (!sc) return { text: '아직 공급망 검사가 없습니다. 공급망 검사 화면에서 패키지 이름 · 저장소 주소 · 파일로 시작하세요.', links: [['공급망 검사', '#/scans']] };
      return { text: `가장 최근 검사는 ${sc.target.label} 입니다. ${sc.status !== 'done' ? '아직 검사 중입니다.' : `결과는 ${({ malicious: '악성 의심', vulnerable: '취약점 있음', clean: '위협 없음' })[sc.verdict]}${sc.risk ? `(위험 점수 ${sc.risk.score.toFixed(1)})` : ''}, 위협 ${sc.findings.filter((f) => f.category === 'threat').length}곳입니다.`} 위협 줄은 코드 보기에서 빨갛게 보입니다.`,
        links: [['검사 결과 보기', `#/scans?id=${sc.id}`]] };
    }
    const PAGES = { '/': '대시보드는 지금 처리할 일(판정 대기)과 eBPF 수집 종합을 보여 줍니다.', '/installs': '설치 검사는 sg-install 로 감시 컨테이너에서 패키지를 실제 설치해 보며 eBPF 로 행동을 관찰한 결과입니다.',
      '/scans': '공급망 검사는 설치 전에 GuardDog · OSV-Scanner 로 코드와 의존성을 정적 검사합니다.', '/events': '이벤트는 지금 걸리고 있는 위반을 실시간으로 보여 줍니다.', '/topology': '토폴로지는 런타임 컨테이너가 무엇을 실행 · 열기 · 연결했는지 관계로 보여 줍니다.',
      '/policies': '정책은 무엇을 막을지 정하는 곳입니다. 쉬운 설정으로 고치고 저장 전 확인을 거쳐 적용합니다.', '/audit': '감사 로그는 지난 위반과 판정 · 정책 변경 이력입니다.' };
    return { text: `${PAGES[page.path] || 'SupplyGuard 화면입니다.'} 궁금한 컨테이너 · 정책 · 검사 이름을 함께 물어보면 기록을 찾아 답합니다.`, links: [] };
  }

  let msgs = [];
  try { msgs = JSON.parse(sessionStorage.getItem(KEY) || '[]'); } catch { msgs = []; }
  const save = () => { try { sessionStorage.setItem(KEY, JSON.stringify(msgs.slice(-30))); } catch { /* 저장 차단 */ } };
  let busy = false;
  const list = h('div', { class: 'chat-list', 'data-part': 'chat-list', 'aria-live': 'polite' });
  const inp = h('textarea', { class: 'ctl chat-input', rows: 2, placeholder: '예: pkg-reqeusts 는 왜 격리됐어?', 'aria-label': '질문' });
  const send = h('button', { type: 'button', class: 'btn btn-primary btn-xs', 'aria-label': '보내기' }, '보내기');
  const sugg = h('div', { class: 'chat-sugg' }, SUGGEST.map((q) => h('button', { type: 'button', class: 'sugg', onclick: () => ask(q) }, q)));
  const panel = h('section', { class: 'chat-panel', 'data-part': 'chat', role: 'dialog', 'aria-label': 'SupplyGuard 도우미', hidden: true },
    h('header', { class: 'chat-head' }, h('b', null, 'SupplyGuard 도우미'), h('span', { class: 'small muted' }, '로컬 모델 qwen2.5:3b · 데이터는 서버 밖으로 나가지 않음'),
      h('button', { type: 'button', class: 'btn btn-ghost btn-xs push-right', 'aria-label': '대화 지우기', onclick: () => { msgs = []; save(); draw(); } }, '지우기'),
      h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-label': '닫기', onclick: () => toggle(false) }, '✕')),
    list, sugg, h('div', { class: 'chat-form' }, inp, send),
    h('p', { class: 'small muted chat-note' }, '읽기 전용 — 판정 · 정책 변경은 하지 않습니다. 첫 질문은 모델을 불러오느라 1분 넘게 걸릴 수 있습니다.'));
  const fab = h('button', { type: 'button', class: 'chat-fab', 'data-part': 'chat-fab', 'aria-label': 'AI 도우미 열기', onclick: () => toggle(panel.hidden) }, '💬');
  function toggle(on) { panel.hidden = !on; fab.setAttribute('aria-expanded', String(on)); if (on) { draw(); setTimeout(() => inp.focus(), 0); } }
  function draw() {
    list.replaceChildren(...(msgs.length ? msgs : [{ role: 'assistant', text: '무엇이든 물어보세요. 판정 대기 · 위반 기록 · 정책 · 공급망 검사 결과를 찾아 답합니다.', links: [] }]).map((m) =>
      h('div', { class: `chat-msg ${m.role}`, 'data-role': m.role }, h('div', { class: 'bubble' }, m.text || (m.pending ? h('span', { class: 'muted' }, '생각하는 중…') : '')),
        m.links && m.links.length ? h('div', { class: 'chat-links', 'data-part': 'chat-links' }, h('span', { class: 'small muted' }, '관련 화면'), m.links.map(([t, href]) => h('a', { href, class: 'link small' }, t + ' →'))) : null)));
    list.scrollTop = list.scrollHeight;
    sugg.hidden = msgs.length > 0;
    send.disabled = busy;
  }
  function ask(q) {
    q = String(q || inp.value).trim(); if (!q || busy) return;
    inp.value = ''; busy = true;
    const r = U.route();
    msgs.push({ role: 'user', text: q });
    const a = { role: 'assistant', text: '', links: [], pending: true };
    msgs.push(a); draw();
    const full = answer(q, { path: r.path });
    let i = 0;
    setTimeout(function step() { // 실제 앱처럼 조각으로 흘려보낸다(목업: 30자/0.1초)
      a.pending = false; a.text = full.text.slice(0, (i += 30)); draw();
      if (i < full.text.length) return setTimeout(step, 100);
      a.links = full.links; busy = false; save(); draw();
    }, 600);
  }
  send.addEventListener('click', () => ask());
  inp.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); ask(); } });
  const mount = () => { document.body.append(fab, panel); };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount); else mount();
  U.chat = { ask, toggle };
})();
