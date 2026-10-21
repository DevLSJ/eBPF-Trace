// SupplyGuard 목업 — 정책 「쉬운 설정」 [10/16 정책 개편]. 처음 쓰는 사람도 정책을 세부적으로 고칠 수 있게
// ① 무엇을 ② 어떤 값(칩, 바로 형식 검사) ③ 걸리면 ④ 어디에 ⑤ 이름 + 한 줄 요약. 고급(폼 · YAML)과 같은 draft 를 고친다.
// draft = { id, description, kind, action, dryRun, disabled, lists: { <필드>: '한 줄에 하나' } } — screens.js ruleEditor 와 같은 모양
// 이식 단위: React 의 정책 편집 「쉬운 설정」 탭(PolicyEasy) · 템플릿(POLICY_TEMPLATES) · 요약(summarizeRule) · 값 분류(classifyValue)
(function () {
  'use strict';
  const U = window.UI;
  const { h, state, fmt, replace } = U;

  const SANDBOX_SCOPE = 'sg-install-*';
  const listOf = (d, f) => (d.lists[f] || '').split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
  const setList = (d, f, xs) => { d.lists[f] = xs.join('\n'); };

  // ── 값 분류 · 형식 검사 — 칩 하나 = 값 하나. { type, field } 또는 { error } ──
  const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/;
  const IPV6 = /^[0-9a-f:]+:[0-9a-f:]*(\/\d{1,3})?$/i;
  const HOST = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i;
  function classifyConnect(v) {
    if (/^\d+$/.test(v)) { const n = Number(v); return n >= 1 && n <= 65535 ? { type: 'port' } : { error: '포트는 1~65535 사이 숫자로 써 주세요' }; }
    const m = v.match(IPV4);
    if (m) { if ([1, 2, 3, 4].some((i) => Number(m[i]) > 255) || (m[6] && Number(m[6]) > 32)) return { error: 'IP는 0~255 네 덩어리, 대역은 /0~/32 로 써 주세요(예: 10.0.0.0/8)' }; return { type: 'cidr' }; }
    if (IPV6.test(v)) return { type: 'cidr' };
    if (HOST.test(v)) return { type: 'host' };
    return { error: '포트(예: 443) · IP나 대역(예: 10.0.0.0/8) · 도메인(예: pypi.org) 중 하나로 써 주세요' };
  }
  const classifyPath = (v) => (v.startsWith('/') ? { type: 'path' } : { error: '/ 로 시작하는 전체 경로로 써 주세요(예: /root/.ssh/)' });
  const classifyExec = (v) => (/[\s|;&>]/.test(v) ? { type: 'args' } : /^[\w.+-]{1,64}$/.test(v) ? { type: 'prog' } : { error: '프로그램 이름(예: curl)이나 명령에 들어갈 글자(예: | sh)로 써 주세요' });
  const classifyName = (v) => (/^[\w.*?\[\]:/-]+$/.test(v) ? { type: 'name' } : { error: '컨테이너 이름이나 이미지 패턴으로 써 주세요(예: pkg-*)' });

  // 칩 그룹 정의: 종류별로 「막을 값」(block) · 「허용 · 예외」(allow). type → 저장 필드
  const GROUPS = {
    open: {
      block: { label: '막을 파일 · 폴더', hint: '폴더는 끝에 / (예: /root/.ssh/), * 로 여러 개(예: /home/*/.ssh/*)', classify: classifyPath, fields: { path: 'denyPaths' }, suggest: ['/etc/shadow', '/root/.ssh/', '/home/*/.ssh/*', '/root/.aws/credentials'] },
      allow: { label: '예외 — 열어도 되는 파일', hint: '막을 목록보다 먼저 봅니다', classify: classifyPath, fields: { path: 'allowPaths' }, suggest: [] },
    },
    exec: {
      block: { label: '막을 프로그램 · 명령 모양', hint: '프로그램 이름(curl) 또는 명령에 들어간 글자(| sh)', classify: classifyExec, fields: { prog: 'denyComms', args: 'denyArgs' }, suggest: ['curl', 'wget', 'nc', '| sh', '| bash', 'base64 -d'] },
    },
    connect: {
      block: { label: '항상 막을 곳', hint: '포트 · IP나 대역 · 도메인. 허용 목록과 상관없이 위반', classify: classifyConnect, fields: { port: 'denyPorts', cidr: 'denyCidrs', host: 'denyHosts' }, suggest: ['4444', '1337', '31337'] },
      allow: { label: '허용할 곳', hint: '하나라도 넣으면 여기 없는 곳으로 가는 연결은 모두 위반', classify: classifyConnect, fields: { port: 'allowPorts', cidr: 'allowCidrs', host: 'allowHosts' }, suggest: ['443', '80', '53', '10.0.0.0/8', 'pypi.org', 'registry.npmjs.org'] },
    },
  };
  const TYPE_LABEL = { port: '포트', cidr: '대역', host: '도메인', path: '경로', prog: '프로그램', args: '명령', name: '이름' };
  const KIND_TEXT = { open: ['파일 열기', '어떤 파일 · 폴더를 여는지 봅니다'], exec: ['프로그램 실행', '어떤 프로그램 · 명령을 실행하는지 봅니다'], connect: ['외부 통신', '어디로 연결하는지 봅니다'] };
  const ACT_TEXT = { alert: ['알림만 보내기', '컨테이너는 그대로 두고 알립니다'], kill: ['즉시 격리', '컨테이너를 바로 멈춥니다'], dry: ['시험 운영', '격리 대상으로 표시만 하고 멈추지 않습니다 — 새 정책을 먼저 써 볼 때'] };

  const chipsOf = (d, g) => Object.entries(g.fields).flatMap(([type, f]) => listOf(d, f).map((value) => ({ type, value, field: f })));
  const actOf = (d) => (d.action === 'kill' ? (d.dryRun ? 'dry' : 'kill') : 'alert');
  const scopeOf = (d) => { const cs = listOf(d, 'containers'); return !cs.length ? 'all' : cs.every((c) => c === SANDBOX_SCOPE) ? 'sandbox' : 'some'; };

  // ── 한 줄 요약 ──
  const fmtConn = (xs) => xs.map((c) => (c.type === 'port' ? `포트 ${c.value}` : c.value)).join(' · ');
  function summarize(d) {
    const scope = { all: '모든 컨테이너에서', sandbox: '설치 검사 컨테이너에서', some: `${listOf(d, 'containers').join(', ')} 컨테이너에서` }[scopeOf(d)];
    const act = { alert: '알림을 보냅니다', kill: '즉시 격리합니다', dry: '격리 대상으로 표시만 합니다(시험 운영)' }[actOf(d)];
    const g = GROUPS[d.kind];
    const block = chipsOf(d, g.block), allow = g.allow ? chipsOf(d, g.allow) : [];
    let what;
    if (d.kind === 'open') what = block.length ? `${block.map((c) => c.value).join(', ')} 를 열면${allow.length ? ` (예외: ${allow.map((c) => c.value).join(', ')})` : ''}` : null;
    else if (d.kind === 'exec') {
      const p = block.filter((c) => c.type === 'prog').map((c) => c.value), a = block.filter((c) => c.type === 'args').map((c) => `「${c.value}」`);
      what = p.length || a.length ? [p.length ? `${p.join(', ')} 를 실행하거나` : '', a.length ? `${a.join(', ')} 가 든 명령을 실행하면` : ''].filter(Boolean).join(' ').replace(/하거나$/, '하면') : null;
    } else {
      const parts = [block.length ? `${fmtConn(block)} 에 연결하${allow.length ? '거나' : '면'}` : '', allow.length ? `허용한 곳(${fmtConn(allow)}) 밖으로 연결하면` : ''].filter(Boolean);
      what = parts.length ? parts.join(', ') : null;
    }
    const s = what ? `${scope} ${what} ${act}.` : '② 에 값을 넣으면 이 정책이 무엇을 하는지 여기에 보입니다.';
    return d.disabled ? `[꺼짐] ${s}` : s;
  }

  // ── 목적별 템플릿 ──
  const TEMPLATES = [
    { key: 'protect-secrets', title: '비밀 파일 보호', desc: '계정 · SSH 키 · 클라우드 자격 증명 파일을 열면 격리', rule: { id: 'protect-secrets', description: '비밀 파일 보호', kind: 'open', action: 'kill', denyPaths: ['/etc/shadow', '/root/.ssh/', '/home/*/.ssh/*', '/root/.aws/credentials'] } },
    { key: 'no-downloader', title: '내려받기 도구 실행 차단', desc: 'curl · wget · nc 로 무언가를 받아 오면 격리', rule: { id: 'no-downloader', description: '내려받기 도구 실행 차단', kind: 'exec', action: 'kill', denyComms: ['curl', 'wget', 'nc'] } },
    { key: 'pipe-shell', title: '받은 스크립트 바로 실행 차단', desc: '「| sh」 처럼 받은 내용을 바로 셸로 넘기면 격리', rule: { id: 'no-pipe-shell', description: '받은 스크립트 바로 실행 차단', kind: 'exec', action: 'kill', denyArgs: ['| sh', '| bash'] } },
    { key: 'reverse-shell', title: '리버스 셸 포트 차단', desc: '공격자가 흔히 쓰는 포트로 연결하면 격리', rule: { id: 'block-reverse-shell', description: '리버스 셸 포트 차단', kind: 'connect', action: 'kill', denyPorts: [4444, 1337, 31337] } },
    { key: 'egress-allow', title: '허용한 곳만 통신', desc: '웹 · DNS 포트와 내부망이 아닌 연결을 알림', rule: { id: 'egress-allow', description: '허용한 곳만 통신', kind: 'connect', action: 'alert', allowPorts: [80, 443, 53], allowCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] } },
    { key: 'install-registry', title: '설치 중엔 패키지 저장소만', desc: '설치 검사에서 pypi · npm · crates 밖으로 연결하면 격리', rule: { id: 'install-registry-only', description: '설치 중엔 패키지 저장소만', kind: 'connect', action: 'kill', containers: [SANDBOX_SCOPE], allowHosts: ['pypi.org', 'pythonhosted.org', 'registry.npmjs.org', 'crates.io', 'github.com'] } },
    { key: 'blank', title: '빈 정책에서 시작', desc: '무엇을 · 어떤 값을 직접 고릅니다', rule: { id: 'new-policy', description: '', kind: 'open', action: 'alert' } },
  ];
  // 이미 있는 id 면 뒤에 -2, -3 …
  function uniqueId(base) { let id = base, n = 2; while (state.rules.some((r) => r.id === id)) id = `${base}-${n++}`; return id; }
  function fromTemplate(key) { const t = TEMPLATES.find((x) => x.key === key) || TEMPLATES[TEMPLATES.length - 1]; return Object.assign(JSON.parse(JSON.stringify(t.rule)), { id: uniqueId(t.rule.id) }); }

  // ── 이벤트 · 감사 행에서 시작 ──
  // 막기: 그 행동을 막는 새 정책 / 허용: 걸린 정책에 가장 좁은 예외(오탐 제안과 같은 규칙 — 통신은 정책에 원래 허용 도메인이 있으면 도메인, 아니면 IP/32)
  function blockLink(e) {
    const value = e.kind === 'open' ? e.path : e.kind === 'exec' ? e.comm : e.dstHost || e.dstIp;
    return value ? { href: '#/policies?id=__new__', state: { intent: 'block', kind: e.kind, value } } : null; // 미리 채우기는 상태로 [10/21b]
  }
  function allowLink(ruleId, e) {
    const r = state.rules.find((x) => x.id === ruleId);
    if (!r || r.kind === 'exec' || ruleId === window.MOCK.SYSTEM_RULE) return null;
    const value = e.kind === 'open' ? e.path : e.dstHost && (r.allowHosts || []).length ? e.dstHost : `${e.dstIp}/32`;
    return value ? { href: `#/policies?id=${encodeURIComponent(ruleId)}`, state: { intent: 'allow', value } } : null;
  }
  function ruleFromBlock(kind, value) {
    const base = { open: { id: 'block-file', denyPaths: [value] }, exec: { id: 'block-program', denyComms: [value] }, connect: { id: 'block-destination' } }[kind];
    const r = Object.assign({ description: `${value} 막기`, kind, action: 'kill' }, base, { id: uniqueId(base.id) });
    if (kind === 'connect') { const c = classifyConnect(value); r[c.type === 'host' ? 'denyHosts' : 'denyCidrs'] = [c.type === 'host' ? value : value.includes('/') ? value : `${value}/32`]; }
    return r;
  }
  // 허용 값을 정책의 알맞은 예외 필드에 더한 사본과 그 값
  function ruleWithAllow(rule, value) {
    const g = GROUPS[rule.kind].allow; if (!g) return { rule, fresh: null };
    const c = g.classify(value); if (c.error) return { rule, fresh: null };
    const f = g.fields[c.type], r = JSON.parse(JSON.stringify(rule)), v = f.endsWith('Ports') ? Number(value) : value;
    if (!(r[f] || []).includes(v)) r[f] = [...(r[f] || []), v];
    return { rule: r, fresh: String(value), field: f };
  }

  // ── 그리기 ── ctx: { isNew, onChange(): 요약만 다시, rerender(): 전체 다시, fresh: Set(새로 더한 값 — 강조) }
  function render(d, ctx) {
    const changed = () => ctx.onChange();
    const step = (key, n, title, ...body) => h('section', { class: 'easy-step', 'data-step': key }, h('h3', null, h('span', { class: 'step-n' }, n), title), ...body);
    const radios = (name, opts, cur, onPick) => h('div', { class: 'easy-radios', role: 'radiogroup' }, opts.map(([v, [label, sub]]) =>
      h('label', { class: `easy-radio ${cur === v ? 'on' : ''}` }, h('input', { type: 'radio', name, value: v, checked: cur === v, onchange: () => onPick(v) }), h('span', null, h('b', null, label), h('small', { class: 'muted' }, sub)))));

    function chipGroup(key, g) {
      const err = h('p', { class: 'chip-error', 'data-chip-error': '', hidden: true });
      const input = h('input', { class: 'ctl chip-input', placeholder: '입력 후 Enter', 'aria-label': g.label });
      const add = (raw) => {
        const v = String(raw).trim(); if (!v) return;
        const c = g.classify(v);
        if (c.error) { err.textContent = `「${v}」 — ${c.error}`; err.hidden = false; return; }
        const f = g.fields[c.type]; const xs = listOf(d, f);
        if (!xs.includes(v)) setList(d, f, [...xs, v]);
        ctx.focus = key; ctx.rerender();
      };
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(input.value); } });
      const cur = chipsOf(d, g);
      const sugg = g.suggest.filter((s) => !cur.some((c) => c.value === s));
      const box = h('div', { class: 'chip-group', 'data-chips': key },
        h('div', { class: 'chip-label' }, h('b', null, g.label), h('small', { class: 'muted' }, ' ', g.hint)),
        h('div', { class: 'chip-box' }, cur.map((c) => h('span', { class: `vchip t-${c.type}`, 'data-chip': '', 'data-type': c.type, 'data-value': c.value, 'data-new': ctx.fresh && ctx.fresh.has(`${c.field}:${c.value}`) ? '' : null },
          h('small', null, TYPE_LABEL[c.type]), h('span', { class: 'mono' }, c.value),
          h('button', { type: 'button', 'aria-label': `${c.value} 빼기`, onclick: () => { setList(d, c.field, listOf(d, c.field).filter((x) => x !== c.value)); ctx.focus = key; ctx.rerender(); } }, '×'))), input),
        err,
        sugg.length ? h('div', { class: 'chip-sugg' }, h('small', { class: 'muted' }, '자주 쓰는 값'), sugg.map((s) => h('button', { type: 'button', class: 'sugg', onclick: () => add(s) }, `+ ${s}`))) : null);
      if (ctx.focus === key) setTimeout(() => input.focus(), 0);
      return box;
    }

    const g = GROUPS[d.kind];
    const scope = scopeOf(d);
    const idInput = h('input', { class: 'ctl mono', 'data-field': 'id', value: d.id, disabled: !ctx.isNew, 'aria-label': '정책 이름(영문)', oninput: (e) => { d.id = e.target.value.trim(); idErr.hidden = /^[a-z0-9][a-z0-9-]*$/.test(d.id); changed(); } });
    const idErr = h('p', { class: 'chip-error', hidden: /^[a-z0-9][a-z0-9-]*$/.test(d.id || '') }, '영문 소문자 · 숫자 · 하이픈(-)만 쓸 수 있습니다');
    return h('div', { class: 'easy' },
      step('what', '1', '무엇을 감시할까요?', radios('easy-kind', Object.entries(KIND_TEXT), d.kind, (v) => { d.kind = v; ctx.rerender(); })),
      step('values', '2', d.kind === 'open' ? '어떤 파일인가요?' : d.kind === 'exec' ? '어떤 프로그램 · 명령인가요?' : '어디로 가는 연결인가요?',
        chipGroup('block', g.block), g.allow ? chipGroup('allow', g.allow) : h('p', { class: 'small muted' }, '실행 정책에는 예외 목록이 없습니다 — 예외가 필요하면 ④ 에서 적용할 컨테이너를 좁히세요.')),
      step('action', '3', '걸리면 어떻게 할까요?', radios('easy-act', Object.entries(ACT_TEXT), actOf(d), (v) => { d.action = v === 'alert' ? 'alert' : 'kill'; d.dryRun = v === 'dry'; ctx.rerender(); }),
        state.info.enforceKill === false ? h('p', { class: 'note-box' }, '지금 서버의 자동 격리가 꺼져 있어 「즉시 격리」도 알림만 갑니다 — ', h('a', { href: '#/settings', class: 'link' }, '설정 › 서버 설정'), ' 참고') : null),
      step('scope', '4', '어디에 적용할까요?', radios('easy-scope', [['all', ['모든 컨테이너', '운영 중인 컨테이너와 설치 검사 모두']], ['sandbox', ['설치 검사에서만', '패키지를 시험 설치하는 감시 컨테이너']], ['some', ['지정한 컨테이너만', '이름이나 이미지 패턴으로 고릅니다']]], scope, (v) => {
        setList(d, 'containers', v === 'all' ? [] : v === 'sandbox' ? [SANDBOX_SCOPE] : listOf(d, 'containers').filter((c) => c !== SANDBOX_SCOPE)); ctx.forceSome = v === 'some'; ctx.rerender(); }),
        scope === 'some' || ctx.forceSome ? chipGroup('containers', { label: '컨테이너', hint: '이름 또는 패턴(예: pkg-*)', classify: classifyName, fields: { name: 'containers' }, suggest: [] }) : null),
      step('name', '5', '이름을 붙여 주세요',
        h('label', { class: 'field' }, h('span', null, h('b', null, '설명'), h('small', { class: 'muted' }, ' 목록에 보이는 한 줄')), h('input', { class: 'ctl', 'data-field': 'description', value: d.description, placeholder: '예: 리버스 셸 포트 차단', oninput: (e) => { d.description = e.target.value; changed(); } })),
        h('label', { class: 'field' }, h('span', null, h('b', null, '정책 이름(영문)'), h('small', { class: 'muted' }, ctx.isNew ? ' 만든 뒤에는 바꿀 수 없습니다' : ' 바꿀 수 없음')), idInput), idErr,
        h('label', { class: 'row-inline' }, U.switchEl(!d.disabled, (on) => { d.disabled = !on; ctx.rerender(); }), ' 이 정책 사용')));
  }

  // 서버 설정 — 보기만. 바꾸는 방법은 서버 설정(.env) + 재시작 [10/16 확정: 화면에서 바꾸지 않음]
  // 서버 설정 보기 — 10/20 H: 알림(웹훅 · Slack 채널 · 보낸/실패 · 마지막 오류 · 테스트 발송) · 컨테이너 발견 방식 · 도메인 판단을 더했다(모두 /api/info)
  // 10/20 결정 2: 「설정」 화면의 서버 설정 탭에 그대로 들어간다(onClose 없음 = 화면 안 칸, 닫기 버튼 없음). 정책 화면의 떠 있는 칸은 없앴다
  function serverSettings(onClose) {
    const root = h('div', { class: `card server-settings ${onClose ? '' : 'inline'}`, 'data-part': 'server-settings', role: onClose ? 'dialog' : 'region', 'aria-label': '서버 설정' });
    let testing = false, testMsg = '';
    const row = (key, label, value, env, desc, extra) => h('div', { class: 'ss-row', 'data-ss': key }, h('div', null, h('b', null, label), h('div', { class: 'small muted' }, desc)), h('div', { class: 'ss-val' }, h('span', null, value), env ? h('code', { class: 'small' }, env) : null, extra || null));
    function notifyRow(n) {
      if (!n) return row('notify', '알림', '미확인', 'NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL', '백엔드가 알림 상태를 알려 주지 않습니다(옛 버전)');
      if (!n.enabled) return row('notify', '알림', '꺼짐 — 채널 없음', 'NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL', '격리 · 판정 대기를 밖으로 알리려면 웹훅이나 Slack 주소를 설정하세요');
      const chs = h('ul', { class: 'ss-channels' }, n.channels.map((c) => h('li', { 'data-channel': c.name }, h('b', null, c.name === 'slack' ? 'Slack' : '웹훅'), ' ', h('span', { class: 'mono' }, c.host),
        h('span', { class: 'small muted num' }, ` · 보냄 ${fmt.num(c.sent)} · 실패 `, h('b', { class: c.failed ? 'tone-danger' : '' }, fmt.num(c.failed)), c.lastAt ? ` · 마지막 성공 ${fmt.dateTime(c.lastAt)}` : ''),
        c.lastError ? h('div', { class: 'small tone-danger' }, `마지막 오류: ${c.lastError}`) : null)));
      const test = U.can() ? h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': 'notify-test', onclick: () => {
        if (testing) return; testing = true; testMsg = '보내는 중…'; draw();
        U.api.notifyTest().then(() => new Promise((r) => setTimeout(r, 1500))).then(() => U.api.info()).then(() => { testMsg = '보냈습니다 — 채널의 보냄 · 실패 수를 확인하세요'; })
          .catch((e) => { testMsg = `보내지 못했습니다 — ${e.message}`; }).finally(() => { testing = false; draw(); });
      } }, '✉ 테스트 발송') : null;
      return row('notify', '알림', h('span', null, '합계 보냄 ', h('b', { class: 'num', 'data-notify-sent': '' }, String(n.sent)), ' · 실패 ', h('b', { class: `num ${n.failed ? 'tone-danger' : ''}`, 'data-notify-failed': '' }, String(n.failed)), n.suppressed ? h('span', { class: 'small muted' }, ` · 묶어서 줄임 ${fmt.num(n.suppressed)}`) : null),
        'NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL', '격리 · 판정 대기를 밖으로 알린다. 호스트만 보입니다(토큰 · 경로는 숨김)',
        h('div', { class: 'ss-extra' }, chs, test, testMsg ? h('span', { class: 'small muted', role: 'status' }, testMsg) : null));
    }
    function draw() {
      const i = state.info, watch = i.watchContainers || [], ignore = i.ignoreContainers || [];
      const disc = i.discovery, dns = i.dnsResolve;
      replace(root,
        h('div', { class: 'card-head' }, h('b', null, '서버 설정'), onClose ? h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'aria-label': '닫기', onclick: onClose }, '✕') : h('span', { class: 'small muted' }, '보기만 — GET /api/info')),
        row('enforce', '자동 격리', i.enforceKill ? '켜짐' : '꺼짐 (알림만)', 'ENFORCE_KILL', i.enforceKill ? '「즉시 격리」 정책에 걸리면 컨테이너를 멈춥니다' : '모든 정책이 알림만 보냅니다'),
        row('watch', '감시 범위', watch.length ? watch.join(', ') : '모든 컨테이너', 'WATCH_CONTAINERS', '이 범위의 컨테이너만 평가 · 격리합니다'),
        row('ignore', '제외', ignore.length ? ignore.join(', ') : '없음', 'IGNORE_CONTAINERS', 'SupplyGuard 자신처럼 보지 않을 컨테이너'),
        row('discovery', '컨테이너 발견 방식', disc === 'fanotify' ? 'fanotify — 시작 순간부터 추적' : disc === 'docker-events' ? 'docker-events' : '미확인', 'CONTAINER_DISCOVERY', disc === 'docker-events' ? (i.discoveryNote || '컨테이너 시작 직후 약 0.1초 안의 동작은 놓칠 수 있습니다') : disc === 'fanotify' ? '컨테이너 런타임을 커널에서 바로 봅니다' : '가젯이 아직 시작되지 않았거나 mock 소스입니다'),
        row('dns', '도메인 판단', dns === 'off' ? h('span', { class: 'tone-warn' }, '꺼짐 — 도메인 규칙 통과') : dns === 'ok' ? '켜짐 (trace_dns)' : '미확인', '', dns === 'off' ? 'trace_dns 가 뜨지 않아 allowHosts · denyHosts · 차단 도메인이 통과 처리됩니다. IP · 포트 규칙만 동작합니다' : '같은 컨테이너의 DNS 응답으로 목적지 도메인을 알아냅니다. 도메인 없이 IP 로 바로 붙으면 「직접 IP 연결」로 봅니다'),
        notifyRow(i.notify),
        h('p', { class: 'small muted ss-how' }, '바꾸는 방법: 서버의 .env 에서 위 값을 고친 뒤 백엔드를 다시 시작하세요. 화면에서는 바꾸지 않습니다 — 범위를 잘못 넓히면 다른 컨테이너가 격리될 수 있습니다.'));
    }
    draw();
    return root;
  }

  U.policyEasy = { render, summarize, TEMPLATES, fromTemplate, ruleFromBlock, ruleWithAllow, blockLink, allowLink, serverSettings, classifyConnect, KIND_TEXT };
})();
