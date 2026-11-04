// SupplyGuard 목업 — 건 보고서 1장 [10/30 계약 §5]. 경로 #/report?case=<caseId> | #/report?install=<installId>(주소에는 id 만). 읽기 전용(조회자도 볼 수 있음).
// 진입: 설치 시트(격리 · 경고 세션) 「보고서」 · 토폴로지 판정 카드 「보고서」 · 대시보드 판정 대기 행 메뉴 「보고서」
// 내용(순서 고정): 제목(라벨 · 출처 칩 · 상태) → 요약 3줄(무엇이 · 언제 · 어떤 규칙) → 격리 타임라인 막대 → 위반 표(시각 · 종류 · 규칙 · 상세 · 판정) → 증거 요약 → 판정 → 정책 변경 · 차단 목록 → 작성 시각 · 작성자
// 버튼: 「인쇄」(window.print, @media print 로 A4 1~2장) · 「Markdown 복사」(같은 내용을 Markdown 으로 클립보드)
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, fmt, levelOf, detailOf } = U;
  const LEVEL_TEXT = U.LEVEL_LABEL, DEC = U.DECISION_LABEL;
  const PROP_STATE = { draft: '초안 — 적용 대기', applied: '적용됨', discarded: '버림' };
  const CHANGE_KIND = { proposal_applied: '제안 적용', policy_edit: '정책 편집', policy_replace: '정책 전체 교체', blocklist_remove: '차단 해제', demo_run: '시연 실행' };
  const changeText = (ch) => (ch.op === 'block' ? `${U.LIST_LABEL[ch.list]} 차단 ${ch.value}` : `${ch.ruleId} ${ch.field} += ${ch.value}`);

  async function load(caseId, installId) {
    let s = null, c = null;
    if (installId) { s = await U.api.install(installId); if (s.caseId) c = await U.api.case(s.caseId).catch(() => null); }
    else if (caseId) { c = await U.api.case(caseId); if (c.source === 'install' && c.installId) s = await U.api.install(c.installId).catch(() => null); }
    else throw new Error('주소에 case=<건 id> 또는 install=<설치 세션 id> 가 필요합니다');
    const container = (s && s.container) || (c && c.container) || '';
    let rows = container ? await U.api.audit({ container, limit: 500 }).catch(() => []) : [];
    rows = rows.filter((a) => (c ? a.caseId === c.id : a.install && a.install.id === s.id)).sort((a, b) => Date.parse(a.event.timestamp) - Date.parse(b.event.timestamp));
    const evs = container ? await U.api.evidence(container).catch(() => []) : [];
    const ev = evs.find((x) => s && x.containerId === s.containerId) || evs[0] || null;
    const prop = c && c.proposalId ? await U.api.proposals({}).then((ps) => ps.find((p) => p.id === c.proposalId) || null).catch(() => null) : null;
    const changes = c ? await U.api.changes({ limit: 500 }).then((ch) => ch.filter((x) => x.caseId === c.id)).catch(() => []) : [];
    return { s, c, rows, ev, prop, changes };
  }

  // 보고서 자료 → 화면 · Markdown 이 같은 줄을 쓴다
  function model(d) {
    const { s, c, rows, ev, prop, changes } = d;
    const label = (c && c.label) || (s ? `${s.manager} ${s.packages.join(' ')}` : '—');
    const source = c ? c.source : 'install';
    const level = c ? c.level : rows.map(levelOf).reduce((a, b) => (U.SEV[b] > U.SEV[a] ? b : a), 'normal');
    const status = s ? U.INSTALL_STATUS[s.status] : LEVEL_TEXT[level];
    const first = rows.length ? rows[0].event.timestamp : (c && c.openedAt) || (s && s.startedAt) || null, last = rows.length ? rows[rows.length - 1].event.timestamp : null;
    const ruleIds = c ? c.ruleIds : [...new Set(rows.map((a) => a.ruleId))];
    const tl = (c && c.isolation && c.isolation.timeline) || (s && s.isolation && s.isolation.timeline) || null;
    const what = [source === 'install' ? `설치 검사 ${label}` : source === 'scan' ? `공급망 검사 ${label}` : `런타임 컨테이너 ${label}`, s && s.image ? `이미지 ${s.image}` : c && c.image ? `이미지 ${c.image}` : '', (s && s.container) || (c && c.container) ? `컨테이너 ${(s && s.container) || c.container}` : ''].filter(Boolean).join(' · ');
    const when = first ? `${fmt.dateTime(first)}${last && last !== first ? ` ~ ${fmt.dateTime(last)}` : ''} · 위반 ${fmt.num(rows.length)}건${c ? ` · 건 ${c.id} 열림 ${fmt.dateTime(c.openedAt)}` : ''}` : '위반 없음';
    const rules = ruleIds.length ? ruleIds.join(', ') : '없음';
    const evidence = ev ? { logs: ev.logs ? ev.logs.split('\n').filter(Boolean).length : 0, changes: ev.changes.length, processes: ev.processes.length, partial: !!ev.partial, error: ev.error || '', at: ev.collectedAt, ms: ev.durationMs } : null;
    const decision = c ? { text: DEC[c.decision], by: c.decidedBy, at: c.decidedAt, note: c.note, state: c.state, closedAt: c.closedAt } : null;
    return { label, source, level, status, what, when, rules, tl, rows, evidence, decision, prop, changes, s, c, at: new Date().toISOString(), by: U.actor() };
  }
  const tlMs = (tl) => { const t = (k) => (tl && tl[k] ? Date.parse(tl[k]) : null); const seg = (a, b) => (a != null && b != null && b >= a ? `${b - a} ms` : '—'); return [['탐지→판정', seg(t('detectedAt'), t('matchedAt'))], ['증거', seg(t('evidenceStartedAt'), t('evidenceDoneAt'))], ['격리', seg(t('evidenceDoneAt') != null ? t('evidenceDoneAt') : t('matchedAt'), t('killedAt'))], ['알림', seg(t('killedAt'), t('notifiedAt'))], ['격리까지', t('detectedAt') != null && t('killedAt') != null ? `${((t('killedAt') - t('detectedAt')) / 1000).toFixed(2)}초` : '—']]; };

  function markdown(m) {
    const L = [];
    L.push(`# ${m.label} — ${U.CASE_SOURCE[m.source] || m.source} · ${m.status}`, '');
    L.push('## 요약', `- 무엇이: ${m.what}`, `- 언제: ${m.when}`, `- 어떤 규칙: ${m.rules}`, '');
    L.push('## 격리 타임라인', m.tl ? tlMs(m.tl).map(([k, v]) => `- ${k}: ${v}`).join('\n') : '- 격리되지 않음 (—)', '');
    L.push(`## 위반 ${m.rows.length}건`, '| 시각 | 종류 | 규칙 | 상세 | 판정 |', '| --- | --- | --- | --- | --- |', ...m.rows.map((a) => `| ${fmt.dateTime(a.event.timestamp)} | ${a.event.kind} | ${a.ruleId} | ${detailOf(a.event).replace(/\|/g, '\\|')} | ${LEVEL_TEXT[levelOf(a)]} |`), '');
    L.push('## 증거 요약', m.evidence ? `- 로그 ${m.evidence.logs}줄 · 파일 변경 ${m.evidence.changes} · 프로세스 ${m.evidence.processes}${m.evidence.partial ? ` · 일부만 모음(${m.evidence.error})` : ''} — ${fmt.dateTime(m.evidence.at)} · ${m.evidence.ms}ms` : '- 모은 증거 없음', '');
    L.push('## 판정', m.decision ? `- ${m.decision.text}${m.decision.by ? ` · ${m.decision.by} · ${fmt.dateTime(m.decision.at)}` : ''}${m.decision.note ? ` · 메모 「${m.decision.note}」` : ''}${m.decision.state === 'closed' ? ` · 종결 ${fmt.dateTime(m.decision.closedAt)}` : ''}` : '- 건 없음', '');
    L.push('## 정책 변경 · 차단 목록', m.prop ? [`- 제안 ${m.prop.id} (${PROP_STATE[m.prop.state] || m.prop.state})`, ...(m.prop.changes.length ? m.prop.changes.map((ch) => `  - ${changeText(ch)}`) : ['  - 변경 없음']), ...(m.prop.notes || []).map((n) => `  - 안내: ${n}`)].join('\n') : '- 제안 없음', ...m.changes.map((x) => `- ${fmt.dateTime(x.at)} ${CHANGE_KIND[x.kind] || x.kind} — ${x.summary} (${x.by})${x.reason ? ` · 사유 「${x.reason}」` : ''}`), '');
    L.push(`작성 ${fmt.dateTime(m.at)} · ${m.by}`);
    return L.join('\n');
  }

  function view(m) {
    const sec = (key, title, body) => h('section', { class: 'report-sec', 'data-sec': key }, h('h2', null, title), body);
    return h('article', { class: 'report', 'data-part': 'report', 'data-case': m.c ? m.c.id : '', 'data-install': m.s ? m.s.id : '' },
      h('header', { class: 'report-head' }, h('h1', null, m.label),
        h('div', { class: 'report-chips' }, h('span', { class: `src-chip src-${m.source}` }, U.CASE_SOURCE[m.source] || m.source), m.s ? U.statusBadge(m.s.status) : U.verdictBadge(U.fakeVerdict(m.level)), m.c ? h('span', { class: 'mono small muted' }, `건 ${m.c.id}`) : null, m.s ? h('span', { class: 'mono small muted' }, `세션 ${m.s.id}`) : null)),
      sec('summary', '요약', h('ul', { class: 'report-sum' }, h('li', null, h('span', null, '무엇이'), h('span', null, m.what)), h('li', null, h('span', null, '언제'), h('span', { class: 'num' }, m.when)), h('li', null, h('span', null, '어떤 규칙'), h('span', { class: 'mono' }, m.rules)))),
      sec('timeline', '격리 타임라인', m.tl ? U.timelineBar(m.tl) : h('p', { class: 'small muted' }, '격리되지 않음 — 구간 없음(—)')),
      sec('violations', `위반 ${fmt.num(m.rows.length)}건`, m.rows.length ? h('div', { class: 'grid-scroll report-table' }, h('table', { class: 'table compact' }, h('thead', null, h('tr', null, ['시각', '종류', '규칙', '상세', '판정'].map((t) => h('th', null, t)))),
        h('tbody', null, m.rows.map((a) => h('tr', { 'data-audit': a.id }, h('td', { class: 'num mono nowrap' }, fmt.dateTime(a.event.timestamp)), h('td', null, U.kindBadge(a.event.kind)), h('td', { class: 'mono small' }, a.ruleId), h('td', { class: 'mono small', title: a.reason || '' }, detailOf(a.event)), h('td', null, U.verdictBadge(a))))))) : h('p', { class: 'small muted' }, '없음')),
      sec('evidence', '증거 요약', m.evidence ? h('div', null, h('p', null, `로그 ${fmt.num(m.evidence.logs)}줄 · 파일 변경 ${fmt.num(m.evidence.changes)} · 프로세스 ${fmt.num(m.evidence.processes)}`, h('span', { class: 'small muted' }, ` — ${fmt.dateTime(m.evidence.at)} · ${m.evidence.ms}ms 동안 모음`)),
        m.evidence.partial ? h('p', { class: 'small tone-warn', 'data-part': 'evidence-partial' }, `일부만 모음 — ${m.evidence.error}`) : null) : h('p', { class: 'small muted' }, '모은 증거 없음 — 격리되지 않았거나 dry-run')),
      sec('decision', '판정', m.decision ? h('div', { class: 'row-inline' }, U.decisionBadge(m.c.decision), m.decision.by ? h('span', { class: 'small muted num' }, `${m.decision.by} · ${fmt.dateTime(m.decision.at)}`) : null, m.decision.note ? h('span', { class: 'small' }, `메모 「${m.decision.note}」`) : null, m.decision.state === 'closed' ? h('span', { class: 'small muted' }, `종결 ${fmt.dateTime(m.decision.closedAt)}`) : null) : h('p', { class: 'small muted' }, '건 없음')),
      sec('changes', '정책 변경 · 차단 목록', h('div', { class: 'col-gap' },
        m.prop ? h('div', null, h('p', { class: 'small' }, h('b', null, `제안 ${m.prop.id}`), ` · ${PROP_STATE[m.prop.state] || m.prop.state}`),
          h('ul', { class: 'change-list' }, m.prop.changes.length ? m.prop.changes.map((ch) => h('li', null, h('span', { class: `badge ${ch.op === 'block' ? 'badge-kill' : 'badge-alert'}` }, ch.op === 'block' ? '차단' : '예외'), h('span', { class: 'mono small' }, changeText(ch)))) : h('li', { class: 'small muted' }, '변경 없음')),
          (m.prop.notes || []).length ? h('ul', { class: 'notes small muted' }, m.prop.notes.map((n) => h('li', null, n))) : null) : h('p', { class: 'small muted' }, '제안 없음'),
        m.changes.length ? h('ul', { class: 'report-changes small' }, m.changes.map((x) => h('li', null, h('span', { class: 'num muted' }, fmt.dateTime(x.at)), ' ', h('b', null, CHANGE_KIND[x.kind] || x.kind), ` — ${x.summary} (${x.by})`, x.reason ? ` · 사유 「${x.reason}」` : ''))) : null)),
      h('footer', { class: 'report-meta small muted', 'data-sec': 'meta' }, h('span', null, `작성 ${fmt.dateTime(m.at)}`), h('span', null, `작성자 ${m.by}`)));
  }

  U.screens['/report'] = {
    title: '보고서',
    mount(page, query) {
      const caseId = query.get('case') || '', installId = query.get('install') || '';
      const wrap = h('div', { class: 'report-wrap', 'data-fill': '' }, U.skeleton(8));
      page.append(wrap);
      const back = installId ? h('a', { ...U.to(`#/installs?id=${encodeURIComponent(installId)}`, { status: 'all' }), class: 'btn btn-ghost btn-xs' }, '← 설치 검사') : null;
      load(caseId, installId).then((d) => {
        const m = model(d);
        const md = markdown(m);
        const copyBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': 'copy-md', onclick: () => { const done = () => U.toast('보고서를 Markdown 으로 복사했습니다', { tone: 'ok', key: 'copy', replace: true }); try { navigator.clipboard.writeText(md).then(done, done); } catch { done(); } } }, '⧉ Markdown 복사');
        const printBtn = h('button', { type: 'button', class: 'btn btn-primary btn-xs', 'data-action': 'print', onclick: () => window.print() }, '🖨 인쇄');
        const src = m.c ? h('a', { ...U.to(U.caseLink(m.c, true)), class: 'btn btn-ghost btn-xs' }, m.c.source === 'runtime' ? '← 토폴로지' : m.c.source === 'scan' ? '← 공급망 검사' : '← 설치 검사') : back;
        U.headerActions(src, copyBtn, printBtn);
        replace(wrap, view(m));
        wrap.dataset.markdown = md; // 회귀 · 복사 확인용
      }).catch((e) => replace(wrap, U.errorState(e, () => U.remount(), { what: '보고서', auto: false })));
      return {};
    },
  };
  U.reportMarkdown = (d) => markdown(model(d));
})();
