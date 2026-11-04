// SupplyGuard 목업 — 상태 신호등 [10/30 계약 §5]. 대시보드(screens.js) 머리 줄에 붙는다 — U.signals().
//   (10/30 시연 패널은 11/04e B 에서 대시보드에서 빼고 「시연」 페이지(#/demo — shared/demo-page.js)로 옮겼다)
// 신호등: 알약 5개(가젯 · 도메인 판단 · 자동 격리 · 알림 · 라이선스) 초록 · 노랑 · 빨강 · 회색, 누르면 #/settings(해당 탭). /api/info + GET /api/license(404 = 없음). 시뮬 값은 state.server(info) + ?license=
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, state, fmt } = U;
  // ── 상태 신호등 [10/30 계약 §5] ──
  function signals() {
    const root = h('div', { class: 'signals', 'data-part': 'signals', role: 'group', 'aria-label': '상태 신호등' });
    let lic; // undefined 확인 중 · null 없음(404) · 'unknown' 조회 실패
    const load = () => U.auth.api.getLicense().then((l) => { lic = l; draw(true); }).catch((e) => { lic = e.status === 404 ? null : 'unknown'; draw(true); });
    let sig = '';
    function draw(force) {
      const i = state.info || {}, n = i.notify, A = U.auth;
      // 문구는 React SignalPills.tsx 와 같게(11/02 결정 — 「이름 · 값」 한 문구, 모바일에서도 이름을 숨기지 않는다)
      const g = i.source === 'gadget' ? ['ok', '가젯 · 커널 감시 중'] : i.source === 'mock' ? ['warn', '가젯 · 모의 이벤트'] : ['off', '가젯 · 미확인'];
      const d = i.dnsResolve === 'ok' ? ['ok', '도메인 판단 켜짐'] : i.dnsResolve === 'off' ? ['warn', '도메인 판단 · 통과 처리'] : ['off', '도메인 판단 · 미확인'];
      const k = i.enforceKill === true ? ['ok', '자동 격리 켜짐'] : i.enforceKill === false ? ['warn', '자동 격리 · 알림만'] : ['off', '자동 격리 · 미확인'];
      const nt = !n ? ['off', '알림 · 미확인'] : n.failed > 0 && n.lastError ? ['danger', `알림 · 실패 ${fmt.num(n.failed)}건`] : !n.enabled || !(n.channels || []).length ? ['warn', '알림 · 미설정'] : ['ok', `알림 · 채널 ${n.channels.length}`];
      const lt = lic === undefined || lic === 'unknown' ? ['off', '라이선스 · 미확인'] : lic === null ? ['danger', '라이선스 없음'] : A.licenseTone(lic) === 'danger' ? ['danger', '라이선스 만료'] : [A.licenseTone(lic) === 'warn' ? 'warn' : 'ok', `라이선스 · ${A.daysLeft(lic)}일 남음`];
      const items = [['gadget', g, ''], ['dns', d, ''], ['kill', k, ''], ['notify', nt, ''], ['license', lt, 'license']];
      const next = JSON.stringify(items);
      if (!force && next === sig) return; sig = next;
      replace(root, items.map(([key, [tone, text], tab]) => h('button', { type: 'button', class: `signal tone-${tone}`, 'data-signal': key, 'data-tone': tone, title: `${text} — 설정에서 보기`,
        onclick: () => U.go(`#/settings${tab ? `?tab=${tab}` : ''}`) }, h('i', { class: 'signal-dot', 'aria-hidden': true }), h('span', { class: 'signal-val' }, text))));
    }
    draw(true); load();
    const fn = () => { if (!root.isConnected) { U.listeners.delete(fn); return; } draw(); };
    U.listeners.add(fn);
    return root;
  }

  U.signals = signals;
})();
