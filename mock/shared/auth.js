// SupplyGuard 목업 — 로그인 · 라이선스 · OTP · 계정 [10/20 2차 시안 A]
// 계약: backend/internal/api/auth.go · model/user.go (쿠키 세션, 단계 need_password → need_license → need_otp_enroll | need_otp → active)
//   POST /api/auth/login {username, password} → {state, user}        GET  /api/auth/me → {state, user, mustChangePassword, license, otpRequired}
//   POST /api/auth/password {current, next} → {state}                 POST /api/auth/license {key} → {state, license}
//   POST /api/auth/otp/enroll → {secret, uri}                         POST /api/auth/otp/enroll/confirm {code} → {state, recoveryCodes[10]}
//   POST /api/auth/otp {code} | {recovery} → {state}                  POST /api/auth/logout → 204
//   GET  /api/license → License | 404                                 GET/POST /api/users · PATCH /api/users/{id} · POST …/reset-password → {tempPassword} · POST …/reset-otp → 204
//   오류: {error, state?} — 로그인 실패 문구는 아이디가 있든 없든 같다. 조회자는 라이선스가 없으면 403 「관리자가 먼저 라이선스를 등록해야 합니다」
//   비밀번호: 5자 이상 · 아이디와 다르게 [10/20 결정 변경 — 10자 → 5자]
//   인증 감사 [10/21 서버 기준 — model.AuthAudit]: GET /api/auth/audit?limit&before=<id>&action&failed=1 → [{id, at, actor, action, target, ip, ok, detail}] (관리자만, 최신순 · 다음 쪽은 마지막 행 id 를 before 로)
//     action 13개: login · login_lock · logout · password_change · license_register · license_renew · otp_enroll · otp_verify · otp_recovery · user_create · user_update · user_reset_password · user_reset_otp
//     성공 · 실패는 ok(로그인 실패 = action login + ok false). system 은 action 이 아니라 actor(초기 관리자 생성). 잘못된 action · before 는 400
// 시뮬레이션: 아래 모의 서버가 같은 단계 · 문구를 흉내 낸다. 목업 전용 단순화(README) — OTP 는 「000000 만 틀림」, 복구 코드는 XXXX-XXXX 형식이면 한 번 통과
// 실제 백엔드: fetch credentials: 'include'(쿠키). 목업과 백엔드를 같은 호스트 이름(127.0.0.1)으로 열어야 쿠키가 붙는다
(function () {
  'use strict';
  const U = window.UI;
  const { h, replace, state, fmt } = U;
  const params = new URLSearchParams(location.search);
  const DAY = 86400e3;
  const DEMO_PW = 'demo-pass-1234'; // 목업 전용 가짜 값(README) — 실제 비밀번호가 아니다
  const ROLE_KO = { admin: '관리자', viewer: '조회자' };
  const MSG = {
    login: '로그인이 필요합니다', badCreds: '아이디 또는 비밀번호가 올바르지 않습니다. 5번 연속 틀리면 5분 동안 로그인할 수 없습니다',
    viewerNoLic: '관리자가 먼저 라이선스를 등록해야 합니다', wrongStep: '지금 로그인 단계에서 할 수 없는 요청입니다', badOTP: 'OTP 코드가 올바르지 않습니다',
    badRecovery: '복구 코드가 올바르지 않거나 이미 사용되었습니다', otpRestart: 'OTP 를 여러 번 틀려 로그인을 처음부터 다시 해야 합니다', adminOnly: '관리자 권한이 필요합니다',
    lastAdmin: '마지막 관리자는 강등하거나 비활성화할 수 없습니다', selfDisable: '자기 자신은 비활성화할 수 없습니다', dupUser: '이미 있는 아이디입니다', enrollFirst: '먼저 OTP 등록을 시작하세요',
    badCurrent: '현재 비밀번호가 올바르지 않습니다', samePW: '새 비밀번호는 지금 비밀번호와 달라야 합니다', badKey: '라이선스 키 형식이 아닙니다(숫자 16자리, XXXX-XXXX-XXXX-XXXX)',
  };
  const err = (status, msg, st) => Object.assign(new Error(msg), { status, authState: st || '' });
  const PW_MIN = 5; // 10/20 결정 변경: 10자 → 5자
  const validatePassword = (username, pw) => { if ([...pw].length < PW_MIN) return `비밀번호는 ${PW_MIN}자 이상이어야 합니다`; if (pw.trim().toLowerCase() === String(username).trim().toLowerCase()) return '비밀번호는 아이디와 달라야 합니다'; return ''; };
  const CODE_ABC = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ', TEMP_ABC = CODE_ABC + 'abcdefghijkmnpqrstuvwxyz', B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const rand = (abc, n) => { const a = new Uint32Array(n); crypto.getRandomValues(a); return [...a].map((x) => abc[x % abc.length]).join(''); };

  // ── 모의 인증 서버 (sim) ───────────────────────────────
  const fresh = params.get('auth') === 'fresh';
  const t0 = Date.now();
  const mkUser = (id, username, displayName, role, o) => Object.assign({ id, username, displayName, role, pw: DEMO_PW, mustChangePassword: false, otpEnabled: true, disabled: false, failed: 0, lockedUntil: 0, createdAt: new Date(t0 - 30 * DAY).toISOString(), lastLoginAt: new Date(t0 - DAY).toISOString() }, o || {});
  const sim = {
    users: [mkUser('u-0001', 'admin', '보안 담당자', 'admin', fresh ? { mustChangePassword: true, otpEnabled: false, lastLoginAt: null } : null),
      mkUser('u-0002', 'viewer', '조회 담당자', 'viewer', fresh ? { mustChangePassword: true, otpEnabled: false, lastLoginAt: null } : null)],
    // ?license=soon(20일 남음 — 칩 노랑) · ?license=expired(이틀 전 만료 — 칩 빨강) [10/20 결정 3]
    license: fresh ? null : { keyMasked: '****-****-****-2026', kind: 'trial', issuedAt: new Date(t0 - 165 * DAY).toISOString(), expiresAt: new Date(t0 + ({ soon: 20, expired: -2 }[params.get('license')] || 200) * DAY - 3600e3).toISOString(), registeredBy: 'admin' },
    session: null, // { userId, state, otpPending, otpFailures }
    used: new Set(), seq: 2,
    log: [], logSeq: 0, // 인증 감사 [10/20 결정 2] — 모의 데이터(시드) + 이 탭에서 한 로그인 · 계정 변경
  };
  // 인증 감사 기록 — IP 는 문서용 주소(TEST-NET, 실데이터 아님). 이 브라우저에서 한 일은 192.0.2.15
  const HERE = '192.0.2.15';
  const AUTH_ACTIONS = ['login', 'login_lock', 'logout', 'password_change', 'license_register', 'license_renew', 'otp_enroll', 'otp_verify', 'otp_recovery', 'user_create', 'user_update', 'user_reset_password', 'user_reset_otp'];
  // 서버(auth/service.go)가 남기는 것과 같은 모양 — actor(한 계정) · action · target(대상 계정 · 키) · ok · detail
  const audit = (action, actor, target, ok, detail, o) => { sim.log.unshift(Object.assign({ id: ++sim.logSeq, at: new Date().toISOString(), actor, action, target: target || '', ip: HERE, ok, detail: detail || '' }, o || {})); };
  // 시드: [시각, action, actor, target, ok, ip, detail] — 오래된 것부터(id 오름차순)
  [[-30 * DAY, 'user_create', 'system', 'admin', true, '', '초기 관리자'], [-6 * DAY, 'login', 'admin', '', true, '192.0.2.10', '다음 단계: active'], [-5 * DAY, 'user_create', 'admin', 'viewer', true, '192.0.2.10', '역할 viewer'],
    [-5 * DAY + 600e3, 'login', 'viewer', '', true, '198.51.100.23', '다음 단계: active'],
    [-3 * DAY, 'login', 'root', '', false, '203.0.113.77', '아이디 또는 비밀번호 틀림'], [-3 * DAY + 20e3, 'login', 'root', '', false, '203.0.113.77', '아이디 또는 비밀번호 틀림'], [-3 * DAY + 40e3, 'login', 'admin', '', false, '203.0.113.77', '아이디 또는 비밀번호 틀림'],
    [-2 * DAY, 'otp_verify', 'viewer', 'viewer', false, '198.51.100.23', ''], [-2 * DAY + 30e3, 'login', 'viewer', '', true, '198.51.100.23', '다음 단계: active'], [-DAY, 'otp_recovery', 'admin', 'admin', true, '192.0.2.10', '복구 코드 사용'], [-DAY + 60e3, 'login', 'admin', '', true, '192.0.2.10', '다음 단계: active']]
    .forEach(([dt, action, actor, target, ok, ip, detail]) => { sim.log.unshift({ id: ++sim.logSeq, at: new Date(t0 + dt).toISOString(), actor, action, target, ip, ok, detail }); });
  const licensed = () => !!sim.license && Date.now() < Date.parse(sim.license.expiresAt);
  const RANK = { '': 0, need_password: 1, need_license: 2, need_otp_enroll: 3, need_otp: 3 };
  function next(u, from) {
    const r = RANK[from] || 0;
    if (r < 1 && u.mustChangePassword) return 'need_password';
    if (r < 2 && !licensed()) { if (u.role !== 'admin') throw err(403, MSG.viewerNoLic); return 'need_license'; }
    if (r < 3) return u.otpEnabled ? 'need_otp' : 'need_otp_enroll';
    return 'active';
  }
  const brief = (u) => ({ id: u.id, username: u.username, displayName: u.displayName, role: u.role });
  const view = (u) => Object.assign(brief(u), { disabled: u.disabled, otpEnabled: u.otpEnabled, mustChangePassword: u.mustChangePassword, locked: Date.now() < u.lockedUntil, createdAt: u.createdAt, lastLoginAt: u.lastLoginAt });
  const licView = (l) => (l ? Object.assign({}, l, { expired: Date.now() >= Date.parse(l.expiresAt) }) : null);
  const SKEY = 'supplyguard.mock.auth';
  const persist = () => { try { if (sim.session && sim.session.state === 'active') sessionStorage.setItem(SKEY, sim.session.userId); else sessionStorage.removeItem(SKEY); } catch { /* 저장 차단 */ } };
  const me = () => { const s = sim.session; if (!s) throw err(401, MSG.login); const u = sim.users.find((x) => x.id === s.userId); if (!u || u.disabled) { sim.session = null; throw err(401, MSG.login); } return { s, u }; };
  const need = (st) => { const { s, u } = me(); if (s.state !== st) throw err(409, MSG.wrongStep, s.state); return { s, u }; };
  const active = () => { const x = me(); if (x.s.state !== 'active') throw err(401, '로그인 단계를 마쳐야 합니다', x.s.state); return x; };
  const admin = () => { const x = active(); if (x.u.role !== 'admin') throw err(403, MSG.adminOnly); return x; };
  const lastAdmin = (u) => u.role === 'admin' && !u.disabled && sim.users.filter((x) => x.role === 'admin' && !x.disabled).length === 1;
  const simApi = {
    me() { const { s, u } = me(); return { state: s.state, user: brief(u), mustChangePassword: u.mustChangePassword, license: licView(sim.license), otpRequired: true }; },
    login({ username, password }) {
      const u = sim.users.find((x) => x.username === String(username || '').trim()), now = Date.now();
      const name = String(username || '').trim();
      if (!u || u.disabled || now < u.lockedUntil) { audit('login', name, '', false, u && now < u.lockedUntil ? '잠긴 동안 시도' : '아이디 또는 비밀번호 틀림'); throw err(401, MSG.badCreds); } // 잠긴 동안은 맞는 비밀번호도 같은 문구로 거절
      if (u.pw !== password) { u.failed++; audit('login', name, '', false, '아이디 또는 비밀번호 틀림'); if (u.failed >= 5) { u.failed = 0; u.lockedUntil = now + 5 * 60000; audit('login_lock', name, name, false, '5회 연속 실패 — 5분 잠금'); } throw err(401, MSG.badCreds); }
      if (!licensed() && u.role !== 'admin') { audit('login', name, '', false, '라이선스 없음(조회자)'); throw err(403, MSG.viewerNoLic); }
      u.failed = 0; u.lastLoginAt = new Date(now).toISOString(); audit('login', name, '', true, '');
      sim.session = { userId: u.id, state: next(u, ''), otpPending: '', otpFailures: 0 }; persist();
      return { state: sim.session.state, user: brief(u) };
    },
    password({ current, next: pw }) {
      const { s, u } = me();
      if (s.state !== 'need_password' && s.state !== 'active') throw err(409, MSG.wrongStep, s.state);
      if (u.pw !== current) throw err(400, MSG.badCurrent, s.state);
      const bad = validatePassword(u.username, pw || ''); if (bad) throw err(400, bad, s.state);
      if (pw === current) throw err(400, MSG.samePW, s.state);
      u.pw = pw; u.mustChangePassword = false; audit('password_change', u.username, u.username, true, '');
      if (s.state !== 'active') s.state = next(u, 'need_password');
      persist(); return { state: s.state };
    },
    license({ key }) {
      const { s, u } = need('need_license');
      if (u.role !== 'admin') throw err(403, MSG.viewerNoLic, s.state);
      const d = String(key || '').replace(/[-\s]/g, ''); if (!/^\d{16}$/.test(d)) throw err(400, MSG.badKey, s.state);
      const now = Date.now();
      sim.license = { keyMasked: `****-****-****-${d.slice(12)}`, kind: 'trial', issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 365 * DAY).toISOString(), registeredBy: u.username };
      audit('license_register', u.username, sim.license.keyMasked, true, `${sim.license.kind} ~${sim.license.expiresAt.slice(0, 10)}`);
      s.state = next(u, 'need_license'); persist();
      return { state: s.state, license: licView(sim.license) };
    },
    otpEnroll() { const { s, u } = need('need_otp_enroll'); if (!s.otpPending) s.otpPending = rand(B32, 32); return { secret: s.otpPending, uri: `otpauth://totp/SupplyGuard:${encodeURIComponent(u.username)}?secret=${s.otpPending}&issuer=SupplyGuard` }; },
    otpConfirm({ code }) {
      const { s, u } = need('need_otp_enroll');
      if (!s.otpPending) throw err(409, MSG.enrollFirst, s.state);
      if (!/^\d{6}$/.test(String(code || '')) || code === '000000') throw err(400, MSG.badOTP, s.state);
      u.otpEnabled = true; s.otpPending = ''; s.state = 'active'; persist(); audit('otp_enroll', u.username, u.username, true, '');
      return { state: 'active', recoveryCodes: Array.from({ length: 10 }, () => `${rand(CODE_ABC, 4)}-${rand(CODE_ABC, 4)}`) };
    },
    otp({ code, recovery }) {
      const { s } = need('need_otp');
      if (recovery !== undefined) {
        const r = String(recovery).trim().toUpperCase();
        const who2 = (sim.users.find((x) => x.id === s.userId) || {}).username || '';
        if (!/^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/.test(r) || sim.used.has(r)) { audit('otp_recovery', who2, who2, false, ''); throw err(400, MSG.badRecovery, s.state); }
        sim.used.add(r); audit('otp_recovery', who2, who2, true, '복구 코드 사용');
      } else if (!/^\d{6}$/.test(String(code || '')) || code === '000000') {
        const who3 = (sim.users.find((x) => x.id === s.userId) || {}).username || '';
        s.otpFailures++; audit('otp_verify', who3, who3, false, '');
        if (s.otpFailures >= 5) { sim.session = null; persist(); throw err(401, MSG.otpRestart); }
        throw err(400, MSG.badOTP, s.state);
      }
      if (recovery === undefined) { const who4 = (sim.users.find((x) => x.id === s.userId) || {}).username || ''; audit('otp_verify', who4, who4, true, ''); }
      s.state = 'active'; persist(); return { state: 'active' };
    },
    logout() { const u = sim.session && sim.users.find((x) => x.id === sim.session.userId); if (u) audit('logout', u.username, u.username, true, ''); sim.session = null; persist(); return null; },
    getLicense() { active(); if (!sim.license) throw err(404, '등록된 라이선스가 없습니다'); return licView(sim.license); },
    users() { admin(); return sim.users.map(view); },
    createUser({ username, displayName, role }) {
      admin();
      const name = String(username || '').trim();
      if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(name)) throw err(400, '아이디는 영문 소문자 · 숫자 · . _ - 3~32자');
      if (!['admin', 'viewer'].includes(role)) throw err(400, '역할은 admin | viewer');
      if (sim.users.some((x) => x.username === name)) throw err(409, MSG.dupUser);
      const temp = rand(TEMP_ABC, 16);
      const u = mkUser(`u-${String(++sim.seq).padStart(4, '0')}`, name, String(displayName || '').trim() || name, role, { pw: temp, mustChangePassword: true, otpEnabled: false, createdAt: new Date().toISOString(), lastLoginAt: null });
      sim.users.push(u); audit('user_create', me().u.username, name, true, `역할 ${role}`);
      return { user: view(u), tempPassword: temp };
    },
    patchUser(id, patch) {
      const { u: by } = admin();
      const u = sim.users.find((x) => x.id === id); if (!u) throw err(404, '계정이 없습니다');
      if (patch.disabled === true && u.id === by.id) throw err(400, MSG.selfDisable);
      if (lastAdmin(u) && ((patch.role && patch.role !== 'admin') || patch.disabled === true)) throw err(409, MSG.lastAdmin);
      // 서버처럼 user_update 한 줄 — 역할 · 비활성 변화를 detail 에(「역할 viewer→admin, 비활성 false→false」)
      if ((patch.role && patch.role !== u.role) || (patch.disabled !== undefined && !!patch.disabled !== u.disabled)) { const role = patch.role || u.role, dis = patch.disabled !== undefined ? !!patch.disabled : u.disabled; audit('user_update', by.username, u.username, true, `역할 ${u.role}→${role}, 비활성 ${u.disabled}→${dis}`); }
      if (patch.role) u.role = patch.role; if (patch.disabled !== undefined) u.disabled = !!patch.disabled; if (patch.displayName) u.displayName = patch.displayName;
      return view(u);
    },
    resetPassword(id) { const { u: by } = admin(); const u = sim.users.find((x) => x.id === id); if (!u) throw err(404, '계정이 없습니다'); const temp = rand(TEMP_ABC, 16); u.pw = temp; u.mustChangePassword = true; u.failed = 0; u.lockedUntil = 0; audit('user_reset_password', by.username, u.username, true, ''); return { tempPassword: temp }; },
    resetOtp(id) { const { u: by } = admin(); const u = sim.users.find((x) => x.id === id); if (!u) throw err(404, '계정이 없습니다'); u.otpEnabled = false; audit('user_reset_otp', by.username, u.username, true, ''); return null; },
    // 인증 감사 [10/21 서버 기준] — 관리자만. 최신순 · before(양의 정수 id, 그보다 작은 것) · action(13개) · failed(1 | true). 잘못된 값은 400. ?fail=authAudit[:N] 이면 N 번 실패
    authAudit(q) {
      admin(); const o = q || {};
      if (U.simFail('authAudit')) throw err(503, '모의 오류 — 서버가 응답하지 않습니다');
      if (o.action && !AUTH_ACTIONS.includes(o.action)) throw err(400, `action 은 ${AUTH_ACTIONS.join(' | ')}`);
      if (o.failed && !['1', 'true'].includes(String(o.failed))) throw err(400, 'failed 는 1 | true');
      const before = o.before ? Number(o.before) : 0; if (o.before && !(Number.isInteger(before) && before > 0)) throw err(400, 'before 는 양의 정수 id');
      let rows = sim.log.filter((x) => (!o.action || x.action === o.action) && (!o.failed || !x.ok) && (!before || x.id < before));
      return rows.slice(0, Math.min(o.limit || 100, 500)).map((x) => Object.assign({}, x));
    },
  };
  // ?as=admin · ?as=viewer — 로그인 건너뜀(빠른 확인). 그 밖에는 이 탭에 남은 세션(sessionStorage)을 이어 쓴다
  const as = params.get('as');
  if (as === 'admin' || as === 'viewer') { const u = sim.users.find((x) => x.username === as); u.mustChangePassword = false; u.otpEnabled = true; if (!sim.license) sim.license = { keyMasked: '****-****-****-2026', kind: 'trial', issuedAt: new Date(t0).toISOString(), expiresAt: new Date(t0 + 365 * DAY).toISOString(), registeredBy: 'admin' }; sim.session = { userId: u.id, state: 'active', otpPending: '', otpFailures: 0 }; }
  else { try { const id = sessionStorage.getItem(SKEY); const u = id && sim.users.find((x) => x.id === id); if (u && !fresh) sim.session = { userId: u.id, state: 'active', otpPending: '', otpFailures: 0 }; } catch { /* 저장 차단 */ } }

  // ── 실제 백엔드 클라이언트 — 쿠키 세션(credentials: include) ──
  async function call(method, path, body) {
    const res = await fetch(state.apiBase + path, { method, credentials: 'include', headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
    if (res.status === 204) return null;
    let data = null; try { data = await res.json(); } catch { /* 본문 없음 */ }
    if (!res.ok) throw err(res.status, (data && data.error) || res.statusText, data && data.state);
    return data;
  }
  const liveApi = {
    me: () => call('GET', '/api/auth/me'), login: (b) => call('POST', '/api/auth/login', b), password: (b) => call('POST', '/api/auth/password', b), license: (b) => call('POST', '/api/auth/license', b),
    otpEnroll: () => call('POST', '/api/auth/otp/enroll'), otpConfirm: (b) => call('POST', '/api/auth/otp/enroll/confirm', b), otp: (b) => call('POST', '/api/auth/otp', b), logout: () => call('POST', '/api/auth/logout'),
    getLicense: () => call('GET', '/api/license'), users: () => call('GET', '/api/users'), createUser: (b) => call('POST', '/api/users', b), patchUser: (id, b) => call('PATCH', `/api/users/${encodeURIComponent(id)}`, b),
    resetPassword: (id) => call('POST', `/api/users/${encodeURIComponent(id)}/reset-password`), resetOtp: (id) => call('POST', `/api/users/${encodeURIComponent(id)}/reset-otp`),
    authAudit: (q) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(q || {})) if (v) p.set(k, String(v)); return call('GET', `/api/auth/audit?${p}`); },
  };
  const api = new Proxy({}, { get: (_, k) => (...a) => (state.source === 'live' ? liveApi[k](...a) : Promise.resolve().then(() => simApi[k](...a))) });

  // ── 로그인 단계 화면 ───────────────────────────────────
  const STEP_OF = { need_password: 'password', need_license: 'license', need_otp_enroll: 'otp-enroll', need_otp: 'otp' };
  let root = null, onActive = null, started = false, who = null;
  function screen(step, title, desc, body) {
    const errEl = h('p', { class: 'auth-error', 'data-part': 'auth-error', role: 'alert', hidden: true });
    const card = h('div', { class: 'auth-card' },
      h('div', { class: 'auth-brand' }, h('span', { class: 'brand-icon', 'aria-hidden': true }, '🛡'), 'SupplyGuard'),
      h('h2', null, title), desc ? h('p', { class: 'small muted' }, desc) : null, body(errEl), errEl,
      step !== 'login' ? h('button', { type: 'button', class: 'btn btn-ghost btn-xs auth-switch', onclick: () => api.logout().catch(() => null).then(() => show('login')) }, '다른 계정으로 로그인') : null,
      state.source === 'sim' ? h('p', { class: 'small muted auth-note' }, '시뮬레이션 — 데모 계정은 mock/README.md 「2026-10-20 2차 시안」') : h('p', { class: 'small muted auth-note' }, `실제 백엔드 ${state.apiBase}`));
    if (!root) { root = h('div', { class: 'auth', 'data-part': 'auth' }); document.body.append(root); }
    root.dataset.step = step;
    replace(root, card);
    const first = card.querySelector('input'); if (first) first.focus();
    return errEl;
  }
  const fail = (errEl) => (e) => { errEl.hidden = false; errEl.textContent = e.message; if (e.status === 401 && e.message === MSG.otpRestart) setTimeout(() => show('login', e.message), 0); };
  const go = (st) => (st === 'active' ? done() : show(STEP_OF[st] || 'login'));
  function field(label, input) { return h('label', { class: 'field' }, h('span', null, h('b', null, label)), input); }
  function show(step, notice) {
    document.body.classList.add('locked');
    if (step === 'login') {
      const u = h('input', { class: 'ctl', name: 'username', autocomplete: 'username', 'aria-label': '아이디' });
      const p = h('input', { class: 'ctl', name: 'password', type: 'password', autocomplete: 'current-password', 'aria-label': '비밀번호' });
      let errEl;
      const submit = (e) => { e.preventDefault(); errEl.hidden = true; api.login({ username: u.value, password: p.value }).then((r) => { who = r.user; go(r.state); }).catch((x) => { fail(errEl)(x); p.value = ''; p.focus(); }); };
      errEl = screen('login', '로그인', '', () => h('form', { class: 'auth-form', onsubmit: submit }, field('아이디', u), field('비밀번호', p), h('button', { type: 'submit', class: 'btn btn-primary', 'data-action': 'login' }, '로그인')));
      if (notice) { errEl.hidden = false; errEl.textContent = notice; }
    } else if (step === 'password') {
      const [cur, nx, cf] = ['current', 'next', 'confirm'].map((n) => h('input', { class: 'ctl', name: n, type: 'password', autocomplete: n === 'current' ? 'current-password' : 'new-password' }));
      let errEl;
      const submit = (e) => {
        e.preventDefault(); errEl.hidden = true;
        const bad = validatePassword((who && who.username) || '', nx.value) || (nx.value !== cf.value ? '새 비밀번호가 일치하지 않습니다' : '');
        if (bad) { fail(errEl)(new Error(bad)); return; }
        api.password({ current: cur.value, next: nx.value }).then((r) => go(r.state)).catch(fail(errEl));
      };
      errEl = screen('password', '비밀번호 변경', `처음 로그인했습니다. 새 비밀번호를 정하세요 — ${PW_MIN}자 이상, 아이디와 다르게.`, () => h('form', { class: 'auth-form', onsubmit: submit },
        field('지금 비밀번호', cur), field('새 비밀번호', nx), field('새 비밀번호 확인', cf), h('button', { type: 'submit', class: 'btn btn-primary', 'data-action': 'password' }, '바꾸고 계속')));
    } else if (step === 'license') {
      let errEl;
      const submit = () => { errEl.hidden = true; api.license({ key: boxes.value() }).then((r) => go(r.state)).catch(fail(errEl)); };
      const boxes = U.keyBoxes({ groups: 4, len: 4, label: '라이선스 키', onEnter: submit });
      errEl = screen('license', '라이선스 등록', '이 서버에 라이선스가 없습니다. 받은 키 16자리를 넣으세요(XXXX-XXXX-XXXX-XXXX). 붙여넣으면 네 칸에 나눠 들어갑니다.', () => h('div', { class: 'auth-form' },
        boxes, h('button', { type: 'button', class: 'btn btn-primary', 'data-action': 'license', onclick: submit }, '등록하고 계속')));
    } else if (step === 'otp-enroll') {
      const code = h('input', { class: 'ctl mono otp-code', name: 'code', inputmode: 'numeric', maxlength: 6, autocomplete: 'one-time-code', placeholder: '123456', 'aria-label': 'OTP 6자리' });
      const qrSlot = h('div', { class: 'otp-qr' }, h('span', { class: 'small muted' }, '불러오는 중…'));
      let errEl;
      const submit = (e) => { e.preventDefault(); errEl.hidden = true; api.otpConfirm({ code: code.value.trim() }).then((r) => showCodes(r.recoveryCodes)).catch(fail(errEl)); };
      errEl = screen('otp-enroll', 'OTP 등록', '인증 앱(Google Authenticator 등)으로 QR 을 찍거나 키를 직접 넣은 뒤, 앱에 나온 6자리를 입력하세요.', () => h('form', { class: 'auth-form', onsubmit: submit },
        qrSlot, field('앱에 나온 6자리', code), h('button', { type: 'submit', class: 'btn btn-primary', 'data-action': 'otp-confirm' }, '확인')));
      api.otpEnroll().then((r) => replace(qrSlot, U.fakeQR(r.uri), h('div', { class: 'otp-key' }, h('span', { class: 'small muted' }, '직접 입력할 키'),
        h('code', { class: 'mono', 'data-part': 'otp-secret' }, r.secret.replace(/(.{4})/g, '$1 ').trim()),
        h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => { try { navigator.clipboard.writeText(r.secret).catch(() => {}); } catch { /* 복사 차단 */ } } }, '⧉ 복사')))).catch(fail(errEl));
    } else if (step === 'otp') {
      let recovery = false, errEl;
      const render = () => {
        const inp = recovery ? h('input', { class: 'ctl mono', name: 'recovery', autocomplete: 'off', placeholder: 'XXXX-XXXX', 'aria-label': '복구 코드' })
          : h('input', { class: 'ctl mono otp-code', name: 'code', inputmode: 'numeric', maxlength: 6, autocomplete: 'one-time-code', placeholder: '123456', 'aria-label': 'OTP 6자리' });
        const submit = (e) => { e.preventDefault(); errEl.hidden = true; api.otp(recovery ? { recovery: inp.value } : { code: inp.value.trim() }).then((r) => go(r.state)).catch(fail(errEl)); };
        errEl = screen('otp', recovery ? '복구 코드로 로그인' : 'OTP 인증', recovery ? '처음 등록할 때 받은 복구 코드 하나를 넣으세요. 한 번 쓴 코드는 다시 쓸 수 없습니다.' : '인증 앱에 나온 6자리를 입력하세요.', () => h('form', { class: 'auth-form', onsubmit: submit },
          field(recovery ? '복구 코드' : 'OTP 6자리', inp), h('button', { type: 'submit', class: 'btn btn-primary', 'data-action': 'otp' }, '확인'),
          h('button', { type: 'button', class: 'btn btn-ghost btn-xs', 'data-action': recovery ? 'use-otp' : 'use-recovery', onclick: () => { recovery = !recovery; render(); } }, recovery ? 'OTP 코드로 로그인' : '복구 코드로 로그인')));
      };
      render();
    }
  }
  // 복구 코드 10개 — 이 화면에서 한 번만. 「저장했습니다」를 체크해야 진행 버튼이 생긴다
  function showCodes(codes) {
    const go2 = h('div', { class: 'auth-go' });
    const saved = h('input', { type: 'checkbox', name: 'saved', onchange: () => replace(go2, saved.checked ? h('button', { type: 'button', class: 'btn btn-primary', 'data-action': 'finish', onclick: () => done() }, '시작하기') : null) });
    const txt = codes.join('\n');
    screen('recovery-codes', '복구 코드 — 지금 한 번만 보입니다', '휴대폰을 잃어버렸을 때 OTP 대신 쓰는 코드입니다. 안전한 곳에 보관하세요. 코드 하나는 한 번만 쓸 수 있습니다.', () => h('div', { class: 'auth-form' },
      h('ol', { class: 'recovery-codes mono', 'data-part': 'recovery-codes' }, codes.map((c) => h('li', null, c))),
      h('div', { class: 'row-actions' },
        h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => { try { navigator.clipboard.writeText(txt).catch(() => {}); } catch { /* 복사 차단 */ } } }, '⧉ 복사'),
        h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => { const url = URL.createObjectURL(new Blob([txt + '\n'], { type: 'text/plain' })); const a = h('a', { href: url, download: 'supplyguard-recovery-codes.txt' }); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000); } }, '⤓ 텍스트로 받기')),
      h('label', { class: 'check' }, saved, ' 복구 코드를 안전한 곳에 저장했습니다'), go2));
  }
  // 활성 세션 → 셸. 처음이면 앱을 띄우고(onActive), 로그아웃 뒤 다시 들어오면 셸을 다시 보인다(역할이 바뀌었을 수 있어 화면을 다시 그린다)
  function done() {
    return api.me().then((m) => {
      state.auth = { user: m.user, license: m.license, otpRequired: m.otpRequired };
      if (root) { root.remove(); root = null; }
      document.body.classList.remove('locked');
      if (!started) { started = true; onActive(); } else { U.remount(); U.emit(); }
    });
  }
  function gate(fn) {
    onActive = fn;
    api.me().then((m) => { who = m.user; if (m.state === 'active') done(); else go(m.state); })
      .catch((e) => {
        if (state.source === 'live' && e.status === 404) { state.auth = { user: { username: '(인증 없음)', displayName: '인증 없는 백엔드', role: 'admin' }, license: null, noAuth: true }; started = true; fn(); return; } // 옛 백엔드: 인증 경로 없음
        show('login', state.source === 'live' && !e.status ? `백엔드에 연결할 수 없습니다 — ${state.apiBase} (${e.message})` : '');
      });
  }
  function logout() { return api.logout().catch(() => null).then(() => { state.auth = null; who = null; show('login'); }); }

  // ── 상단: 라이선스 칩 · 계정 메뉴 [10/20 A] ─────────────
  const daysLeft = (l) => Math.max(0, Math.ceil((Date.parse(l.expiresAt) - Date.now()) / DAY));
  function licenseText(l) { if (!l) return '라이선스 없음'; if (l.expired || daysLeft(l) === 0) return '라이선스 만료'; return `${l.kind === 'trial' ? '평가판' : '라이선스'} · ${daysLeft(l)}일 남음`; }
  // 칩 색 [10/20 결정 3]: 만료(또는 0일) 빨강 · 30일 이하 노랑 · 그 밖 기본(초록). 라이선스 없음은 회색
  const LIC_WARN_DAYS = 30;
  const licenseTone = (l) => (!l ? 'none' : l.expired || daysLeft(l) === 0 ? 'danger' : daysLeft(l) <= LIC_WARN_DAYS ? 'warn' : 'ok');
  const licenseChip = (l) => h('span', { class: `lic-chip ${licenseTone(l)}`, 'data-tone': licenseTone(l), title: l ? `${l.keyMasked} · 만료 ${fmt.dateTime(l.expiresAt)}` : '' }, licenseText(l));
  function headerEl() {
    const chip = h('span', { class: 'lic-chip', 'data-part': 'license-chip' });
    const btn = h('button', { type: 'button', class: 'btn btn-ghost btn-xs acct', 'data-part': 'account', 'aria-haspopup': 'menu', 'aria-expanded': 'false' });
    const menu = h('div', { class: 'menu', 'data-part': 'account-menu', role: 'menu', hidden: true },
      h('button', { type: 'button', role: 'menuitem', 'data-menu': 'profile', onclick: () => { closeMenu(); profile(); } }, '내 정보'),
      h('button', { type: 'button', role: 'menuitem', 'data-menu': 'password', onclick: () => { closeMenu(); changePassword(); } }, '비밀번호 변경'),
      h('button', { type: 'button', role: 'menuitem', 'data-menu': 'logout', onclick: () => { closeMenu(); logout(); } }, '로그아웃'));
    const closeMenu = () => { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
    btn.addEventListener('click', (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute('aria-expanded', String(!menu.hidden)); if (!menu.hidden) menu.querySelector('button').focus(); });
    document.addEventListener('click', (e) => { if (!menu.hidden && !menu.contains(e.target)) closeMenu(); });
    menu.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeMenu(); btn.focus(); } });
    const root2 = h('span', { class: 'acct-wrap' }, chip, h('span', { class: 'menu-anchor' }, btn, menu));
    root2.sync = () => {
      const a = state.auth; if (!a) return;
      const l = a.license; chip.textContent = a.noAuth ? '인증 없음' : licenseText(l);
      chip.className = `lic-chip ${a.noAuth ? '' : licenseTone(l)}`; // 30일 이하 노랑 · 만료 빨강 [10/20 결정 3]
      chip.title = l ? `${l.keyMasked} · 만료 ${fmt.dateTime(l.expiresAt)}` : '';
      btn.textContent = `👤 ${a.user.displayName} · ${ROLE_KO[a.user.role] || a.user.role} ▾`;
      menu.querySelector('[data-menu="password"]').hidden = !!a.noAuth; menu.querySelector('[data-menu="logout"]').hidden = !!a.noAuth;
    };
    return root2;
  }
  function profile() {
    const a = state.auth, u = a.user;
    U.modal({ title: '내 정보', kind: 'profile', body: h('dl', { class: 'dl' },
      h('dt', null, '아이디'), h('dd', { class: 'mono' }, u.username), h('dt', null, '이름'), h('dd', null, u.displayName), h('dt', null, '역할'), h('dd', null, ROLE_KO[u.role]),
      h('dt', null, '라이선스'), h('dd', null, licenseText(a.license), a.license ? h('span', { class: 'small muted' }, ` · ${a.license.keyMasked} · 만료 ${fmt.dateTime(a.license.expiresAt)}`) : null),
      h('dt', null, 'OTP'), h('dd', null, a.otpRequired === false ? '서버 설정으로 꺼짐' : '등록됨')) });
  }
  function changePassword() {
    const [cur, nx, cf] = ['current', 'next', 'confirm'].map((n) => h('input', { class: 'ctl', name: n, type: 'password', autocomplete: n === 'current' ? 'current-password' : 'new-password' }));
    const msg = h('p', { class: 'small tone-danger', role: 'alert', hidden: true });
    const save = () => {
      const bad = validatePassword(state.auth.user.username, nx.value) || (nx.value !== cf.value ? '새 비밀번호가 일치하지 않습니다' : '');
      if (bad) { msg.hidden = false; msg.textContent = bad; return; }
      api.password({ current: cur.value, next: nx.value }).then(() => { m.close(); U.toast('비밀번호를 바꿨습니다', { tone: 'ok' }); }).catch((e) => { msg.hidden = false; msg.textContent = e.message; });
    };
    const m = U.modal({ title: '비밀번호 변경', kind: 'password', guard: () => !!(cur.value || nx.value || cf.value),
      body: h('div', { class: 'form' }, field('지금 비밀번호', cur), field(`새 비밀번호 (${PW_MIN}자 이상, 아이디와 다르게)`, nx), field('새 비밀번호 확인', cf), msg),
      foot: [h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => m.tryClose() }, '취소'), h('button', { type: 'button', class: 'btn btn-primary', onclick: save }, '바꾸기')] });
  }

  // ── 계정 탭 (관리자) [10/20 A] — 「설정」 화면 「계정」 탭에 들어간다(10/20 결정 2 — 정책 화면에서 옮김) ──
  function tempPasswordDialog(username, temp) {
    U.modal({ title: `${username} 임시 비밀번호`, kind: 'temp-password', body: h('div', { class: 'col-gap' },
      h('p', { class: 'small' }, `지금 한 번만 보입니다. 직접 전달하세요. 첫 로그인에서 새 비밀번호(${PW_MIN}자 이상, 아이디와 다르게)로 바꾸고 OTP 를 등록합니다.`),
      h('code', { class: 'temp-pw mono', 'data-temp-password': '' }, temp),
      h('div', { class: 'row-actions' }, h('button', { type: 'button', class: 'btn btn-ghost btn-xs', onclick: () => { try { navigator.clipboard.writeText(temp).catch(() => {}); } catch { /* 복사 차단 */ } U.toast('임시 비밀번호를 복사했습니다', { tone: 'ok', key: 'copy', replace: true }); } }, '⧉ 복사'))) });
  }
  function accountsView() {
    const body = h('div', { class: 'grow scroll' });
    const msg = h('p', { class: 'small tone-danger', role: 'alert', hidden: true });
    const root2 = h('div', { class: 'col', 'data-view': 'accounts' },
      h('div', { class: 'acct-head' }, h('p', { class: 'small muted' }, `관리자는 모든 쓰기, 조회자는 보기만 합니다. 새 계정 · 비밀번호 초기화의 임시 비밀번호는 한 번만 보입니다. 새 비밀번호는 ${PW_MIN}자 이상, 아이디와 다르게.`),
        h('button', { type: 'button', class: 'btn btn-primary btn-xs', 'data-action': 'user-add', onclick: () => addUser() }, '+ 계정 추가')), msg, body);
    const showErr = (e) => { msg.hidden = false; msg.textContent = e.message; };
    const STATUS = (u) => (u.disabled ? ['비활성', 'off'] : u.locked ? ['잠김(5분)', 'warn'] : u.mustChangePassword ? ['첫 로그인 대기', 'info'] : ['활성', 'ok']);
    function load() {
      msg.hidden = true;
      api.users().then((us) => {
        const admins = us.filter((u) => u.role === 'admin' && !u.disabled).length;
        const meId = state.auth && state.auth.user.id;
        replace(body, h('table', { class: 'table', 'data-table': 'users' }, h('thead', null, h('tr', null, ['아이디', '이름', '역할', '상태', 'OTP', '마지막 로그인', ''].map((t) => h('th', null, t)))),
          h('tbody', null, us.map((u) => {
            const last = u.role === 'admin' && !u.disabled && admins === 1;
            const [st, tone] = STATUS(u);
            const act = (label, action, run, cls) => h('button', { type: 'button', class: `btn ${cls || 'btn-ghost'} btn-xs`, 'data-action': action, onclick: run }, label);
            return h('tr', { 'data-user': u.username },
              h('td', { class: 'mono' }, u.username, u.id === meId ? h('span', { class: 'small muted' }, ' (나)') : null), h('td', null, u.displayName),
              h('td', null, h('span', { class: `role-chip role-${u.role}` }, ROLE_KO[u.role]), last ? h('span', { class: 'small muted', title: MSG.lastAdmin }, ' · 마지막 관리자') : null),
              h('td', null, h('span', { class: `st-dot st-${tone}` }, st)), h('td', { class: 'small' }, u.otpEnabled ? '등록됨' : '미등록'),
              h('td', { class: 'num small muted nowrap' }, u.lastLoginAt ? fmt.dateTime(u.lastLoginAt) : '—'),
              h('td', { class: 'row-actions nowrap' },
                // 마지막 관리자 · 자기 자신은 강등 · 비활성 버튼을 그리지 않는다(누를 수 없는 버튼 금지)
                last ? null : u.role === 'admin' ? act('조회자로', 'demote', () => roleChange(u, 'viewer')) : act('관리자로', 'promote', () => roleChange(u, 'admin')),
                last || u.id === meId ? null : act(u.disabled ? '활성화' : '비활성', 'disable', () => toggleDisabled(u), u.disabled ? 'btn-ghost' : 'btn-danger-ghost'),
                act('비밀번호 초기화', 'reset-pw', () => resetPw(u)), u.otpEnabled ? act('OTP 초기화', 'reset-otp', () => resetOtp(u)) : null));
          }))),
        h('p', { class: 'small muted pad-sm', 'data-part': 'last-admin' }, `관리자는 지금 ${admins}명입니다. ${MSG.lastAdmin} — 다른 계정을 먼저 관리자로 올리세요.`));
      }).catch((e) => replace(body, U.loadErrorNote(e, '계정'))); // 다시 시도 · 자동 재시도 없이 일반 오류 안내 [10/21 — React SettingsPage]
    }
    const confirmThen = (opts, run) => U.confirmDialog(Object.assign({ reason: false }, opts)).then((ok) => ok && run().then(load).catch(showErr));
    const roleChange = (u, role) => confirmThen({ title: role === 'admin' ? '관리자로 올리기' : '조회자로 내리기', target: `${u.username} (${u.displayName})`, tone: 'primary', okLabel: '바꾸기',
      effects: [role === 'admin' ? '정책 · 판정 · 계정 관리 같은 모든 쓰기를 할 수 있게 됩니다' : '쓰기 버튼이 모두 사라지고 보기만 할 수 있습니다', '지금 로그인 중이면 다음 요청부터 적용됩니다'], undo: '같은 화면에서 역할을 다시 바꿉니다' },
    () => api.patchUser(u.id, { role }));
    const toggleDisabled = (u) => confirmThen({ title: u.disabled ? '계정 활성화' : '계정 비활성', target: `${u.username} (${u.displayName})`, okLabel: u.disabled ? '활성화' : '비활성',
      effects: u.disabled ? ['다시 로그인할 수 있습니다'] : ['지금 세션이 끊기고 로그인할 수 없습니다', '판정 · 변경 이력의 처리자 기록은 남습니다'], undo: '같은 화면에서 다시 활성화합니다' },
    () => api.patchUser(u.id, { disabled: !u.disabled }));
    const resetPw = (u) => U.confirmDialog({ reason: false, title: '비밀번호 초기화', target: `${u.username} (${u.displayName})`, okLabel: '초기화',
      effects: ['새 임시 비밀번호를 만들어 한 번 보여 줍니다', `첫 로그인에서 비밀번호를 바꿔야 합니다(${PW_MIN}자 이상, 아이디와 다르게)`, '5분 잠금도 풀립니다'], undo: '되돌릴 수 없습니다 — 새 임시 비밀번호를 전달하세요' })
      .then((ok) => ok && api.resetPassword(u.id).then((r) => { load(); tempPasswordDialog(u.username, r.tempPassword); }).catch(showErr));
    const resetOtp = (u) => confirmThen({ title: 'OTP 초기화', target: `${u.username} (${u.displayName})`, okLabel: '초기화',
      effects: ['등록된 인증 앱과 남은 복구 코드가 지워집니다', '다음 로그인에서 OTP 를 다시 등록합니다'], undo: '되돌릴 수 없습니다 — 다시 등록하게 안내하세요' }, () => api.resetOtp(u.id));
    function addUser() {
      const name = h('input', { class: 'ctl mono', name: 'new-username', placeholder: '예: analyst1', autocomplete: 'off' });
      const disp = h('input', { class: 'ctl', name: 'new-display', placeholder: '예: 분석 담당' });
      const role = U.select([['viewer', '조회자 — 보기만'], ['admin', '관리자 — 모든 쓰기']], 'viewer', () => {}, { name: 'new-role', 'aria-label': '역할' });
      const em = h('p', { class: 'small tone-danger', role: 'alert', hidden: true });
      const create = () => api.createUser({ username: name.value, displayName: disp.value, role: role.value }).then((r) => { m.close(); load(); tempPasswordDialog(r.user.username, r.tempPassword); }).catch((e) => { em.hidden = false; em.textContent = e.message; });
      const m = U.modal({ title: '계정 추가', kind: 'user-add', guard: () => !!(name.value || disp.value),
        body: h('div', { class: 'form' }, field('아이디', name), field('이름', disp), field('역할', role), em),
        foot: [h('button', { type: 'button', class: 'btn btn-ghost', onclick: () => m.tryClose() }, '취소'), h('button', { type: 'button', class: 'btn btn-primary', 'data-action': 'user-create', onclick: create }, '만들기')] });
    }
    load();
    return root2;
  }

  U.auth = { gate, logout, headerEl, accountsView, api, ROLE_KO, MSG, AUTH_ACTIONS, licenseText, licenseTone, licenseChip, daysLeft, PW_MIN, sim: state.source === 'sim' ? sim : null };
})();
