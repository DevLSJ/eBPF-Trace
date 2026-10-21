// e2e 가짜 백엔드의 인증 부분 — backend/internal/api/auth.go · internal/auth 의 계약과 문구를 따른다.
// 기본은 「관리자로 로그인된 active 세션 · OTP 꺼짐 · 평가판 라이선스」라서 기존 시나리오는 로그인 없이 바로 화면을 연다.
// 테스트 전용 고정값(가짜) — 실제 비밀번호 · 키가 아니다.

export const ACTOR = '보안 담당자';
export const ADMIN_PW = 'e2e-admin-pass-1';
export const VIEWER_PW = 'e2e-viewer-pass-1';
export const OTP_OK = '123456'; // 가짜 백엔드가 받는 유일한 OTP 코드
export const OTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
export const OTP_URI = `otpauth://totp/SupplyGuard:admin?secret=${OTP_SECRET}&issuer=SupplyGuard&algorithm=SHA1&digits=6&period=30`;
export const RECOVERY = ['A2B3-C4D5', 'E6F7-G8H9', 'J2K3-L4M5', 'N6P7-Q8R9', 'S2T3-U4V5', 'W6X7-Y8Z9', 'A3B4-C5D6', 'E7F8-G9H2', 'J3K4-L5M6', 'N7P8-Q9R2'];
const DAY = 86400e3;

export const MSG = {
  login: '로그인이 필요합니다',
  badCreds: '아이디 또는 비밀번호가 올바르지 않습니다. 5번 연속 틀리면 5분 동안 로그인할 수 없습니다',
  viewerNoLic: '관리자가 먼저 라이선스를 등록해야 합니다',
  wrongStep: '지금 로그인 단계에서 할 수 없는 요청입니다',
  badOTP: 'OTP 코드가 올바르지 않습니다',
  badRecovery: '복구 코드가 올바르지 않거나 이미 사용되었습니다',
  finishLogin: '로그인 단계를 마쳐야 합니다',
  viewerWrite: '조회자는 읽기만 할 수 있습니다',
  adminOnly: '관리자 권한이 필요합니다',
  lastAdmin: '마지막 관리자는 강등하거나 비활성화할 수 없습니다',
  selfDisable: '자기 자신은 비활성화할 수 없습니다',
  dupUser: '이미 있는 아이디입니다',
  enrollFirst: '먼저 OTP 등록을 시작하세요',
  badCurrent: '현재 비밀번호가 올바르지 않습니다',
  samePW: '새 비밀번호는 지금 비밀번호와 달라야 합니다',
  badKey: '라이선스 키 형식이 아닙니다(숫자 16자리, XXXX-XXXX-XXXX-XXXX)',
};

export type State = 'need_password' | 'need_license' | 'need_otp_enroll' | 'need_otp' | 'active';
export interface MUser {
  id: string;
  username: string;
  displayName: string;
  role: 'admin' | 'viewer';
  pw: string;
  mustChangePassword: boolean;
  otpEnabled: boolean;
  disabled: boolean;
  failed: number;
  lockedUntil: number;
  createdAt: string;
  lastLoginAt: string | null;
}
export interface MLicense {
  keyMasked: string;
  kind: string;
  issuedAt: string;
  expiresAt: string;
  registeredBy: string;
}
type Res = { status: number; body?: unknown };

export class MockAuth {
  otpRequired = false;
  license: MLicense | null;
  users: MUser[];
  session: { userId: string; state: State; enrollStarted: boolean } | null;
  audit: { id: number; at: string; actor: string; action: string; target: string; ip: string; ok: boolean; detail: string }[] = [];
  usedRecovery = new Set<string>();
  private seq = 2;

  constructor() {
    const now = Date.now();
    this.license = { keyMasked: '****-****-****-2026', kind: 'trial', issuedAt: new Date(now - 165 * DAY).toISOString(), expiresAt: new Date(now + 200 * DAY - 3600e3).toISOString(), registeredBy: 'admin' };
    const mk = (id: string, username: string, displayName: string, role: MUser['role'], pw: string): MUser => ({
      id, username, displayName, role, pw, mustChangePassword: false, otpEnabled: false, disabled: false, failed: 0, lockedUntil: 0,
      createdAt: new Date(now - 30 * DAY).toISOString(), lastLoginAt: new Date(now - DAY).toISOString(),
    });
    this.users = [mk('u-0001', 'admin', ACTOR, 'admin', ADMIN_PW), mk('u-0002', 'viewer', '조회 담당자', 'viewer', VIEWER_PW)];
    this.session = { userId: 'u-0001', state: 'active', enrollStarted: false };
    this.log('admin', 'login', '', true, '다음 단계: active');
  }

  // ── 시나리오 도우미 ──
  user(name: string) {
    return this.users.find((u) => u.username === name)!;
  }
  current() {
    return this.session ? this.users.find((u) => u.id === this.session!.userId) ?? null : null;
  }
  loggedOut() {
    this.session = null;
    return this;
  }
  asViewer() {
    this.session = { userId: 'u-0002', state: 'active', enrollStarted: false };
    return this;
  }
  // 첫 설치: 관리자 비밀번호 변경 필요 · 라이선스 없음 · 로그인 전
  fresh() {
    const a = this.user('admin');
    a.mustChangePassword = true;
    a.lastLoginAt = null;
    this.license = null;
    this.session = null;
    return this;
  }
  setLicenseDays(days: number) {
    const now = Date.now();
    this.license = { keyMasked: '****-****-****-2026', kind: 'trial', issuedAt: new Date(now - 300 * DAY).toISOString(), expiresAt: new Date(now + days * DAY - 3600e3).toISOString(), registeredBy: 'admin' };
  }
  actorName() {
    return this.current()?.displayName ?? ACTOR;
  }

  private log(actor: string, action: string, target: string, ok: boolean, detail = '') {
    this.audit.unshift({ id: this.audit.length + 1, at: new Date().toISOString(), actor, action, target, ip: '127.0.0.1', ok, detail });
  }
  private licensed() {
    return !!this.license && Date.now() < Date.parse(this.license.expiresAt);
  }
  private licView() {
    return this.license ? { ...this.license, expired: !this.licensed() } : null;
  }
  private next(u: MUser, from: State | ''): State | 'viewerNoLic' {
    const rank: Record<string, number> = { '': 0, need_password: 1, need_license: 2, need_otp_enroll: 3, need_otp: 3 };
    const r = rank[from] ?? 0;
    if (r < 1 && u.mustChangePassword) return 'need_password';
    if (r < 2 && !this.licensed()) return u.role === 'admin' ? 'need_license' : 'viewerNoLic';
    if (r < 3 && this.otpRequired) return u.otpEnabled ? 'need_otp' : 'need_otp_enroll';
    return 'active';
  }
  private brief(u: MUser) {
    return { id: u.id, username: u.username, displayName: u.displayName, role: u.role };
  }
  private view(u: MUser) {
    return { ...this.brief(u), disabled: u.disabled, otpEnabled: u.otpEnabled, mustChangePassword: u.mustChangePassword, locked: Date.now() < u.lockedUntil, createdAt: u.createdAt, lastLoginAt: u.lastLoginAt };
  }
  private err(status: number, error: string, state?: string): Res {
    return { status, body: state ? { error, state } : { error } };
  }
  private step(...allowed: State[]): { u: MUser; res?: undefined } | { res: Res; u?: undefined } {
    const u = this.current();
    if (!this.session || !u || u.disabled) return { res: this.err(401, MSG.login) };
    if (!allowed.includes(this.session.state)) return { res: this.err(409, MSG.wrongStep, this.session.state) };
    return { u };
  }

  // 미들웨어: 단계 경로 밖의 /api/* — active 세션만, 조회자의 쓰기는 403. null 이면 통과
  gate(method: string, path: string, writing: boolean): Res | null {
    if (path.startsWith('/auth/') && path !== '/auth/audit') return null;
    const u = this.current();
    if (!this.session || !u || u.disabled) return this.err(401, MSG.login);
    if (this.session.state !== 'active') return this.err(401, MSG.finishLogin, this.session.state);
    if (u.role !== 'admin' && writing) return this.err(403, MSG.viewerWrite);
    if (u.role !== 'admin' && (path === '/auth/audit' || path.startsWith('/users'))) return this.err(403, MSG.adminOnly);
    void method;
    return null;
  }
  active() {
    return this.session?.state === 'active';
  }

  // 인증 경로 처리. 해당 없으면 null
  handle(method: string, path: string, body: string | undefined): Res | null {
    const b = parseBody(body); // W18: YAML 본문(PUT /api/policies)도 지나가므로 JSON 이 아니면 빈 객체
    const s = (k: string) => (typeof b[k] === 'string' ? (b[k] as string) : '');
    let m: RegExpMatchArray | null;
    if (method === 'GET' && path === '/auth/me') {
      const u = this.current();
      if (!this.session || !u || u.disabled) return this.err(401, MSG.login);
      return { status: 200, body: { state: this.session.state, user: this.brief(u), mustChangePassword: u.mustChangePassword, license: this.licView(), otpRequired: this.otpRequired } };
    }
    if (method === 'POST' && path === '/auth/login') {
      const u = this.users.find((x) => x.username === s('username').trim());
      const now = Date.now();
      if (!u || u.disabled || now < u.lockedUntil) {
        this.log(s('username'), 'login', '', false, u ? '잠긴 계정' : '없는 아이디');
        return this.err(401, MSG.badCreds);
      }
      if (u.pw !== s('password')) {
        u.failed++;
        if (u.failed >= 5) {
          u.failed = 0;
          u.lockedUntil = now + 5 * 60_000;
          this.log(u.username, 'login_lock', u.username, false, '5회 연속 실패 — 5분 잠금');
        }
        this.log(u.username, 'login', '', false, '비밀번호 틀림');
        return this.err(401, MSG.badCreds);
      }
      const st = this.next(u, '');
      if (st === 'viewerNoLic') return this.err(403, MSG.viewerNoLic);
      u.failed = 0;
      u.lastLoginAt = new Date(now).toISOString();
      this.session = { userId: u.id, state: st, enrollStarted: false };
      this.log(u.username, 'login', '', true, `다음 단계: ${st}`);
      return { status: 200, body: { state: st, user: this.brief(u) } };
    }
    if (method === 'POST' && path === '/auth/password') {
      const r = this.step('need_password', 'active');
      if (r.res) return r.res;
      const u = r.u;
      const st = this.session!.state;
      const next = s('next');
      if (u.pw !== s('current')) return this.err(400, MSG.badCurrent, st);
      if ([...next].length < 5) return this.err(400, '비밀번호는 5자 이상이어야 합니다', st);
      if (next.trim().toLowerCase() === u.username.toLowerCase()) return this.err(400, '비밀번호는 아이디와 달라야 합니다', st);
      if (next === s('current')) return this.err(400, MSG.samePW, st);
      u.pw = next;
      u.mustChangePassword = false;
      if (st !== 'active') {
        const n = this.next(u, 'need_password');
        if (n === 'viewerNoLic') return this.err(403, MSG.viewerNoLic, st);
        this.session!.state = n;
      }
      this.log(u.username, 'password_change', u.username, true);
      return { status: 200, body: { state: this.session!.state } };
    }
    if (method === 'POST' && path === '/auth/license') {
      const r = this.step('need_license');
      if (r.res) return r.res;
      const d = s('key').replace(/[-\s]/g, '');
      if (!/^\d{16}$/.test(d)) return this.err(400, MSG.badKey, 'need_license');
      const now = Date.now();
      this.license = { keyMasked: `****-****-****-${d.slice(12)}`, kind: 'trial', issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 365 * DAY).toISOString(), registeredBy: r.u.username };
      this.session!.state = this.next(r.u, 'need_license') as State;
      this.log(r.u.username, 'license', this.license.keyMasked, true);
      return { status: 200, body: { state: this.session!.state, license: this.licView() } };
    }
    if (method === 'POST' && path === '/auth/otp/enroll') {
      const r = this.step('need_otp_enroll');
      if (r.res) return r.res;
      this.session!.enrollStarted = true;
      return { status: 200, body: { secret: OTP_SECRET, uri: OTP_URI } };
    }
    if (method === 'POST' && path === '/auth/otp/enroll/confirm') {
      const r = this.step('need_otp_enroll');
      if (r.res) return r.res;
      if (!this.session!.enrollStarted) return this.err(409, MSG.enrollFirst, 'need_otp_enroll');
      if (s('code') !== OTP_OK) return this.err(400, MSG.badOTP, 'need_otp_enroll');
      r.u.otpEnabled = true;
      this.session!.state = 'active';
      this.log(r.u.username, 'otp_enroll', r.u.username, true);
      return { status: 200, body: { state: 'active', recoveryCodes: RECOVERY } };
    }
    if (method === 'POST' && path === '/auth/otp') {
      const r = this.step('need_otp');
      if (r.res) return r.res;
      if (s('recovery').trim()) {
        const code = s('recovery').trim().toUpperCase();
        if (!RECOVERY.includes(code) || this.usedRecovery.has(code)) return this.err(400, MSG.badRecovery, 'need_otp');
        this.usedRecovery.add(code);
      } else if (s('code') !== OTP_OK) return this.err(400, MSG.badOTP, 'need_otp');
      this.session!.state = 'active';
      this.log(r.u.username, 'otp_verify', r.u.username, true);
      return { status: 200, body: { state: 'active' } };
    }
    if (method === 'POST' && path === '/auth/logout') {
      const u = this.current();
      if (u) this.log(u.username, 'logout', '', true);
      this.session = null;
      return { status: 204 };
    }
    // W21: 라이선스 갱신 — 관리자만(조회자는 gate 의 403), 만료 여부와 상관없이 바꾼다. 감사에는 가린 키만
    if (method === 'PUT' && path === '/license') {
      const u = this.current()!;
      if (u.role !== 'admin') return this.err(403, MSG.adminOnly);
      const d = s('key').replace(/[-\s]/g, '');
      if (!/^\d{16}$/.test(d)) {
        this.log(u.username, 'license_renew', '', false, '형식 오류');
        return this.err(400, MSG.badKey);
      }
      const now = Date.now();
      this.license = { keyMasked: `****-****-****-${d.slice(12)}`, kind: 'trial', issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 365 * DAY).toISOString(), registeredBy: u.username };
      this.log(u.username, 'license_renew', this.license.keyMasked, true);
      return { status: 200, body: this.licView() };
    }
    if (method === 'GET' && path === '/license') return this.license ? { status: 200, body: this.licView() } : this.err(404, '등록된 라이선스가 없습니다');
    if (method === 'GET' && path === '/auth/audit') return { status: 200, body: this.audit };
    if (method === 'GET' && path === '/users') return { status: 200, body: this.users.map((u) => this.view(u)) };
    if (method === 'POST' && path === '/users') {
      const name = s('username').trim();
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$/.test(name)) return this.err(400, '아이디는 영문 · 숫자 · . _ - 로 3~32자입니다');
      if (b.role !== 'admin' && b.role !== 'viewer') return this.err(400, 'role: admin | viewer');
      if (this.users.some((u) => u.username === name)) return this.err(409, MSG.dupUser);
      const temp = `Tmp${String(++this.seq).padStart(4, '0')}xYzAbCdEf`.slice(0, 16);
      const u: MUser = { id: `u-${String(this.seq).padStart(4, '0')}`, username: name, displayName: s('displayName').trim() || name, role: b.role, pw: temp, mustChangePassword: true, otpEnabled: false, disabled: false, failed: 0, lockedUntil: 0, createdAt: new Date().toISOString(), lastLoginAt: null };
      this.users.push(u);
      this.log(this.current()?.username ?? '', 'user_create', name, true, `역할 ${u.role}`);
      return { status: 201, body: { user: this.view(u), tempPassword: temp } };
    }
    if (method === 'PATCH' && (m = path.match(/^\/users\/([^/]+)$/))) {
      const u = this.users.find((x) => x.id === decodeURIComponent(m![1]));
      if (!u) return this.err(404, '계정이 없습니다');
      const me = this.current()!;
      const admins = this.users.filter((x) => x.role === 'admin' && !x.disabled && x.id !== u.id).length;
      if (b.disabled === true && u.id === me.id) return this.err(400, MSG.selfDisable);
      const role = (b.role as MUser['role']) ?? u.role;
      const disabled = (b.disabled as boolean | undefined) ?? u.disabled;
      if (u.role === 'admin' && !u.disabled && (role !== 'admin' || disabled) && admins === 0) return this.err(409, MSG.lastAdmin);
      Object.assign(u, { role, disabled });
      if (typeof b.displayName === 'string') u.displayName = b.displayName;
      this.log(me.username, 'user_update', u.username, true);
      return { status: 200, body: this.view(u) };
    }
    if (method === 'POST' && (m = path.match(/^\/users\/([^/]+)\/(reset-password|reset-otp)$/))) {
      const u = this.users.find((x) => x.id === decodeURIComponent(m![1]));
      if (!u) return this.err(404, '계정이 없습니다');
      if (m[2] === 'reset-otp') {
        u.otpEnabled = false;
        this.log(this.current()!.username, 'otp_reset', u.username, true);
        return { status: 204 };
      }
      const temp = `Rst${String(++this.seq).padStart(4, '0')}pQrStUvW`.slice(0, 16);
      Object.assign(u, { pw: temp, mustChangePassword: true, failed: 0, lockedUntil: 0 });
      this.log(this.current()!.username, 'password_reset', u.username, true);
      return { status: 200, body: { tempPassword: temp } };
    }
    return null;
  }
}

function parseBody(body: string | undefined): Record<string, unknown> {
  try {
    return (body ? JSON.parse(body) : {}) as Record<string, unknown>;
  } catch {
    return {};
  }
}
