/* 실제 백엔드(live) 회귀용 로그인 도우미 [10/21] — 쿠키 세션을 브라우저 컨텍스트에 심는다.
   개발 백엔드(make dev · 메모리 저장소)는 11/04 부터 AUTH_DEV_MODE 로 admin/admin 로그인이 바로 active 다(OTP 도 끔).
   개발 모드 없이 띄운 백엔드는 첫 로그인에 비밀번호 변경 · 라이선스 단계가 있어 그 단계를 API 로 끝낸다.
   - 처음 비밀번호: 환경 변수 ADMIN_PW, 없으면 저장소 Makefile 의 DEV_ADMIN_PW(개발 전용 고정값)
   - 바꾼 비밀번호: LIVE_TEST_PW(기본은 아래 테스트 전용 값 — 메모리 저장소라 백엔드를 다시 띄우면 처음으로 돌아간다)
   - 라이선스: 숫자 16자리 형식만 보는 평가판 키(가짜)
   Node 에서 부르고(브라우저 콘솔에 401 이 찍히지 않게) 받은 세션 쿠키를 컨텍스트에 넣는다. 쿠키가 생긴 뒤의 쓰기는 Origin(목업 주소)을 붙여 CSRF 검사를 지난다 */
const fs = require('fs');
const path = require('path');

function devPassword() {
  if (process.env.ADMIN_PW) return process.env.ADMIN_PW;
  try {
    const mk = fs.readFileSync(path.join(__dirname, '..', '..', 'Makefile'), 'utf8');
    const m = mk.match(/^DEV_ADMIN_PW\s*:?=\s*(\S+)/m);
    return m ? m[1] : '';
  } catch { return ''; }
}
const TEST_PW = process.env.LIVE_TEST_PW || 'mock-live-1021';
const TRIAL_KEY = '1021-0000-0000-2026';

// pg: 목업 페이지가 열린 Page(Origin 으로 그 주소를 쓴다). api: 백엔드 주소. 끝나면 'active'(아니면 오류)
async function liveLogin(pg, api) {
  const origin = new URL(pg.url()).origin;
  let cookie = '';
  const call = async (method, p, body) => {
    const headers = { Origin: origin };
    if (body) headers['Content-Type'] = 'application/json';
    if (cookie) headers.Cookie = cookie;
    const res = await fetch(api + p, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    let data = null; try { data = await res.json(); } catch { /* 본문 없음 */ }
    return { status: res.status, data };
  };
  let st = '', used = '';
  for (const pw of [TEST_PW, devPassword()]) {
    if (!pw) continue;
    const x = await call('POST', '/api/auth/login', { username: 'admin', password: pw });
    if (x.status === 200) { st = x.data.state; used = pw; break; }
  }
  if (!st) throw new Error('로그인 실패(비밀번호 확인)');
  if (st === 'need_password') { const x = await call('POST', '/api/auth/password', { current: used, next: TEST_PW }); if (x.status !== 200) throw new Error(`비밀번호 변경 ${x.status}`); st = x.data.state; }
  if (st === 'need_license') { const x = await call('POST', '/api/auth/license', { key: TRIAL_KEY }); if (x.status !== 200) throw new Error(`라이선스 ${x.status}`); st = x.data.state; }
  if (st !== 'active') throw new Error(`로그인 단계가 남음: ${st}`);
  const [name, ...rest] = cookie.split('=');
  await pg.context().addCookies([{ name, value: rest.join('='), url: api, httpOnly: true, sameSite: 'Strict' }]);
  return st;
}

module.exports = { liveLogin };
