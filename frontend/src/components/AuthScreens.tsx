import { Copy, Download, Eye, EyeOff, RotateCw, ShieldCheck } from 'lucide-react';
import QRCode from 'qrcode';
import { useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent, type ReactNode, type RefObject } from 'react';
import { useToast } from '../hooks/toast-context';
import { ApiError, authApi } from '../lib/api';
import { AUTH_MSG, validatePassword } from '../lib/auth';
import type { SessionState, UserBrief } from '../lib/types';
import { KeyBoxes } from './KeyBoxes';
import { ThemeToggle } from './ThemeToggle';

// 로그인 단계 화면(W16) — 목업 shared/auth.js 의 카드 · 문구 그대로.
// 로그인 → (첫 로그인) 비밀번호 변경 → (라이선스 없음 · 관리자) 라이선스 → OTP 등록 → 복구 코드 / OTP 입력(복구 코드 전환)

export type AuthStep = 'login' | 'password' | 'license' | 'otp-enroll' | 'recovery-codes' | 'otp';

interface Props {
  step: AuthStep;
  notice: string;
  codes?: string[];
  who: UserBrief | null;
  onState: (state: SessionState, user?: UserBrief) => void;
  onCodes: (codes: string[]) => void;
  onDone: () => void;
  onRestart: (notice: string) => void;
  onSwitch: () => void;
}

const input = 'h-9 w-full rounded-[6px] border border-slate-300 bg-field px-2.5 text-sm focus:border-indigo-500 focus:outline-none';
const primary = 'flex h-9 items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-fg transition-colors duration-[var(--t-btn)] ease-in-out hover:bg-primary-hover disabled:opacity-50';
const ghostBase = 'inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-600 hover:bg-slate-100';
const ghost = `${ghostBase} justify-self-start`;
// 빈 칸 표시(11/09 G25) — 고치면 바로 지운다
const invalid = 'aria-invalid:border-red-500';

export function AuthScreens(p: Props) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  // 단계가 바뀌면 이전 단계의 오류를 지운다 (렌더 중 상태 조정 — 이펙트 없이)
  const [shown, setShown] = useState(p.step);
  if (shown !== p.step) {
    setShown(p.step);
    setError('');
  }
  const msg = error || (p.step === 'login' ? p.notice : '');

  // 단계 API 호출: 401 은 처음부터(OTP 여러 번 틀림 · 세션 만료), 그 밖은 카드 안 문구
  const run = async <T,>(f: () => Promise<T>, ok: (r: T) => void, onFail?: () => void) => {
    setBusy(true);
    setError('');
    try {
      ok(await f());
    } catch (e) {
      onFail?.();
      if (e instanceof ApiError && e.status === 401 && p.step !== 'login') p.onRestart(e.message);
      else setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const common = { error: msg, busy, run, setError };

  let body: ReactNode;
  if (p.step === 'login') body = <LoginStep {...p} {...common} />;
  else if (p.step === 'password') body = <PasswordStep {...p} {...common} />;
  else if (p.step === 'license') body = <LicenseStep {...p} {...common} />;
  else if (p.step === 'otp-enroll') body = <OtpEnrollStep {...p} {...common} />;
  else if (p.step === 'recovery-codes') body = <RecoveryCodes codes={p.codes ?? []} onDone={p.onDone} />;
  else body = <OtpStep {...p} {...common} />;

  return (
    <AuthCard part="auth" attrs={{ 'data-step': p.step }}>
      {body}
      {msg && (
        <p role="alert" data-part="auth-error" className="rounded-md bg-red-50 px-2.5 py-2 text-[13px] text-red-700">
          {msg}
        </p>
      )}
      {p.step !== 'login' && (
        <button type="button" className={ghost} onClick={p.onSwitch}>
          다른 계정으로 로그인
        </button>
      )}
    </AuthCard>
  );
}

// 로그인 단계 · 세션 확인이 같이 쓰는 가운데 카드(11/09 G02 · G03 — 표시만)
function AuthCard({ part, attrs, cardAttrs, children }: { part: string; attrs?: Record<string, string>; cardAttrs?: Record<string, string>; children: ReactNode }) {
  return (
    <div data-part={part} {...attrs} className="relative flex min-h-full items-center justify-center bg-bg px-4 py-8">
      <div {...cardAttrs} className="grid w-[400px] max-w-full gap-3 rounded-[12px] border border-card-line bg-surface p-7 shadow-[var(--sh-md)]">
        <div className="flex items-center gap-2 font-semibold text-slate-900">
          <ShieldCheck className="size-5 text-indigo-500" aria-hidden /> SupplyGuard
        </div>
        {children}
      </div>
      {/* 11/09 G01 해/달 단추 — 셸 머리와 같은 부품, 로그인 · 세션 확인 화면 오른쪽 위(인증 흐름과 무관한 표시).
          자리는 absolute 라 카드 뒤에 둔다 — 카드가 이 틀의 첫 div 로 남는다(카드 모양 시험이 그렇게 찾음) */}
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
    </div>
  );
}

// G02 세션 확인 중(GET /api/auth/me 응답 전) — 카드 모양 스켈레톤 + 한 문장
export function SessionChecking() {
  return (
    <AuthCard part="auth-loading" attrs={{ 'aria-busy': 'true' }}>
      <i className="sg-skeleton block h-6 w-20" aria-hidden />
      <i className="sg-skeleton block h-9 w-full" aria-hidden />
      <i className="sg-skeleton block h-9 w-full" aria-hidden />
      <i className="sg-skeleton block h-9 w-full" aria-hidden />
      <p role="status" className="text-[13px] text-slate-500">
        로그인 정보를 확인하는 중입니다.
      </p>
    </AuthCard>
  );
}

// G03 세션 확인 실패(401 · 옛 백엔드 404 밖) — 오류 + 「다시 시도」(같은 확인 요청을 다시 부른다)
export function SessionCheckError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <AuthCard part="auth-check-error" cardAttrs={{ role: 'alert' }}>
      <h2 className="text-lg font-semibold text-slate-900">로그인 정보를 확인하지 못했습니다.</h2>
      <p className="text-[13px] text-slate-500" data-part="auth-check-message">
        {message}
      </p>
      <button type="button" className={`${primary} gap-1.5`} data-action="retry" onClick={onRetry}>
        <RotateCw className="size-4" aria-hidden /> 다시 시도
      </button>
    </AuthCard>
  );
}

type StepProps = Props & {
  error: string;
  busy: boolean;
  run: <T>(f: () => Promise<T>, ok: (r: T) => void, onFail?: () => void) => Promise<void>;
  setError: (s: string) => void;
};

function Head({ title, desc }: { title: string; desc?: string }) {
  return (
    <>
      <h2 className="text-lg font-semibold text-slate-900">{title}</h2>
      {desc && <p className="text-[13px] text-slate-500">{desc}</p>}
    </>
  );
}
function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="grid gap-1 text-sm">
      <b className="font-medium text-slate-700">{label}</b>
      {children}
    </label>
  );
}
const submitting = (f: () => void) => (e: FormEvent) => {
  e.preventDefault();
  f();
};

// 칸 아래 한 줄(빈 값 · Caps Lock) — 11/09 G25 · G26
const fieldNote = 'text-[12.5px] leading-snug';

function LoginStep({ run, busy, onState }: StepProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  // G25: 빈 칸이면 서버로 보내지 않고 칸 아래 문구(보내는 값 · 순서는 그대로 — 둘 다 차 있을 때만 예전과 같은 요청)
  const [missing, setMissing] = useState({ username: false, password: false });
  // G26: 비밀번호 보기 · Caps Lock 안내
  const [reveal, setReveal] = useState(false);
  const [caps, setCaps] = useState(false);
  const idRef = useRef<HTMLInputElement>(null);
  const pwRef = useRef<HTMLInputElement>(null);
  const uid = useId();
  const ids = { username: `${uid}-id`, password: `${uid}-pw`, idErr: `${uid}-id-err`, pwErr: `${uid}-pw-err`, caps: `${uid}-caps` };
  const submit = () => {
    const miss = { username: !username.trim(), password: !password };
    if (miss.username || miss.password) {
      setMissing(miss);
      (miss.username ? idRef : pwRef).current?.focus();
      return;
    }
    const tried = password;
    void run(
      () => authApi.login(username, password),
      (r) => onState(r.state, r.user),
      // G27: 실패하면 비밀번호 칸을 비우고(예전과 같음) 그 칸에 초점. 응답을 기다리는 사이 새로 입력한 값은 지우지 않는다
      // (늦은 실패 응답이 새 값을 지우면 다음 「로그인」이 빈 값 검사에 걸려 서버로 가지 않는다 — 11/09 실측)
      () => {
        setPassword((now) => (now === tried ? '' : now));
        pwRef.current?.focus();
      },
    );
  };
  const capsCheck = (e: KeyboardEvent<HTMLInputElement>) => setCaps(e.getModifierState('CapsLock'));
  const pwDescribed = [missing.password && ids.pwErr, caps && ids.caps].filter(Boolean).join(' ') || undefined;
  return (
    <>
      <Head title="로그인" />
      <form
        className="grid gap-3"
        noValidate
        aria-busy={busy || undefined}
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div className="grid gap-1 text-sm">
          <label htmlFor={ids.username} className="font-medium text-slate-700">
            아이디
          </label>
          <input
            ref={idRef}
            id={ids.username}
            className={`${input} ${invalid}`}
            name="username"
            autoComplete="username"
            autoFocus
            value={username}
            aria-invalid={missing.username || undefined}
            aria-describedby={missing.username ? ids.idErr : undefined}
            onChange={(e) => {
              setUsername(e.target.value);
              if (missing.username) setMissing((m) => ({ ...m, username: false }));
            }}
          />
          {missing.username && (
            <span id={ids.idErr} data-part="field-error" data-for="username" className={`${fieldNote} text-red-700`}>
              아이디를 입력하세요.
            </span>
          )}
        </div>
        <div className="grid gap-1 text-sm">
          <label htmlFor={ids.password} className="font-medium text-slate-700">
            비밀번호
          </label>
          <div className="relative">
            <input
              ref={pwRef}
              id={ids.password}
              className={`${input} ${invalid} pr-10`}
              name="password"
              type={reveal ? 'text' : 'password'}
              autoComplete="current-password"
              value={password}
              aria-invalid={missing.password || undefined}
              aria-describedby={pwDescribed}
              onChange={(e) => {
                setPassword(e.target.value);
                if (missing.password) setMissing((m) => ({ ...m, password: false }));
              }}
              onKeyDown={capsCheck}
              onKeyUp={capsCheck}
              onBlur={() => setCaps(false)}
            />
            <button
              type="button"
              data-action="reveal-password"
              className="absolute inset-y-0 right-0 flex w-9 items-center justify-center rounded-r-[6px] text-slate-500 hover:text-slate-800 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-indigo-500"
              aria-label={reveal ? '숨기기(비밀번호)' : '보기(비밀번호)'}
              title={reveal ? '숨기기(비밀번호)' : '보기(비밀번호)'}
              aria-pressed={reveal}
              aria-controls={ids.password}
              onClick={() => setReveal((v) => !v)}
            >
              {reveal ? <EyeOff className="size-4" aria-hidden /> : <Eye className="size-4" aria-hidden />}
            </button>
          </div>
          {missing.password && (
            <span id={ids.pwErr} data-part="field-error" data-for="password" className={`${fieldNote} text-red-700`}>
              비밀번호를 입력하세요.
            </span>
          )}
          {caps && (
            <span id={ids.caps} data-part="caps-lock" role="status" className={`${fieldNote} text-amber-800`}>
              Caps Lock이 켜져 있습니다.
            </span>
          )}
        </div>
        <button type="submit" className={primary} disabled={busy}>
          {busy ? '로그인 중…' : '로그인'}
        </button>
      </form>
    </>
  );
}

function PasswordStep({ run, busy, onState, who, setError }: StepProps) {
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const submit = () => {
    const bad = validatePassword(who?.username ?? '', next) || (next !== confirm ? AUTH_MSG.mismatch : '');
    if (bad) return setError(bad);
    void run(() => authApi.password(cur, next), (r) => onState(r.state));
  };
  return (
    <>
      <Head title="비밀번호 변경" desc="처음 로그인했습니다. 새 비밀번호를 정하세요(5자 이상, 아이디와 다르게)." />
      <form className="grid gap-3" onSubmit={submitting(submit)}>
        <Field label="지금 비밀번호">
          <input className={input} type="password" name="current" autoComplete="current-password" autoFocus value={cur} onChange={(e) => setCur(e.target.value)} />
        </Field>
        <Field label="새 비밀번호">
          <input className={input} type="password" name="next" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Field label="새 비밀번호 확인">
          <input className={input} type="password" name="confirm" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </Field>
        <button type="submit" className={primary} disabled={busy}>
          바꾸고 계속
        </button>
      </form>
    </>
  );
}

function LicenseStep({ run, busy, onState }: StepProps) {
  const [key, setKey] = useState(['', '', '', '']);
  const submit = () => void run(() => authApi.license(key.join('-')), (r) => onState(r.state));
  return (
    <>
      <Head title="라이선스 등록" desc="이 서버에 라이선스가 없습니다. 받은 키 16자리를 넣으세요(XXXX-XXXX-XXXX-XXXX). 붙여넣으면 네 칸에 나눠 들어갑니다." />
      <div className="grid gap-3">
        <KeyBoxes value={key} onChange={setKey} label="라이선스 키" onEnter={() => !busy && submit()} />
        <button type="button" className={primary} disabled={busy} onClick={submit}>
          등록하고 계속
        </button>
      </div>
    </>
  );
}

// 복사 — 성공 · 실패를 토스트로 알린다(11/09 G29). 클립보드가 막히면(비보안 주소 등) 직접 고르게 안내
async function copyText(t: string) {
  try {
    await navigator.clipboard.writeText(t);
    return true;
  } catch {
    return false;
  }
}
function useCopy() {
  const toast = useToast();
  return (t: string, what: string) =>
    void copyText(t).then((ok) =>
      ok ? toast('복사했습니다.', { key: 'auth-copy', tone: 'ok' }) : toast(`복사하지 못했습니다. ${what}를 직접 선택해 복사하세요.`, { key: 'auth-copy', tone: 'warn' }),
    );
}

// G30 OTP 6자리 자동 확인: 6자리가 차면 잠깐(AUTO_MS) 뒤 한 번 보낸다. 그 사이 확인 · Enter 를 누르면 그쪽 한 번만.
// 자동 확인이 틀리면 칸을 비우고 초점 — 다시 자동으로 보내지 않는다(한 단계에 한 번). 비운 직후 빈 칸 확인은 보내지 않는다.
// 보내는 요청 · 값은 확인 단추와 같다(send 그대로)
const AUTO_MS = 300;
function useOtpAuto(ref: RefObject<HTMLInputElement | null>, send: (code: string, onFail?: () => void) => Promise<void>, ready: boolean) {
  const [code, setCode] = useState('');
  const used = useRef(false);
  const cleared = useRef(false);
  const inflight = useRef(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const go = (v: string, auto: boolean) => {
    window.clearTimeout(timer.current);
    if (inflight.current) return; // 자동 확인과 Enter 가 겹침 — 이미 보내는 중
    if (!auto && cleared.current && !v) return ref.current?.focus();
    inflight.current = true;
    const onFail = auto
      ? () => {
          setCode('');
          cleared.current = true;
          ref.current?.focus();
        }
      : undefined;
    void send(v, onFail).finally(() => {
      inflight.current = false;
    });
  };
  const change = (v: string) => {
    setCode(v);
    cleared.current = false;
    window.clearTimeout(timer.current);
    if (ready && !used.current && /^\d{6}$/.test(v.trim()))
      timer.current = window.setTimeout(() => {
        used.current = true;
        go(v, true);
      }, AUTO_MS);
  };
  const reset = () => {
    window.clearTimeout(timer.current);
    cleared.current = false;
    setCode('');
  };
  return { code, change, submit: () => go(code, false), reset };
}

// OTP 등록: 서버가 준 otpauth:// uri 를 이 번들의 qrcode 로 SVG QR 로 만든다(외부 요청 없음)
// 등록 3단계 안내(11/09 G29) — 앱 설치 → QR 읽기 → 코드 입력
const ENROLL_STEPS = ['인증 앱 설치', 'QR 읽기', '코드 입력'];

function OtpEnrollStep({ run, busy, onCodes, setError }: StepProps) {
  const [enroll, setEnroll] = useState<{ secret: string; uri: string; qr: string } | null>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  const otp = useOtpAuto(codeRef, (c, onFail) => run(() => authApi.otpConfirm(c.trim()), (r) => onCodes(r.recoveryCodes), onFail), !!enroll);
  // 수동 입력 키는 접어 둔다(G29) — 「키 보기」
  const [showKey, setShowKey] = useState(false);
  const copy = useCopy();
  const keyId = useId();
  useEffect(() => {
    let live = true;
    authApi
      .otpEnroll()
      .then(async (r) => {
        const svg = await QRCode.toString(r.uri, { type: 'svg', errorCorrectionLevel: 'M', margin: 2 });
        if (live) setEnroll({ ...r, qr: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}` });
      })
      .catch((e: unknown) => live && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
  }, [setError]);
  return (
    <>
      <Head title="OTP 등록" desc="Google Authenticator 등 인증 앱으로 QR을 읽고, 앱에 나온 6자리를 입력합니다." />
      <ol className="grid grid-cols-3 gap-1.5" data-part="otp-steps" aria-label="OTP 등록 단계">
        {ENROLL_STEPS.map((t, i) => (
          <li key={t} className="flex min-w-0 items-center gap-1.5 rounded-md bg-slate-50 px-2 py-1.5 text-xs font-medium text-slate-700">
            <b className="grid size-5 shrink-0 place-items-center rounded-full bg-indigo-50 text-[11px] font-semibold text-indigo-700" aria-hidden>
              {i + 1}
            </b>
            <span className="min-w-0 break-keep">{t}</span>
          </li>
        ))}
      </ol>
      <form
        className="grid gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          otp.submit();
        }}
      >
        <div className="grid justify-items-center gap-2 py-1" data-part="qr">
          {enroll ? (
            <>
              <img src={enroll.qr} width={168} height={168} alt="OTP 등록 QR(인증 앱으로 찍으세요)" className="rounded border border-slate-200 bg-white" />
              <button type="button" className={`${ghostBase} justify-self-center`} data-action="otp-key" aria-expanded={showKey} aria-controls={keyId} onClick={() => setShowKey((v) => !v)}>
                {showKey ? '키 숨기기' : '키 보기'}
              </button>
              <div id={keyId} hidden={!showKey} className="flex flex-wrap items-center justify-center gap-1.5 text-xs">
                <span className="text-slate-500">직접 입력할 키</span>
                <code className="rounded bg-slate-100 px-2 py-1 font-mono" data-part="otp-secret">
                  {enroll.secret.replace(/(.{4})/g, '$1 ').trim()}
                </code>
                <button type="button" className={ghost} aria-label="복사(키)" title="복사(키)" onClick={() => copy(enroll.secret, '키')}>
                  <Copy className="size-3" aria-hidden /> 복사
                </button>
              </div>
            </>
          ) : (
            <span className="text-xs text-slate-400">불러오는 중…</span>
          )}
        </div>
        <Field label="앱에 나온 6자리">
          <input ref={codeRef} className={`${input} text-center font-mono text-lg tracking-[0.3em]`} name="code" inputMode="numeric" maxLength={6} autoComplete="one-time-code" placeholder="123456" value={otp.code} onChange={(e) => otp.change(e.target.value)} />
        </Field>
        <button type="submit" className={primary} disabled={busy || !enroll}>
          확인
        </button>
      </form>
    </>
  );
}

// 복구 코드 10개 — 이 화면에서 한 번만. 「저장했습니다」를 체크해야 진행 버튼이 생긴다
function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const copy = useCopy();
  const text = codes.join('\n');
  const download = () => {
    const url = URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'supplyguard-recovery-codes.txt';
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };
  return (
    <>
      <Head title="복구 코드(지금 한 번만 보입니다)" desc="휴대폰을 잃어버렸을 때 OTP 대신 쓰는 코드입니다. 안전한 곳에 보관하세요. 코드 하나는 한 번만 쓸 수 있습니다." />
      <div className="grid gap-3">
        <ol className="grid list-inside list-decimal grid-cols-2 gap-x-4 gap-y-1.5 rounded-lg bg-slate-50 px-4 py-3 font-mono text-[13px]" data-part="recovery-codes">
          {codes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ol>
        <div className="flex gap-1">
          <button type="button" className={ghost} onClick={() => copy(text, '복구 코드')}>
            <Copy className="size-3" aria-hidden /> 복사
          </button>
          <button type="button" className={ghost} onClick={download}>
            <Download className="size-3" aria-hidden /> 텍스트로 받기
          </button>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" name="saved" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> 복구 코드를 안전한 곳에 저장했습니다
        </label>
        {saved && (
          <button type="button" className={primary} onClick={onDone}>
            시작하기
          </button>
        )}
      </div>
    </>
  );
}

function OtpStep({ run, busy, onState }: StepProps) {
  const [recovery, setRecovery] = useState(false);
  const [value, setValue] = useState('');
  const codeRef = useRef<HTMLInputElement>(null);
  const otp = useOtpAuto(codeRef, (c, onFail) => run(() => authApi.otp({ code: c.trim() }), (r) => onState(r.state), onFail), true);
  const submit = () => (recovery ? void run(() => authApi.otp({ recovery: value }), (r) => onState(r.state)) : otp.submit());
  return (
    <>
      <Head
        title={recovery ? '복구 코드로 로그인' : 'OTP 인증'}
        desc={recovery ? '처음 등록할 때 받은 복구 코드 하나를 넣으세요. 한 번 쓴 코드는 다시 쓸 수 없습니다.' : '인증 앱에 나온 6자리를 입력하세요.'}
      />
      <form className="grid gap-3" onSubmit={submitting(submit)}>
        {recovery ? (
          <Field label="복구 코드">
            <input key="recovery" className={`${input} font-mono`} name="recovery" autoComplete="off" autoFocus placeholder="XXXX-XXXX" value={value} onChange={(e) => setValue(e.target.value)} />
          </Field>
        ) : (
          <Field label="OTP 6자리">
            <input key="code" ref={codeRef} className={`${input} text-center font-mono text-lg tracking-[0.3em]`} name="code" inputMode="numeric" maxLength={6} autoComplete="one-time-code" autoFocus placeholder="123456" value={otp.code} onChange={(e) => otp.change(e.target.value)} />
          </Field>
        )}
        <button type="submit" className={primary} disabled={busy}>
          확인
        </button>
        <button
          type="button"
          className={ghost}
          onClick={() => {
            setRecovery((r) => !r);
            setValue('');
            otp.reset();
          }}
        >
          {recovery ? 'OTP 코드로 로그인' : '복구 코드로 로그인'}
        </button>
      </form>
    </>
  );
}
