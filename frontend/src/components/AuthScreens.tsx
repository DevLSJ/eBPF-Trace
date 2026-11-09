import { Copy, Download, ShieldCheck } from 'lucide-react';
import QRCode from 'qrcode';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { ApiError, authApi } from '../lib/api';
import { AUTH_MSG, validatePassword } from '../lib/auth';
import type { SessionState, UserBrief } from '../lib/types';
import { KeyBoxes } from './KeyBoxes';

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
const ghost = 'inline-flex items-center gap-1 justify-self-start rounded px-2 py-1 text-xs text-slate-600 hover:bg-slate-100';

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
    <div
      data-part="auth"
      data-step={p.step}
      className="flex min-h-full items-center justify-center bg-bg px-4 py-8"
    >
      <div className="grid w-[400px] max-w-full gap-3 rounded-[12px] border border-card-line bg-surface p-7 shadow-[var(--sh-md)]">
        <div className="flex items-center gap-2 font-semibold text-slate-900">
          <ShieldCheck className="size-5 text-indigo-500" aria-hidden /> SupplyGuard
        </div>
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
      </div>
    </div>
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

function LoginStep({ run, busy, onState }: StepProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  return (
    <>
      <Head title="로그인" />
      <form
        className="grid gap-3"
        onSubmit={submitting(() =>
          void run(
            () => authApi.login(username, password),
            (r) => onState(r.state, r.user),
            () => setPassword(''),
          ),
        )}
      >
        <Field label="아이디">
          <input className={input} name="username" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} />
        </Field>
        <Field label="비밀번호">
          <input className={input} name="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <button type="submit" className={primary} disabled={busy}>
          로그인
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
      <Head title="비밀번호 변경" desc="처음 로그인했습니다. 새 비밀번호를 정하세요 — 5자 이상, 아이디와 다르게." />
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

const copy = (t: string) => {
  try {
    void navigator.clipboard?.writeText(t).catch(() => {});
  } catch {
    /* 복사 차단 */
  }
};

// OTP 등록: 서버가 준 otpauth:// uri 를 이 번들의 qrcode 로 SVG QR 로 만든다(외부 요청 없음)
function OtpEnrollStep({ run, busy, onCodes, setError }: StepProps) {
  const [enroll, setEnroll] = useState<{ secret: string; uri: string; qr: string } | null>(null);
  const [code, setCode] = useState('');
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
      <Head title="OTP 등록" desc="인증 앱(Google Authenticator 등)으로 QR 을 찍거나 키를 직접 넣은 뒤, 앱에 나온 6자리를 입력하세요." />
      <form className="grid gap-3" onSubmit={submitting(() => void run(() => authApi.otpConfirm(code.trim()), (r) => onCodes(r.recoveryCodes)))}>
        <div className="grid justify-items-center gap-2 py-2" data-part="qr">
          {enroll ? (
            <>
              <img src={enroll.qr} width={168} height={168} alt="OTP 등록 QR — 인증 앱으로 찍으세요" className="rounded border border-slate-200 bg-white" />
              <div className="flex flex-wrap items-center justify-center gap-1.5 text-xs">
                <span className="text-slate-500">직접 입력할 키</span>
                <code className="rounded bg-slate-100 px-2 py-1 font-mono" data-part="otp-secret">
                  {enroll.secret.replace(/(.{4})/g, '$1 ').trim()}
                </code>
                <button type="button" className={ghost} onClick={() => copy(enroll.secret)}>
                  <Copy className="size-3" aria-hidden /> 복사
                </button>
              </div>
            </>
          ) : (
            <span className="text-xs text-slate-400">불러오는 중…</span>
          )}
        </div>
        <Field label="앱에 나온 6자리">
          <input className={`${input} text-center font-mono text-lg tracking-[0.3em]`} name="code" inputMode="numeric" maxLength={6} autoComplete="one-time-code" placeholder="123456" value={code} onChange={(e) => setCode(e.target.value)} />
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
      <Head title="복구 코드 — 지금 한 번만 보입니다" desc="휴대폰을 잃어버렸을 때 OTP 대신 쓰는 코드입니다. 안전한 곳에 보관하세요. 코드 하나는 한 번만 쓸 수 있습니다." />
      <div className="grid gap-3">
        <ol className="grid list-inside list-decimal grid-cols-2 gap-x-4 gap-y-1.5 rounded-lg bg-slate-50 px-4 py-3 font-mono text-[13px]" data-part="recovery-codes">
          {codes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ol>
        <div className="flex gap-1">
          <button type="button" className={ghost} onClick={() => copy(text)}>
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
  const submit = () => void run(() => authApi.otp(recovery ? { recovery: value } : { code: value.trim() }), (r) => onState(r.state));
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
            <input key="code" className={`${input} text-center font-mono text-lg tracking-[0.3em]`} name="code" inputMode="numeric" maxLength={6} autoComplete="one-time-code" autoFocus placeholder="123456" value={value} onChange={(e) => setValue(e.target.value)} />
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
          }}
        >
          {recovery ? 'OTP 코드로 로그인' : '복구 코드로 로그인'}
        </button>
      </form>
    </>
  );
}
