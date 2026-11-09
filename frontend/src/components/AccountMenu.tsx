import { ChevronDown, UserRound } from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/auth-context';
import { useToast } from '../hooks/toast-context';
import { authApi } from '../lib/api';
import { AUTH_MSG, licenseText, licenseTone, PW_MIN, ROLE_KO, validatePassword } from '../lib/auth';
import { fmtDateTime } from '../lib/format';
import { THEME_LABEL, THEME_PREFS, useTheme } from '../lib/theme';
import { Modal } from './Modal';

// 상단 오른쪽: 라이선스 칩 + 계정 메뉴(내 정보 · 비밀번호 변경 · 로그아웃) [W16, 목업 auth.js headerEl]
const TONE: Record<string, string> = {
  ok: 'bg-emerald-50 text-emerald-700',
  warn: 'bg-amber-100 text-amber-800',
  danger: 'bg-red-100 text-red-700',
  none: 'bg-slate-100 text-slate-600',
};

export function AccountMenu() {
  const { me, noAuth, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const [dialog, setDialog] = useState<'profile' | 'password' | null>(null);
  const wrap = useRef<HTMLSpanElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const [theme, setTheme] = useTheme();

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('click', onDoc);
    return () => document.removeEventListener('click', onDoc);
  }, [open]);

  if (!me) return null;
  const lic = me.license;
  const tone = noAuth ? 'none' : licenseTone(lic);
  const pick = (f: () => void) => () => {
    setOpen(false);
    f();
  };

  return (
    <span className="flex shrink-0 items-center gap-2">
      <Link
        to="/settings?tab=license"
        data-part="license-chip"
        data-tone={tone}
        title={lic ? `${lic.keyMasked} · 만료 ${fmtDateTime(lic.expiresAt)}` : undefined}
        className={`hidden rounded-full px-2 py-0.5 text-xs whitespace-nowrap md:inline ${TONE[tone]}`}
      >
        {noAuth ? '인증 없음' : licenseText(lic)}
      </Link>
      <span className="relative" ref={wrap}>
        <button
          ref={btn}
          type="button"
          data-part="account"
          aria-haspopup="menu"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-700 hover:bg-slate-100"
        >
          <UserRound className="size-4" aria-hidden />
          <span className="hidden md:inline">
            {me.user.displayName} · {ROLE_KO[me.user.role] ?? me.user.role}
          </span>
          <ChevronDown className="size-3.5" aria-hidden />
        </button>
        {open && (
          <div
            role="menu"
            data-part="account-menu"
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setOpen(false);
                btn.current?.focus();
              }
            }}
            className="tk-pop-in absolute top-[calc(100%+6px)] right-0 z-40 grid min-w-40 rounded-lg border border-border bg-raised p-1 shadow-[var(--sh-2)]"
          >
            {[
              ['내 정보', () => setDialog('profile')] as const,
              ...(noAuth
                ? []
                : ([
                    ['비밀번호 변경', () => setDialog('password')],
                    ['로그아웃', () => void logout()],
                  ] as const)),
            ].map(([label, run], i) => (
              <button
                key={label}
                type="button"
                role="menuitem"
                autoFocus={i === 0}
                onClick={pick(run)}
                className="rounded-md px-2.5 py-2 text-left text-[13px] hover:bg-slate-100 focus:bg-slate-100 focus:outline-none"
              >
                {label}
              </button>
            ))}
            {/* 테마(10/30 계약 §7): 시스템 · 라이트 · 다크 — localStorage supplyguard.theme */}
            <div className="my-1 border-t border-border" role="separator" />
            <div className="px-2.5 pt-0.5 text-[11px] text-text-3">테마</div>
            <div className="flex gap-1 p-1" role="group" aria-label="테마">
              {THEME_PREFS.map((t) => (
                <button
                  key={t}
                  type="button"
                  role="menuitemradio"
                  aria-checked={theme === t}
                  data-theme-pick={t}
                  onClick={() => setTheme(t)}
                  className={`flex-1 rounded-md px-2 py-1 text-xs ${theme === t ? 'bg-accent-soft font-medium text-accent-text' : 'text-text-2 hover:bg-surface-2'}`}
                >
                  {THEME_LABEL[t]}
                </button>
              ))}
            </div>
          </div>
        )}
      </span>
      {dialog === 'profile' && <Profile onClose={() => setDialog(null)} />}
      {dialog === 'password' && <ChangePassword onClose={() => setDialog(null)} />}
    </span>
  );
}

function Profile({ onClose }: { onClose: () => void }) {
  const { me } = useAuth();
  if (!me) return null;
  const u = me.user;
  const l = me.license;
  const rows: [string, ReactNode][] = [
    ['아이디', <span className="font-mono">{u.username}</span>],
    ['이름', u.displayName],
    ['역할', ROLE_KO[u.role] ?? u.role],
    ['라이선스', <>{licenseText(l)}{l && <span className="text-xs text-slate-500"> · {l.keyMasked} · 만료 {fmtDateTime(l.expiresAt)}</span>}</>],
    ['OTP', me.otpRequired ? '등록됨' : '서버 설정으로 꺼짐'],
  ];
  return (
    <Modal title="내 정보" kind="profile" onClose={onClose}>
      <dl className="grid grid-cols-[5rem_1fr] gap-x-3 gap-y-2 text-sm">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-slate-500">{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </Modal>
  );
}

function ChangePassword({ onClose }: { onClose: () => void }) {
  const { me } = useAuth();
  const toast = useToast();
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const save = async () => {
    const bad = validatePassword(me?.user.username ?? '', next) || (next !== confirm ? AUTH_MSG.mismatch : '');
    if (bad) return setMsg(bad);
    setBusy(true);
    try {
      await authApi.password(cur, next, false);
      onClose();
      toast('비밀번호를 바꿨습니다', { key: 'password', tone: 'ok' });
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const field = (label: string, v: string, set: (s: string) => void, auto: string) => (
    <label className="grid gap-1 text-sm">
      <b className="font-medium text-slate-700">{label}</b>
      <input type="password" autoComplete={auto} value={v} onChange={(e) => set(e.target.value)} className="h-9 rounded-[var(--r-md)] border border-slate-300 px-2.5 focus:border-indigo-500 focus:outline-none" />
    </label>
  );
  return (
    <Modal
      title="비밀번호 변경"
      kind="password"
      onClose={onClose}
      guard={() => !!(cur || next || confirm)}
      foot={
        <>
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-100">
            취소
          </button>
          <button type="button" disabled={busy} onClick={() => void save()} className="rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-fg hover:bg-primary-hover disabled:opacity-50">
            바꾸기
          </button>
        </>
      }
    >
      <div className="grid gap-3">
        {field('지금 비밀번호', cur, setCur, 'current-password')}
        {field(`새 비밀번호 (${PW_MIN}자 이상, 아이디와 다르게)`, next, setNext, 'new-password')}
        {field('새 비밀번호 확인', confirm, setConfirm, 'new-password')}
        {msg && (
          <p role="alert" className="text-xs text-red-600">
            {msg}
          </p>
        )}
      </div>
    </Modal>
  );
}
