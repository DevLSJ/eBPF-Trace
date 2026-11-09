import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { AuthScreens, SessionCheckError, SessionChecking, type AuthStep } from '../components/AuthScreens';
import { ApiError, authApi, setAuthHooks } from '../lib/api';
import type { Me, SessionState, UserBrief } from '../lib/types';
import { useToast } from './toast-context';

// 로그인 게이트(W16). 앱 시작 때 GET /api/auth/me → active 면 앱, 아니면 그 단계 화면.
// 앱 안의 401 은 본문 state 의 단계로(없으면 로그인 + 문구), 403 은 「관리자만」 안내만 — 로그아웃하지 않는다.

const STEP_OF: Record<Exclude<SessionState, 'active'>, AuthStep> = {
  need_password: 'password',
  need_license: 'license',
  need_otp_enroll: 'otp-enroll',
  need_otp: 'otp',
};

type Gate = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'step'; step: AuthStep; notice: string; codes?: string[] } | { kind: 'active' };

// 세션 확인 실패 문구(11/09 G03): 서버가 JSON 문장을 주면 그 문장만(상태 코드 없이), 그 밖(연결 실패 · 프록시 오류)은 고정 문장
const CONNECT_FAIL = '서버에 연결하지 못했습니다. 네트워크를 확인한 뒤 다시 시도하세요.';
const checkError = (e: unknown) => (e instanceof ApiError && e.json && e.message ? e.message : CONNECT_FAIL);

interface Ctx {
  me: Me | null;
  // 옛 백엔드(/api/auth/* 없음) — 로그인 없이 관리자로 본다
  noAuth: boolean;
  isAdmin: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<Ctx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const toast = useToast();
  const [gate, setGate] = useState<Gate>({ kind: 'loading' });
  const [me, setMe] = useState<Me | null>(null);
  const [noAuth, setNoAuth] = useState(false);
  const [who, setWho] = useState<UserBrief | null>(null);
  const gen = useRef(0);

  const toStep = useCallback((state: string, notice = '') => {
    const step = STEP_OF[state as keyof typeof STEP_OF];
    setGate({ kind: 'step', step: step ?? 'login', notice: step ? '' : notice });
  }, []);

  // active 확인 → 셸. 역할 · 라이선스는 매번 me 에서 다시 읽는다
  const finish = useCallback(() => {
    const my = ++gen.current;
    return authApi.me().then(
      (m) => {
        if (my !== gen.current) return;
        setMe(m);
        setWho(m.user);
        if (m.state === 'active') setGate({ kind: 'active' });
        else toStep(m.state);
      },
      (e: unknown) => {
        if (my !== gen.current) return;
        if (e instanceof ApiError && e.status === 404 && !e.json) {
          setNoAuth(true);
          setMe({ state: 'active', user: { id: '', username: '(인증 없음)', displayName: '인증 없는 백엔드', role: 'admin' }, mustChangePassword: false, license: null, otpRequired: false });
          setGate({ kind: 'active' });
        } else if (e instanceof ApiError && e.status === 401) toStep(e.state);
        else setGate({ kind: 'error', message: checkError(e) }); // G03: 오류 + 「다시 시도」(같은 확인을 다시 부른다)
      },
    );
  }, [toStep]);

  useEffect(() => {
    void finish();
  }, [finish]);

  const refresh = useCallback(async () => {
    try {
      const m = await authApi.me();
      setMe(m);
      if (m.state !== 'active') toStep(m.state);
    } catch {
      /* 다음 요청의 401 이 처리한다 */
    }
  }, [toStep]);

  useEffect(() => {
    setAuthHooks({
      unauthorized: (state, message) => {
        gen.current++;
        toStep(state, message);
      },
      forbidden: (message) => {
        toast(`관리자만 할 수 있습니다(${message}).`, { key: 'forbidden', tone: 'warn' });
        void refresh(); // 역할이 바뀌었으면 쓰기 버튼을 숨긴다
      },
    });
    return () => setAuthHooks(null);
  }, [toStep, toast, refresh]);

  const logout = useCallback(async () => {
    gen.current++;
    await authApi.logout().catch(() => undefined);
    setMe(null);
    setGate({ kind: 'step', step: 'login', notice: '' });
  }, []);

  const value = useMemo<Ctx>(() => ({ me, noAuth, isAdmin: me?.user.role === 'admin', refresh, logout }), [me, noAuth, refresh, logout]);

  if (gate.kind === 'loading') return <SessionChecking />;
  if (gate.kind === 'error')
    return (
      <SessionCheckError
        message={gate.message}
        onRetry={() => {
          setGate({ kind: 'loading' });
          void finish();
        }}
      />
    );
  if (gate.kind === 'step')
    return (
      <AuthScreens
        step={gate.step}
        notice={gate.notice}
        codes={gate.codes}
        who={who}
        onState={(state, user) => {
          if (user) setWho(user);
          if (state === 'active') void finish();
          else toStep(state);
        }}
        onCodes={(codes) => setGate({ kind: 'step', step: 'recovery-codes', notice: '', codes })}
        onDone={() => void finish()}
        onRestart={(notice) => setGate({ kind: 'step', step: 'login', notice })}
        onSwitch={() => void logout()}
      />
    );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): Ctx {
  const c = useContext(AuthContext);
  if (!c) throw new Error('useAuth must be used inside AuthProvider');
  return c;
}
