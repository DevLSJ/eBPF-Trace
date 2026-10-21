import { KeyRound, Plus, Send } from 'lucide-react';
import { useCallback, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { KeyBoxes } from '../../components/KeyBoxes';
import { ConfirmDialog, Modal } from '../../components/Modal';
import { Empty, LoadError } from '../../components/Panel';
import { useAuth } from '../../hooks/auth-context';
import { useToast } from '../../hooks/toast-context';
import { useLoad } from '../../hooks/useLoad';
import { api, ApiError, authApi, errorText } from '../../lib/api';
import { AUTH_MSG, daysLeft, licenseText, ROLE_KO } from '../../lib/auth';
import { fmtDateTime, fmtNum } from '../../lib/format';
import type { Info, Role, UserView } from '../../lib/types';

// 설정(W16, 10/20 확정) — 서버 설정(보기 · 알림 테스트) · 계정 · 라이선스 · 인증 감사. 조회자는 계정 · 인증 감사 탭이 없다
type Tab = 'server' | 'accounts' | 'license' | 'auth-audit';
const TABS: { key: Tab; label: string; admin?: boolean }[] = [
  { key: 'server', label: '서버 설정' },
  { key: 'accounts', label: '계정', admin: true },
  { key: 'license', label: '라이선스' },
  { key: 'auth-audit', label: '인증 감사', admin: true },
];

export function SettingsPage() {
  const { isAdmin } = useAuth();
  const [params, setParams] = useSearchParams();
  const tabs = TABS.filter((t) => isAdmin || !t.admin);
  const tab = tabs.find((t) => t.key === params.get('tab'))?.key ?? 'server';
  return (
    <div className="flex h-full min-h-0 flex-col rounded-lg border border-slate-200 bg-white">
      <div role="tablist" data-part="settings-tabs" aria-label="설정" className="flex shrink-0 gap-1 border-b border-slate-100 px-3">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={tab === t.key}
            onClick={() => setParams(t.key === 'server' ? {} : { tab: t.key }, { replace: true })}
            className={`-mb-px border-b-2 px-3 py-2.5 text-sm ${tab === t.key ? 'border-indigo-600 font-medium text-indigo-700' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {tab === 'server' && <ServerTab />}
        {tab === 'accounts' && <AccountsTab />}
        {tab === 'license' && <LicenseTab />}
        {tab === 'auth-audit' && <AuthAuditTab />}
      </div>
    </div>
  );
}

function Section({ title, part, children, actions }: { title: string; part?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="grid gap-2 border-b border-slate-100 px-5 py-4" data-part={part}>
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-slate-800">{title}</h3>
        {actions}
      </div>
      {children}
    </section>
  );
}
function Row({ label, value, env, desc }: { label: string; value: ReactNode; env: string; desc: string }) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-t border-slate-100 pt-2 first:border-t-0 first:pt-0">
      <div>
        <b className="text-sm font-medium text-slate-800">{label}</b>
        <div className="text-xs text-slate-500">{desc}</div>
      </div>
      <div className="grid justify-items-end gap-0.5">
        <span className="text-sm font-semibold text-slate-800">{value}</span>
        <code className="text-[11px] text-slate-500">{env}</code>
      </div>
    </div>
  );
}

// 서버 설정 — 보기만. 바꾸는 방법은 서버 .env + 재시작 (10/16 확정: 범위를 잘못 넓히면 다른 컨테이너가 격리된다)
function ServerTab() {
  const { isAdmin } = useAuth();
  const toast = useToast();
  const info = useLoad(api.info);
  const [sending, setSending] = useState(false);
  if (!info.data) return info.error ? <LoadError error={info.error} what="서버 정보" /> : <Empty>불러오는 중…</Empty>;
  const i: Info = info.data;
  const watch = i.watchContainers ?? [];
  const ignore = i.ignoreContainers ?? [];
  const n = i.notify;
  const test = async () => {
    setSending(true);
    try {
      await authApi.notifyTest();
      toast('테스트 알림을 보냈습니다 — 잠시 뒤 결과를 다시 읽습니다', { key: 'notify-test', tone: 'ok' });
      window.setTimeout(() => {
        info.reload();
        setSending(false);
      }, 1500);
    } catch (e) {
      toast(`테스트 발송 실패: ${errorText(e)}`, { key: 'notify-test', tone: 'danger' });
      setSending(false);
    }
  };
  return (
    <div data-view="server">
      <Section title="동작">
        <Row label="자동 격리" value={i.enforceKill ? '켜짐' : '꺼짐 (알림만)'} env="ENFORCE_KILL" desc={i.enforceKill ? '「즉시 격리」 정책에 걸리면 컨테이너를 멈춥니다' : '모든 정책이 알림만 보냅니다'} />
        <Row label="감시 범위" value={watch.length ? watch.join(', ') : '모든 컨테이너'} env="WATCH_CONTAINERS" desc="이 범위의 컨테이너만 평가 · 격리합니다" />
        <Row label="제외" value={ignore.length ? ignore.join(', ') : '없음'} env="IGNORE_CONTAINERS" desc="SupplyGuard 자신처럼 보지 않을 컨테이너" />
      </Section>
      <Section
        title="알림"
        part="notify"
        actions={
          isAdmin && n?.channels.length ? (
            <button type="button" disabled={sending} onClick={() => void test()} className="flex items-center gap-1.5 rounded-md border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-50 disabled:opacity-50">
              <Send className="size-3.5" aria-hidden /> 테스트 발송
            </button>
          ) : null
        }
      >
        {!n ? (
          <p className="text-xs text-slate-500">이 백엔드는 알림 상태를 알려 주지 않습니다.</p>
        ) : !n.channels.length ? (
          <p className="text-xs text-slate-500">
            알림 채널이 없습니다 — 서버 .env 에 <code>NOTIFY_WEBHOOK_URL</code> · <code>NOTIFY_SLACK_URL</code> 을 넣고 다시 시작하세요.
          </p>
        ) : (
          <>
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-slate-500">
                <tr>
                  {['채널', '호스트', '보냄', '실패', '마지막 성공', '마지막 오류'].map((t) => (
                    <th key={t} className="py-1 font-medium">
                      {t}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {n.channels.map((c) => (
                  <tr key={c.name} data-channel={c.name} className="border-t border-slate-100">
                    <td className="py-1.5">{c.name}</td>
                    <td className="py-1.5 font-mono text-xs">{c.host}</td>
                    <td className="num py-1.5" data-sent="">
                      {fmtNum(c.sent)}
                    </td>
                    <td className={`num py-1.5 ${c.failed ? 'text-red-600' : ''}`}>{fmtNum(c.failed)}</td>
                    <td className="num py-1.5 text-xs text-slate-500">{c.lastAt ? fmtDateTime(c.lastAt) : '—'}</td>
                    <td className="max-w-0 truncate py-1.5 text-xs text-red-600" title={c.lastError}>
                      {c.lastError || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-xs text-slate-500">
              합계 보냄 {fmtNum(n.sent)} · 실패 {fmtNum(n.failed)}
              {n.suppressed ? ` · 같은 알림 묶음 ${fmtNum(n.suppressed)}` : ''} — 채널은 <code>NOTIFY_WEBHOOK_URL</code> · <code>NOTIFY_SLACK_URL</code>
            </p>
          </>
        )}
      </Section>
      <Section title="컨테이너 발견 방식" part="discovery">
        <Row
          label="발견 방식"
          value={i.discovery || (i.source === 'mock' ? 'mock (해당 없음)' : '시작 전')}
          env="CONTAINER_DISCOVERY"
          desc={i.discoveryNote || (i.discovery === 'fanotify' ? '컨테이너가 시작되는 순간부터 관찰합니다' : '새 컨테이너를 어떻게 찾아 감시에 붙이는지')}
        />
      </Section>
      <Section title="도메인 판단" part="dns">
        <Row
          label="trace_dns"
          value={i.dnsResolve === 'off' ? '꺼짐' : i.dnsResolve === 'ok' ? '켜짐' : '—'}
          env="dnsResolve"
          desc={i.dnsResolve === 'off' ? '도메인 기준 규칙(allowHosts · denyHosts · 차단 도메인)이 통과 처리됩니다. IP · 포트 규칙만 동작합니다' : '연결 대상 IP 를 DNS 응답으로 도메인에 맞춰 판단합니다'}
        />
      </Section>
      <p className="px-5 py-4 text-xs text-slate-500">
        바꾸는 방법: 서버의 .env 에서 위 값을 고친 뒤 백엔드를 다시 시작하세요. 화면에서는 바꾸지 않습니다 — 범위를 잘못 넓히면 다른 컨테이너가 격리될 수 있습니다.
      </p>
    </div>
  );
}

// ── 계정(관리자) ──
type Confirm = { title: string; target: string; effects: string[]; undo: string; okLabel: string; tone?: 'primary' | 'danger'; run: () => Promise<unknown>; temp?: string };

function AccountsTab() {
  const { me } = useAuth();
  const users = useLoad(authApi.users);
  const [msg, setMsg] = useState('');
  const [adding, setAdding] = useState(false);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [temp, setTemp] = useState<{ username: string; password: string } | null>(null);
  const admins = (users.data ?? []).filter((u) => u.role === 'admin' && !u.disabled).length;
  const status = (u: UserView): [string, string] =>
    u.disabled ? ['비활성', 'text-slate-400'] : u.locked ? ['잠김(5분)', 'text-amber-700'] : u.mustChangePassword ? ['첫 로그인 대기', 'text-indigo-700'] : ['활성', 'text-emerald-700'];
  const who = (u: UserView) => `${u.username} (${u.displayName})`;
  const act = (label: string, onClick: () => void, danger = false) => (
    <button type="button" onClick={onClick} className={`rounded px-1.5 py-0.5 text-xs hover:bg-slate-100 ${danger ? 'text-red-600' : 'text-slate-600'}`}>
      {label}
    </button>
  );
  const run = async (c: Confirm) => {
    setConfirm(null);
    setMsg('');
    try {
      const r = await c.run();
      users.reload();
      if (c.temp && r && typeof r === 'object' && 'tempPassword' in r) setTemp({ username: c.temp, password: (r as { tempPassword: string }).tempPassword });
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  };
  const roleChange = (u: UserView, role: Role) =>
    setConfirm({
      title: role === 'admin' ? '관리자로 올리기' : '조회자로 내리기',
      target: who(u),
      tone: 'primary',
      okLabel: '바꾸기',
      effects: [role === 'admin' ? '정책 · 판정 · 계정 관리 같은 모든 쓰기를 할 수 있게 됩니다' : '쓰기 버튼이 모두 사라지고 보기만 할 수 있습니다', '지금 로그인 중이면 다음 요청부터 적용됩니다'],
      undo: '같은 화면에서 역할을 다시 바꿉니다',
      run: () => authApi.patchUser(u.id, { role }),
    });
  const toggleDisabled = (u: UserView) =>
    setConfirm({
      title: u.disabled ? '계정 활성화' : '계정 비활성',
      target: who(u),
      okLabel: u.disabled ? '활성화' : '비활성',
      effects: u.disabled ? ['다시 로그인할 수 있습니다'] : ['지금 세션이 끊기고 로그인할 수 없습니다', '판정 · 변경 이력의 처리자 기록은 남습니다'],
      undo: '같은 화면에서 다시 활성화합니다',
      run: () => authApi.patchUser(u.id, { disabled: !u.disabled }),
    });
  const resetPw = (u: UserView) =>
    setConfirm({
      title: '비밀번호 초기화',
      target: who(u),
      okLabel: '초기화',
      effects: ['새 임시 비밀번호를 만들어 한 번 보여 줍니다', '첫 로그인에서 비밀번호를 바꿔야 합니다', '5분 잠금도 풀립니다'],
      undo: '되돌릴 수 없습니다 — 새 임시 비밀번호를 전달하세요',
      run: () => authApi.resetPassword(u.id),
      temp: u.username,
    });
  const resetOtp = (u: UserView) =>
    setConfirm({
      title: 'OTP 초기화',
      target: who(u),
      okLabel: '초기화',
      effects: ['등록된 인증 앱과 남은 복구 코드가 지워집니다', '다음 로그인에서 OTP 를 다시 등록합니다'],
      undo: '되돌릴 수 없습니다 — 다시 등록하게 안내하세요',
      run: () => authApi.resetOtp(u.id),
    });

  return (
    <div data-view="accounts" className="flex flex-col">
      <div className="flex items-center justify-between gap-3 border-b border-slate-100 px-5 py-3">
        <p className="text-xs text-slate-500">관리자는 모든 쓰기, 조회자는 보기만 합니다. 새 계정 · 비밀번호 초기화의 임시 비밀번호는 한 번만 보입니다.</p>
        <button type="button" onClick={() => setAdding(true)} className="flex shrink-0 items-center gap-1 rounded-md bg-indigo-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-indigo-700">
          <Plus className="size-3.5" aria-hidden /> 계정 추가
        </button>
      </div>
      {msg && (
        <p role="alert" className="mx-5 mt-3 rounded-md bg-red-50 px-3 py-2 text-xs text-red-700">
          {msg}
        </p>
      )}
      {!users.data ? (
        users.error ? <LoadError error={users.error} what="계정" /> : <Empty>불러오는 중…</Empty>
      ) : (
        <>
          <table className="w-full text-sm" data-table="users">
            <thead className="bg-slate-50 text-left text-xs text-slate-500">
              <tr>
                {['아이디', '이름', '역할', '상태', 'OTP', '마지막 로그인', ''].map((t, i) => (
                  <th key={i} className="px-4 py-2 font-medium">
                    {t}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.data.map((u) => {
                const last = u.role === 'admin' && !u.disabled && admins === 1;
                const self = u.id === me?.user.id;
                const [st, tone] = status(u);
                return (
                  <tr key={u.id} data-user={u.username} className="border-t border-slate-100">
                    <td className="px-4 py-2 font-mono">
                      {u.username}
                      {self && <span className="text-xs text-slate-400"> (나)</span>}
                    </td>
                    <td className="px-4 py-2">{u.displayName}</td>
                    <td className="px-4 py-2">
                      <span className={`rounded px-1.5 py-0.5 text-xs ${u.role === 'admin' ? 'bg-indigo-50 text-indigo-700' : 'bg-slate-100 text-slate-600'}`}>{ROLE_KO[u.role]}</span>
                      {last && (
                        <span className="text-xs text-slate-400" title={AUTH_MSG.lastAdmin}>
                          {' '}
                          · 마지막 관리자
                        </span>
                      )}
                    </td>
                    <td className={`px-4 py-2 text-xs ${tone}`}>{st}</td>
                    <td className="px-4 py-2 text-xs">{u.otpEnabled ? '등록됨' : '미등록'}</td>
                    <td className="num px-4 py-2 text-xs whitespace-nowrap text-slate-500">{u.lastLoginAt ? fmtDateTime(u.lastLoginAt) : '—'}</td>
                    <td className="px-4 py-2 whitespace-nowrap">
                      {/* 마지막 관리자 · 자기 자신은 강등 · 비활성 버튼을 그리지 않는다(누를 수 없는 버튼 금지) */}
                      {!last && (u.role === 'admin' ? act('조회자로', () => roleChange(u, 'viewer')) : act('관리자로', () => roleChange(u, 'admin')))}
                      {!last && !self && act(u.disabled ? '활성화' : '비활성', () => toggleDisabled(u), !u.disabled)}
                      {act('비밀번호 초기화', () => resetPw(u))}
                      {u.otpEnabled && act('OTP 초기화', () => resetOtp(u))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="px-5 py-3 text-xs text-slate-500" data-part="last-admin">
            관리자는 지금 {admins}명입니다. {AUTH_MSG.lastAdmin} — 다른 계정을 먼저 관리자로 올리세요.
          </p>
        </>
      )}
      {adding && (
        <AddUser
          onClose={() => setAdding(false)}
          onCreated={(username, password) => {
            setAdding(false);
            users.reload();
            setTemp({ username, password });
          }}
        />
      )}
      {confirm && <ConfirmDialog {...confirm} onConfirm={() => void run(confirm)} onCancel={() => setConfirm(null)} />}
      {temp && (
        <Modal title={`${temp.username} 임시 비밀번호`} kind="temp-password" onClose={() => setTemp(null)}>
          <p className="text-sm">지금 한 번만 보입니다. 직접 전달하세요. 첫 로그인에서 새 비밀번호로 바꿉니다.</p>
          <code className="rounded-md bg-slate-100 px-3 py-2 text-center font-mono text-base" data-temp-password="">
            {temp.password}
          </code>
          <button
            type="button"
            onClick={() => void navigator.clipboard?.writeText(temp.password).catch(() => {})}
            className="justify-self-start rounded px-2 py-1 text-xs text-slate-600 hover:bg-slate-100"
          >
            복사
          </button>
        </Modal>
      )}
    </div>
  );
}

function AddUser({ onClose, onCreated }: { onClose: () => void; onCreated: (username: string, password: string) => void }) {
  const [username, setUsername] = useState('');
  const [display, setDisplay] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const create = async () => {
    setBusy(true);
    setMsg('');
    try {
      const r = await authApi.createUser({ username: username.trim(), displayName: display.trim(), role });
      onCreated(r.user.username, r.tempPassword);
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : String(e));
      setBusy(false);
    }
  };
  const cls = 'h-9 rounded-md border border-slate-300 px-2.5 text-sm focus:border-indigo-500 focus:outline-none';
  return (
    <Modal
      title="계정 추가"
      kind="user-add"
      onClose={onClose}
      guard={() => !!(username || display)}
      foot={
        <>
          <button type="button" onClick={onClose} className="rounded-md px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-100">
            취소
          </button>
          <button type="button" disabled={busy} onClick={() => void create()} className="rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
            만들기
          </button>
        </>
      }
    >
      <div className="grid gap-3 text-sm">
        <label className="grid gap-1">
          <b className="font-medium">아이디</b>
          <input className={`${cls} font-mono`} placeholder="예: analyst1" autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label className="grid gap-1">
          <b className="font-medium">이름</b>
          <input className={cls} placeholder="예: 분석 담당" value={display} onChange={(e) => setDisplay(e.target.value)} />
        </label>
        <label className="grid gap-1">
          <b className="font-medium">역할</b>
          <select className={cls} value={role} onChange={(e) => setRole(e.target.value as Role)}>
            <option value="viewer">조회자 — 보기만</option>
            <option value="admin">관리자 — 모든 쓰기</option>
          </select>
        </label>
        {msg && (
          <p role="alert" className="text-xs text-red-600">
            {msg}
          </p>
        )}
      </div>
    </Modal>
  );
}

// ── 라이선스 ──
// W21(10/20): 관리자만 「새 키 등록」 — 로그인 라이선스 단계와 같은 4칸 입력 → 확인 대화상자 → PUT /api/license → 탭 · 상단 칩 갱신.
// 형식 검사는 서버(license.Validate) 한 곳 — 오류 문구도 로그인 단계와 같은 서버 문구를 그대로 보인다
type RenewPhase = 'closed' | 'input' | 'confirm';
function LicenseTab() {
  const { isAdmin, refresh } = useAuth();
  const toast = useToast();
  const lic = useLoad(authApi.getLicense);
  const [phase, setPhase] = useState<RenewPhase>('closed');
  const [key, setKey] = useState(['', '', '', '']);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const open = () => {
    setKey(['', '', '', '']);
    setMsg('');
    setPhase('input');
  };
  const save = async () => {
    setPhase('input');
    setMsg('');
    setBusy(true);
    try {
      const l = await authApi.renewLicense(key.join('-'));
      setPhase('closed');
      lic.reload();
      void refresh(); // 상단 칩은 /api/auth/me 의 license 로 그린다
      toast(`라이선스를 바꿨습니다 — ${fmtDateTime(l.expiresAt)}까지`, { key: 'license-renew', tone: 'ok' });
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const last4 = key[3]?.length === 4 ? key[3] : '????';
  // Enter 로 확인 대화상자를 열면 같은 키 입력이 새로 포커스된 「바꾸기」를 눌러 확인을 건너뛴다 — 키를 뗀 뒤에 연다
  const confirmAfterEnter = () => !busy && window.addEventListener('keyup', () => setPhase((p) => (p === 'input' ? 'confirm' : p)), { once: true });
  const renew = isAdmin && (
    <>
      {phase === 'input' && (
        <Modal
          title="새 라이선스 키 등록"
          kind="license-renew"
          onClose={() => setPhase('closed')}
          guard={() => key.some((k) => k !== '')}
          foot={
            <>
              <button type="button" onClick={() => setPhase('closed')} className="rounded-md px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-100">
                취소
              </button>
              <button type="button" disabled={busy} onClick={() => setPhase('confirm')} className="rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
                등록
              </button>
            </>
          }
        >
          <p className="text-[13px] text-slate-500">받은 키 16자리를 넣으세요(XXXX-XXXX-XXXX-XXXX). 붙여넣으면 네 칸에 나눠 들어갑니다.</p>
          <KeyBoxes value={key} onChange={setKey} label="라이선스 키" onEnter={confirmAfterEnter} />
          {msg && (
            <p role="alert" className="rounded-md bg-red-50 px-2.5 py-2 text-[13px] text-red-700">
              {msg}
            </p>
          )}
        </Modal>
      )}
      {phase === 'confirm' && (
        <ConfirmDialog
          title="라이선스 바꾸기"
          target={`새 키 ****-****-****-${last4}`}
          tone="primary"
          okLabel="바꾸기"
          effects={[
            `지금 라이선스를 바꿉니다${lic.data ? ` — 지금 키 ${lic.data.keyMasked} 는 더 쓰지 않습니다` : ''}`,
            '만료일을 오늘부터 1년으로 새로 계산합니다',
            '인증 감사에 「라이선스 갱신」이 남습니다(키는 가린 값만)',
          ]}
          undo="되돌릴 수 없습니다 — 다른 키를 다시 등록하면 그날부터 1년입니다"
          onConfirm={() => void save()}
          onCancel={() => setPhase('input')}
        />
      )}
    </>
  );
  const button = isAdmin && (
    <button type="button" onClick={open} className="flex shrink-0 items-center gap-1 rounded-md bg-indigo-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-indigo-700">
      <KeyRound className="size-3.5" aria-hidden /> 새 키 등록
    </button>
  );
  const noLicense = lic.error instanceof ApiError && lic.error.status === 404 && lic.error.json;
  if (noLicense)
    return (
      <div data-view="license">
        <Empty>등록된 라이선스가 없습니다 — {isAdmin ? '「새 키 등록」으로 넣거나 ' : '관리자가 '}다음 로그인 때 등록합니다.</Empty>
        {button && <div className="flex justify-center pb-6">{button}</div>}
        {renew}
      </div>
    );
  if (!lic.data) return <div data-view="license">{lic.error ? <LoadError error={lic.error} what="라이선스" /> : <Empty>불러오는 중…</Empty>}</div>;
  const l = lic.data;
  const rows: [string, ReactNode][] = [
    ['상태', `${licenseText(l)}`],
    ['종류', l.kind === 'trial' ? '평가판 (1년)' : l.kind],
    ['키', <span className="font-mono">{l.keyMasked}</span>],
    ['시작', fmtDateTime(l.issuedAt)],
    ['만료', `${fmtDateTime(l.expiresAt)}${l.expired ? '' : ` (${daysLeft(l)}일 남음)`}`],
    ['등록한 계정', l.registeredBy || '—'],
  ];
  return (
    <div data-view="license" className="px-5 py-4">
      <div className="flex max-w-xl items-start justify-between gap-3">
        <dl className="grid flex-1 grid-cols-[7rem_1fr] gap-x-3 gap-y-2 text-sm">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-slate-500">{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
        {button}
      </div>
      <p className="mt-4 text-xs text-slate-500">
        키 원문은 서버에 저장하지 않습니다(가린 값만).{' '}
        {isAdmin ? '「새 키 등록」으로 언제든 바꿀 수 있습니다 — 만료일은 등록한 날부터 1년으로 새로 계산합니다.' : '만료되면 관리자가 새 키를 등록합니다.'}
      </p>
      {renew}
    </div>
  );
}

// ── 인증 감사(관리자) ──
const ACTION_KO: Record<string, string> = {
  login: '로그인',
  login_lock: '로그인 잠금',
  logout: '로그아웃',
  password_change: '비밀번호 변경',
  password_reset: '비밀번호 초기화',
  license: '라이선스 등록',
  license_register: '라이선스 등록',
  license_renew: '라이선스 갱신',
  otp_enroll: 'OTP 등록',
  otp_verify: 'OTP 확인',
  otp_recovery: '복구 코드 사용',
  otp_reset: 'OTP 초기화',
  user_create: '계정 추가',
  user_update: '계정 변경',
  // 서버(auth/service.go)가 실제로 남기는 이름(10/20) — 위 password_reset · otp_reset 은 목업 · 가짜 서버 이름
  user_reset_password: '비밀번호 초기화',
  user_reset_otp: 'OTP 초기화',
};
function AuthAuditTab() {
  const load = useCallback(() => authApi.audit(200), []);
  const rows = useLoad(load);
  if (!rows.data) return <div data-view="auth-audit">{rows.error ? <LoadError error={rows.error} what="인증 감사" /> : <Empty>불러오는 중…</Empty>}</div>;
  return (
    <div data-view="auth-audit">
      {rows.data.length === 0 ? (
        <Empty>기록 없음</Empty>
      ) : (
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-slate-50 text-left text-xs text-slate-500">
            <tr>
              {['시각', '계정', '동작', '대상', 'IP', '결과', '내용'].map((t) => (
                <th key={t} className="px-4 py-2 font-medium">
                  {t}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.data.map((a) => (
              <tr key={a.id} data-audit={a.id} className="border-t border-slate-100">
                <td className="num px-4 py-1.5 text-xs whitespace-nowrap">{fmtDateTime(a.at)}</td>
                <td className="px-4 py-1.5 font-mono text-xs">{a.actor || '—'}</td>
                <td className="px-4 py-1.5">{ACTION_KO[a.action] ?? a.action}</td>
                <td className="px-4 py-1.5 font-mono text-xs">{a.target || '—'}</td>
                <td className="px-4 py-1.5 font-mono text-xs text-slate-500">{a.ip || '—'}</td>
                <td className={`px-4 py-1.5 text-xs ${a.ok ? 'text-emerald-700' : 'text-red-600'}`}>{a.ok ? '성공' : '실패'}</td>
                <td className="px-4 py-1.5 text-xs text-slate-600">{a.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
