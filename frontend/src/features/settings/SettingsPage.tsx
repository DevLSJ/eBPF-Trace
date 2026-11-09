import { KeyRound, Plus, Send } from 'lucide-react';
import { useCallback, useMemo, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { KeyBoxes } from '../../components/KeyBoxes';
import { AppliedFilters, EmptyState, NoResults } from '../../components/list/ListStates';
import { TimeText } from '../../components/list/cells';
import { ActionButton } from '../../components/ActionButton';
import { ConfirmDialog, Modal } from '../../components/Modal';
import { Empty, LoadError } from '../../components/Panel';
import { GridCells, SortHead, TableScroll } from '../../components/DataTable';
import { COL_W, useTableKit, type Column } from '../../hooks/useTableKit';
import { downloadCSV } from '../../components/list/csv';
import { fmtDay, fmtLog, fmtStatus } from '../../components/list/cell-format';
import { rowState } from '../../components/list/hooks';
import { Select } from '../../components/Select';
import { TableToolbar } from '../../components/TableToolbar';
import { ScreenHead } from '../../components/ScreenHead';
import { useAuth } from '../../hooks/auth-context';
import { useToast } from '../../hooks/toast-context';
import { PageActions } from '../../components/PageActions';
import { resetLayout } from '../../lib/layout';
import { useLoad } from '../../hooks/useLoad';
import { api, ApiError, authApi, failText } from '../../lib/api';
import { engineName, LOCAL_ONLY, NOT_SENT_ITEMS, SENT_ITEMS } from '../../lib/chatEngine';
import { AUTH_MSG, daysLeft, licenseText, ROLE_KO } from '../../lib/auth';
import { fmtNum } from '../../lib/format';
import type { AuthAuditEntry, Info, Role, UserView } from '../../lib/types';

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
  const toast = useToast();
  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
    <ScreenHead screen="settings" />
    <div className="sg-card flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* 화면 머리 오른쪽 「화면 배치 기본 순서로」(11/04d, R1 11/04) — 확인 없이 즉시 · 토스트 · 조회자도(이 브라우저에만 저장된 값). 열린 사이드바는 바로 기본 순서 */}
      <PageActions>
        <button
          type="button"
          data-action="layout-reset"
          title="길게 눌러 바꾼 순서(사이드바 · 대시보드 숫자 칸 · 평가 지표)를 처음대로 되돌림(이 브라우저에만 저장된 값)"
          onClick={() => {
            resetLayout();
            toast('화면 배치를 기본 순서로 되돌렸습니다. 사이드바 · 대시보드 숫자 칸 · 평가 지표 순서가 처음대로 돌아갑니다.', { tone: 'ok', key: 'layout-reset' });
          }}
          className="ml-auto shrink-0 rounded-md px-2.5 py-1 text-xs whitespace-nowrap text-text-2 hover:bg-surface-2 hover:text-text"
        >
          화면 배치 기본 순서로
        </button>
      </PageActions>
      <div role="tablist" data-part="settings-tabs" aria-label="설정" className="flex shrink-0 gap-1 overflow-x-auto border-b border-border px-3 [scrollbar-width:none]">
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
      <div data-fill="" className="min-h-0 flex-1 overflow-y-auto">
        {tab === 'server' && <ServerTab />}
        {tab === 'accounts' && <AccountsTab />}
        {tab === 'license' && <LicenseTab />}
        {tab === 'auth-audit' && <AuthAuditTab />}
      </div>
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
// 11/09 G38: 화면 문장은 쉬운 말. 설정 이름(ENFORCE_KILL · NOTIFY_* · OLLAMA_URL …)은 값 아래 보조 글(data-part="setting-name") · 툴팁으로만
function Row({ label, value, env, desc, hint }: { label: string; value: ReactNode; env: string; desc: string; hint?: string }) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-t border-slate-100 pt-2 first:border-t-0 first:pt-0">
      <div>
        <b className="text-sm font-medium text-slate-800">{label}</b>
        <div className="text-xs text-slate-500" title={hint}>
          {desc}
        </div>
      </div>
      <div className="grid justify-items-end gap-0.5">
        <span className="text-sm font-semibold text-slate-800">{value}</span>
        <code data-part="setting-name" className="text-xs text-slate-500">
          {env}
        </code>
      </div>
    </div>
  );
}
// 보조 글 한 줄(문장 아래 설정 이름)
function SettingNames({ names }: { names: string }) {
  return (
    <span className="mt-0.5 block">
      <code data-part="setting-name" className="text-xs text-text-3">
        {names}
      </code>
    </span>
  );
}
const DISCOVERY_KO: Record<string, string> = { fanotify: '커널 알림(fanotify)', 'docker-events': 'Docker 이벤트(docker-events)' };

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
      toast('테스트 알림을 보냈습니다. 잠시 뒤 결과를 다시 읽습니다.', { key: 'notify-test', tone: 'ok' });
      window.setTimeout(() => {
        info.reload();
        setSending(false);
      }, 1500);
    } catch (e) {
      toast(failText('테스트 알림을 보내지 못했습니다.', e), { key: 'notify-test', tone: 'danger' });
      setSending(false);
    }
  };
  return (
    <div data-view="server">
      <Section title="동작">
        <Row label="자동 격리" value={i.enforceKill ? '켜짐' : '꺼짐(알림만)'} env="ENFORCE_KILL" desc={i.enforceKill ? '「즉시 격리」 정책에 걸리면 컨테이너를 멈춥니다' : '모든 정책이 알림만 보냅니다'} />
        <Row label="감시 범위" value={watch.length ? watch.join(', ') : '모든 컨테이너'} env="WATCH_CONTAINERS" desc="이 범위의 컨테이너만 평가 · 격리합니다" />
        <Row label="제외" value={ignore.length ? ignore.join(', ') : '없음'} env="IGNORE_CONTAINERS" desc="SupplyGuard 자신처럼 보지 않을 컨테이너" />
      </Section>
      <Section
        title="알림"
        part="notify"
        actions={
          isAdmin && n?.channels.length ? (
            <ActionButton reason={sending && '테스트 알림을 보내는 중입니다'} onClick={() => void test()} className="sg-btn sg-btn-sm sg-btn-secondary flex items-center gap-1.5">
              <Send className="size-3.5" aria-hidden /> 테스트 발송
            </ActionButton>
          ) : null
        }
      >
        {!n ? (
          <p className="text-xs text-slate-500">이 백엔드는 알림 상태를 알려 주지 않습니다.</p>
        ) : !n.channels.length ? (
          <p className="text-xs text-slate-500">
            알림 채널이 없습니다. 서버 설정에 웹훅 · Slack 주소를 넣고 다시 시작하세요.
            <SettingNames names="NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL" />
          </p>
        ) : (
          <>
            <div className="max-md:overflow-x-auto">
            <table className="sg-table" data-table="notify">
              <thead>
                <tr>
                  {['채널', '호스트', '보냄', '실패', '마지막 성공', '마지막 오류'].map((t) => (
                    <th key={t} className={t === '보냄' || t === '실패' ? 'num-col' : undefined}>
                      {t}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {n.channels.map((c) => (
                  <tr key={c.name} data-channel={c.name}>
                    <td data-col="name" className="tk-short">{c.name}</td>
                    <td data-col="host" className="tk-short font-mono text-xs">{c.host}</td>
                    <td data-col="sent" className="num num-col tk-short" data-sent="">
                      {fmtNum(c.sent)}
                    </td>
                    <td data-col="failed" className={`num num-col tk-short ${c.failed ? 'text-red-600' : ''}`}>{fmtNum(c.failed)}</td>
                    <td data-col="last" className="tk-short text-slate-500">
                      <TimeText value={c.lastAt} kind="status" />
                    </td>
                    <td data-col="error" className="tk-fill text-xs text-red-600" title={c.lastError}>
                      {c.lastError || ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            <p className="text-xs text-slate-500">
              합계 보냄 {fmtNum(n.sent)} · 실패 {fmtNum(n.failed)}
              {n.suppressed ? ` · 같은 알림 묶음 ${fmtNum(n.suppressed)}` : ''}. 채널은 서버 설정의 웹훅 · Slack 주소로 정합니다.
              <SettingNames names="NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL" />
            </p>
          </>
        )}
      </Section>
      <Section title="컨테이너 발견 방식" part="discovery">
        <Row
          label="발견 방식"
          value={i.discovery ? (DISCOVERY_KO[i.discovery] ?? i.discovery) : i.source === 'mock' ? '해당 없음(모의 재생)' : '시작 전'}
          env="CONTAINER_DISCOVERY"
          desc={i.discoveryNote || (i.discovery === 'fanotify' ? '컨테이너가 시작되는 순간부터 관찰합니다' : '새 컨테이너를 어떻게 찾아 감시에 붙이는지')}
        />
      </Section>
      <AiSection info={i} />
      <Section title="도메인 판단" part="dns">
        <Row
          label="도메인 조회 감시"
          value={i.dnsResolve === 'off' ? '꺼짐' : i.dnsResolve === 'ok' ? '켜짐' : ''}
          env="trace_dns"
          hint="allowHosts · denyHosts · 차단 목록 도메인 · kind: dns 규칙"
          desc={i.dnsResolve === 'off' ? '도메인 기준 규칙(허용 · 금지 · 차단 도메인)과 DNS 질의 규칙이 통과 처리됩니다. IP · 포트 규칙만 동작합니다' : '연결 대상 IP 를 DNS 응답으로 도메인에 맞춰 판단하고, DNS 질의 규칙을 평가합니다'}
        />
      </Section>
      <p className="px-5 py-4 text-xs text-slate-500">
        바꾸는 방법: 서버 설정 파일(.env)에서 위 값을 고친 뒤 백엔드를 다시 시작하세요. 화면에서는 바꾸지 않습니다. 범위를 잘못 넓히면 다른 컨테이너가 격리될 수 있습니다.
      </p>
    </div>
  );
}

// AI 도우미(11/09) — 쓰는 모델 · 예비 · 밖으로 나가는 데이터 범위. 보기만(바꾸는 것은 서버 .env)
function AiSection({ info }: { info: Info }) {
  const e = info.chatEngine;
  const on = info.chat === true;
  const claude = on && e?.provider === 'claude';
  return (
    <Section title="AI 도우미" part="ai">
      <Row
        label="모델"
        value={on ? engineName(e) : '꺼짐'}
        env={on ? 'CHAT_PROVIDER · CLAUDE_MODEL' : 'ANTHROPIC_API_KEY · OLLAMA_URL'}
        desc={!on ? 'Claude API 키나 로컬 Ollama 주소가 있으면 켜짐' : claude ? '질문과 조회한 사실을 Anthropic API 로 보내 답을 받음' : LOCAL_ONLY}
      />
      {on && <Row label="예비" value={e?.backup ? '로컬 Ollama' : '없음'} env="OLLAMA_URL" desc="기본 모델에 닿지 않거나 답을 거절할 때 같은 질문을 넘김" />}
      {claude && (
        <div data-part="ai-scope" className="grid gap-3 border-t border-slate-100 pt-2 text-xs text-slate-600 sm:grid-cols-2">
          <div>
            <b className="text-sm font-medium text-slate-800">밖으로 나가는 데이터</b>
            <ul data-part="ai-sent" className="mt-1 grid list-disc gap-0.5 pl-4">
              {SENT_ITEMS.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          </div>
          <div>
            <b className="text-sm font-medium text-slate-800">보내지 않는 데이터</b>
            <ul data-part="ai-not-sent" className="mt-1 grid list-disc gap-0.5 pl-4">
              {NOT_SENT_ITEMS.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
            <p className="mt-2">
              서버 밖으로 보내지 않으려면 로컬 Ollama 만 쓰도록 서버 설정을 바꿈
              <SettingNames names="CHAT_PROVIDER=ollama" />
            </p>
          </div>
        </div>
      )}
    </Section>
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
  // 계정 표 칸(R4 11/04) — 머리 클릭 정렬, 기본은 받은 순서(정렬 없음). 버튼 칸은 정렬하지 않는다.
  // 11/09 SPEC §4: 현황 표 — 상태가 맨 앞, 마지막 로그인은 MM-DD HH:mm + 전체 시각 툴팁
  // 11/09 표 도구: 칸 보이기 · 폭 · 순서 = supplyguard.grid.settings-users.v1, CSV = 보이는 칸 · 화면 글. 행 동작 칸은 이름이 없어 늘 보이고 고정
  const userCols = useMemo<Column<UserView>[]>(
    () => [
      {
        key: 'status',
        label: '상태',
        sort: (u) => (u.disabled ? 3 : u.locked ? 0 : u.mustChangePassword ? 1 : 2),
        short: true,
        cellClass: 'text-xs',
        cell: (u) => {
          const [st, tone] = status(u);
          return <span className={tone}>{st}</span>;
        },
        csv: (u) => status(u)[0],
      },
      {
        key: 'username',
        label: '아이디',
        sort: (u) => u.username,
        short: true,
        cellClass: 'font-mono',
        cell: (u) => (
          <>
            {u.username}
            {u.id === me?.user.id && <span className="text-xs text-slate-400"> (나)</span>}
          </>
        ),
        csv: (u) => u.username,
      },
      { key: 'name', label: '이름', sort: (u) => u.displayName, cell: (u) => u.displayName },
      {
        key: 'role',
        label: '역할',
        sort: (u) => ROLE_KO[u.role],
        short: true,
        cell: (u) => (
          <>
            <span className={`rounded px-1.5 py-0.5 text-xs ${u.role === 'admin' ? 'bg-indigo-50 text-indigo-700' : 'bg-slate-100 text-slate-600'}`}>{ROLE_KO[u.role]}</span>
            {u.role === 'admin' && !u.disabled && admins === 1 && (
              <span className="text-xs text-slate-400" title={AUTH_MSG.lastAdmin}>
                {' '}
                · 마지막 관리자
              </span>
            )}
          </>
        ),
        csv: (u) => ROLE_KO[u.role],
      },
      { key: 'otp', label: 'OTP', sort: (u) => (u.otpEnabled ? 1 : 0), short: true, cellClass: 'text-xs', cell: (u) => (u.otpEnabled ? '등록됨' : '미등록') },
      {
        key: 'last',
        label: '마지막 로그인',
        sort: (u) => (u.lastLoginAt ? Date.parse(u.lastLoginAt) : null),
        short: true,
        cellClass: 'text-slate-500',
        cell: (u) => (u.lastLoginAt ? <TimeText value={u.lastLoginAt} kind="status" /> : null),
        csv: (u) => (u.lastLoginAt ? fmtStatus(u.lastLoginAt) : null),
      },
      {
        key: 'actions',
        label: '',
        short: true,
        fixed: true,
        cell: (u) => {
          const last = u.role === 'admin' && !u.disabled && admins === 1;
          const self = u.id === me?.user.id;
          return (
            <>
              {/* 마지막 관리자 · 자기 자신은 강등 · 비활성 버튼을 그리지 않는다(누를 수 없는 버튼 금지) */}
              {!last && (u.role === 'admin' ? act('조회자로', () => roleChange(u, 'viewer')) : act('관리자로', () => roleChange(u, 'admin')))}
              {!last && !self && act(u.disabled ? '활성화' : '비활성', () => toggleDisabled(u), !u.disabled)}
              {act('비밀번호 초기화', () => resetPw(u))}
              {u.otpEnabled && act('OTP 초기화', () => resetOtp(u))}
            </>
          );
        },
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps -- 행 동작(act · roleChange …)은 렌더마다 새로 만들지만 같은 일을 한다
    [admins, me?.user.id],
  );
  const userKit = useTableKit({ columns: userCols, grid: 'settings-users' });
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
      title: role === 'admin' ? `${u.username}을(를) 관리자로 올릴까요?` : `${u.username}을(를) 조회자로 내릴까요?`,
      target: who(u),
      tone: 'primary',
      okLabel: '바꾸기',
      effects: [role === 'admin' ? '정책 · 판정 · 계정 관리 같은 모든 쓰기를 할 수 있게 됩니다' : '쓰기 버튼이 모두 사라지고 보기만 할 수 있습니다', '지금 로그인 중이면 다음 요청부터 적용됩니다'],
      undo: '같은 화면에서 역할을 다시 바꿉니다',
      run: () => authApi.patchUser(u.id, { role }),
    });
  const toggleDisabled = (u: UserView) =>
    setConfirm({
      title: u.disabled ? `계정 ${u.username}을(를) 활성화할까요?` : `계정 ${u.username}을(를) 비활성으로 바꿀까요?`,
      target: who(u),
      okLabel: u.disabled ? '활성화' : '비활성',
      effects: u.disabled ? ['다시 로그인할 수 있습니다'] : ['지금 세션이 끊기고 로그인할 수 없습니다', '판정 · 변경 이력의 처리자 기록은 남습니다'],
      undo: '같은 화면에서 다시 활성화합니다',
      run: () => authApi.patchUser(u.id, { disabled: !u.disabled }),
    });
  const resetPw = (u: UserView) =>
    setConfirm({
      title: `${u.username}의 비밀번호를 초기화할까요?`,
      target: who(u),
      okLabel: '초기화',
      effects: ['새 임시 비밀번호를 만들어 한 번 보여 줍니다', '첫 로그인에서 비밀번호를 바꿔야 합니다', '5분 잠금도 풀립니다'],
      undo: '되돌릴 수 없습니다. 새 임시 비밀번호를 전달하세요',
      run: () => authApi.resetPassword(u.id),
      temp: u.username,
    });
  const resetOtp = (u: UserView) =>
    setConfirm({
      title: `${u.username}의 OTP를 초기화할까요?`,
      target: who(u),
      okLabel: '초기화',
      effects: ['등록된 인증 앱과 남은 복구 코드가 지워집니다', '다음 로그인에서 OTP 를 다시 등록합니다'],
      undo: '되돌릴 수 없습니다. 다시 등록하게 안내하세요',
      run: () => authApi.resetOtp(u.id),
    });

  return (
    <div data-view="accounts" className="flex flex-col">
      <div className="flex items-center justify-between gap-3 border-b border-slate-100 px-5 py-3">
        <p className="text-xs text-slate-500">관리자는 모든 쓰기, 조회자는 보기만 합니다. 새 계정 · 비밀번호 초기화의 임시 비밀번호는 한 번만 보입니다.</p>
        <button type="button" onClick={() => setAdding(true)} className="flex shrink-0 items-center gap-1 rounded-md bg-primary px-2.5 py-1 text-xs font-medium text-primary-fg hover:bg-primary-hover">
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
          <TableToolbar name="users" total={users.data.length} kit={userKit} onRefresh={users.reload} refreshing={users.loading} onExport={() => downloadCSV('supplyguard-accounts.csv', userKit.csv(users.data!))} />
          <TableScroll className="max-md:overflow-x-auto">
          <table className="sg-table" data-table="users">
            <SortHead kit={userKit} />
            <tbody>
              {userKit.sorted(users.data).map((u) => (
                <tr key={u.id} data-user={u.username} {...rowState({})}>
                  <GridCells kit={userKit} row={u} />
                </tr>
              ))}
            </tbody>
          </table>
          </TableScroll>
          <p className="px-5 py-3 text-xs text-slate-500" data-part="last-admin">
            관리자는 지금 {admins}명입니다. {AUTH_MSG.lastAdmin}. 다른 계정을 먼저 관리자로 올리세요.
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
  // 입력 글자 13.5 · 포커스 링은 전역 규칙 하나(11/09 SPEC §1)
  const cls = 'h-9 rounded-md border border-slate-300 px-2.5';
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
          <ActionButton reason={busy && '계정을 만드는 중입니다'} onClick={() => void create()} className="rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-fg hover:bg-primary-hover aria-disabled:opacity-50">
            {busy ? '만드는 중…' : '만들기'}
          </ActionButton>
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
            <option value="viewer">조회자(보기만)</option>
            <option value="admin">관리자(모든 쓰기)</option>
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
      toast(`라이선스를 바꿨습니다. ${fmtDay(l.expiresAt)}까지 쓸 수 있습니다.`, { key: 'license-renew', tone: 'ok' });
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const last4 = key[3]?.length === 4 ? key[3] : '????';
  // Enter 는 KeyBoxes 가 키를 뗀 뒤에 알린다 — 새로 포커스된 「바꾸기」가 같은 Enter 로 눌리지 않는다
  const confirmOnEnter = () => !busy && setPhase('confirm');
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
              <ActionButton reason={busy && '라이선스를 등록하는 중입니다'} onClick={() => setPhase('confirm')} className="rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-fg hover:bg-primary-hover aria-disabled:opacity-50">
                등록
              </ActionButton>
            </>
          }
        >
          <p className="text-[13px] text-slate-500">받은 키 16자리를 넣으세요(XXXX-XXXX-XXXX-XXXX). 붙여넣으면 네 칸에 나눠 들어갑니다.</p>
          <KeyBoxes value={key} onChange={setKey} label="라이선스 키" onEnter={confirmOnEnter} />
          {msg && (
            <p role="alert" className="rounded-md bg-red-50 px-2.5 py-2 text-[13px] text-red-700">
              {msg}
            </p>
          )}
        </Modal>
      )}
      {phase === 'confirm' && (
        <ConfirmDialog
          title="라이선스를 바꿀까요?"
          target={`새 키 ****-****-****-${last4}`}
          tone="primary"
          okLabel="바꾸기"
          effects={[
            `지금 라이선스를 바꿉니다${lic.data ? `(지금 키 ${lic.data.keyMasked} 는 더 쓰지 않음)` : ''}`,
            '만료일을 오늘부터 1년으로 새로 계산합니다',
            '인증 감사에 「라이선스 갱신」이 남습니다(키는 가린 값만)',
          ]}
          undo="되돌릴 수 없습니다. 다른 키를 다시 등록하면 그날부터 1년입니다"
          onConfirm={() => void save()}
          onCancel={() => setPhase('input')}
        />
      )}
    </>
  );
  const button = isAdmin && (
    <button type="button" onClick={open} className="flex shrink-0 items-center gap-1 rounded-md bg-primary px-2.5 py-1 text-xs font-medium text-primary-fg hover:bg-primary-hover">
      <KeyRound className="size-3.5" aria-hidden /> 새 키 등록
    </button>
  );
  const noLicense = lic.error instanceof ApiError && lic.error.status === 404 && lic.error.json;
  if (noLicense)
    return (
      <div data-view="license">
        <Empty>등록된 라이선스가 없습니다. {isAdmin ? '「새 키 등록」으로 넣거나 ' : '관리자가 '}다음 로그인 때 등록합니다.</Empty>
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
    ['시작', <TimeText value={l.issuedAt} kind="day" />],
    ['만료', <>
      <TimeText value={l.expiresAt} kind="day" />
      {l.expired ? '' : ` (${daysLeft(l)}일 남음)`}
    </>],
    ['등록한 계정', l.registeredBy || ''],
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
        {isAdmin ? '「새 키 등록」으로 언제든 바꿀 수 있습니다. 만료일은 등록한 날부터 1년으로 새로 계산합니다.' : '만료되면 관리자가 새 키를 등록합니다.'}
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
// 서버가 남기는 동작 이름 13개(backend auth/service.go, 10/21 필터 계약) — 「한 일」 고르기 목록. 목록 밖 action 은 서버가 400
const AUDIT_ACTIONS = ['login', 'login_lock', 'logout', 'password_change', 'license_register', 'license_renew', 'otp_enroll', 'otp_verify', 'otp_recovery',
  'user_create', 'user_update', 'user_reset_password', 'user_reset_otp'];
const AUDIT_PAGE = 200;
const AUDIT_ACTION_OPTIONS = AUDIT_ACTIONS.map((a) => ({ value: a, label: ACTION_KO[a] ?? a }));

// 필터(한 일 · 실패만)는 서버가 거른다 — GET /api/auth/audit?action=&failed=1, 「더 보기」는 마지막 행 id 를 before 로
function AuthAuditTab() {
  const [action, setAction] = useState('');
  const [failed, setFailed] = useState(false);
  const chips = [
    !!action && { key: 'action', label: `한 일: ${ACTION_KO[action] ?? action}`, clear: () => setAction('') },
    failed && { key: 'failed', label: '실패만', clear: () => setFailed(false) },
  ];
  return (
    <div data-view="auth-audit">
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-100 px-4 py-2.5 text-sm" data-part="auth-audit-filters">
        <Select name="action" label="한 일" value={action} options={AUDIT_ACTION_OPTIONS} onChange={setAction} />
        <label className="flex cursor-pointer items-center gap-2 text-slate-600 select-none">
          <input type="checkbox" className="accent-indigo-600" data-field="failed" checked={failed} onChange={(e) => setFailed(e.target.checked)} />
          실패만
        </label>
      </div>
      <AppliedFilters
        items={chips}
        onClearAll={() => {
          setAction('');
          setFailed(false);
        }}
      />
      {/* 필터가 바뀌면 처음부터 — 더 불러온 행 · 끝 표시를 버린다 */}
      <AuthAuditRows
        key={`${action}|${failed}`}
        action={action}
        failed={failed}
        onClear={() => {
          setAction('');
          setFailed(false);
        }}
      />
    </div>
  );
}

// 인증 감사 표 칸(R4 11/04) — 머리 클릭 정렬(불러온 행 안), 기본은 시각 내림(받은 순서 그대로). 「더 보기」(커서)는 그대로.
// 11/09 SPEC §4: 기록류 — 시각이 맨 앞(YYYY-MM-DD HH:mm:ss 고정폭)
// 표 도구: 칸 보이기 · 폭 · 순서 = supplyguard.grid.settings-auth-audit.v1, CSV = 보이는 칸 · 화면 글(불러온 행)
const AUTH_AUDIT_COLS: Column<AuthAuditEntry>[] = [
  { key: 'at', label: '시각', sort: (a) => Date.parse(a.at), short: true, width: COL_W.log, cell: (a) => <TimeText value={a.at} kind="log" />, csv: (a) => fmtLog(a.at) },
  { key: 'actor', label: '계정', sort: (a) => a.actor, short: true, width: COL_W.user, cellClass: 'font-mono text-xs', cell: (a) => a.actor },
  { key: 'action', label: '동작', sort: (a) => ACTION_KO[a.action] ?? a.action, short: true, cell: (a) => ACTION_KO[a.action] ?? a.action },
  { key: 'target', label: '대상', sort: (a) => a.target, short: true, cellClass: 'font-mono text-xs', cell: (a) => a.target },
  { key: 'ip', label: 'IP', sort: (a) => a.ip, short: true, cellClass: 'font-mono text-xs text-slate-500', cell: (a) => a.ip },
  { key: 'ok', label: '결과', sort: (a) => (a.ok ? 1 : 0), short: true, cellClass: 'text-xs', cell: (a) => <span className={a.ok ? 'text-emerald-700' : 'text-red-600'}>{a.ok ? '성공' : '실패'}</span>, csv: (a) => (a.ok ? '성공' : '실패') },
  { key: 'detail', label: '내용', sort: (a) => a.detail, fill: true, cellClass: 'text-xs text-slate-600', cell: (a) => <span title={a.detail}>{a.detail}</span>, csv: (a) => a.detail },
];

function AuthAuditRows({ action, failed, onClear }: { action: string; failed: boolean; onClear: () => void }) {
  const kit = useTableKit({ columns: AUTH_AUDIT_COLS, sort: { key: 'at', dir: 'desc' }, grid: 'settings-auth-audit' });
  const load = useCallback(() => authApi.audit({ limit: AUDIT_PAGE, action, failed }), [action, failed]);
  const rows = useLoad(load);
  const [extra, setExtra] = useState<AuthAuditEntry[]>([]);
  const [end, setEnd] = useState(false);
  const [moreBusy, setMoreBusy] = useState(false);
  const [moreErr, setMoreErr] = useState<unknown>(null);
  if (!rows.data) return rows.error ? <LoadError error={rows.error} what="인증 감사" /> : <Empty>불러오는 중…</Empty>;
  const all = [...rows.data, ...extra];
  const hasMore = !end && rows.data.length >= AUDIT_PAGE;
  const more = async () => {
    setMoreBusy(true);
    setMoreErr(null);
    try {
      const next = await authApi.audit({ limit: AUDIT_PAGE, action, failed, before: all[all.length - 1].id });
      setExtra((x) => [...x, ...next]);
      if (next.length < AUDIT_PAGE) setEnd(true);
    } catch (e) {
      setMoreErr(e);
    } finally {
      setMoreBusy(false);
    }
  };
  if (all.length === 0) return action || failed ? <NoResults onClear={onClear} /> : <EmptyState what="인증 감사 기록" hint="로그인 · 비밀번호 · OTP · 계정 · 라이선스 변경이 여기에 남습니다." />;
  return (
    <>
      <TableToolbar name="auth-audit" total={all.length} kit={kit} onRefresh={rows.reload} refreshing={rows.loading} onExport={() => downloadCSV('supplyguard-auth-audit.csv', kit.csv(all))} />
      <TableScroll className="max-md:overflow-x-auto">
      <table className="sg-table" data-table="auth-audit">
        <SortHead kit={kit} />
        <tbody>
          {kit.sorted(all).map((a) => (
            <tr key={a.id} data-audit={a.id} {...rowState({})}>
              <GridCells kit={kit} row={a} />
            </tr>
          ))}
        </tbody>
      </table>
      </TableScroll>
      {(hasMore || moreErr != null) && (
        <div className="flex flex-col items-center gap-1 border-t border-slate-100 py-3 text-xs">
          {moreErr != null && (
            <span className="text-red-600" role="alert">
              {failText('더 불러오지 못했습니다.', moreErr)}
            </span>
          )}
          {hasMore && (
            <ActionButton data-action="more" reason={moreBusy && '불러오는 중입니다'} onClick={() => void more()} className="sg-btn sg-btn-sm sg-btn-secondary">
              {moreBusy ? '불러오는 중…' : '더 보기'}
            </ActionButton>
          )}
        </div>
      )}
    </>
  );
}
