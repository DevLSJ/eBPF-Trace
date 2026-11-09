import { Link } from 'react-router-dom';
import { useAuth } from '../../hooks/auth-context';
import { useStream } from '../../hooks/stream-context';
import { daysLeft, licenseTone } from '../../lib/auth';
import { fmtNum } from '../../lib/format';

// 상태 신호등(10/30 계약 §5) — 대시보드 머리 한 줄, 알약 5개(가젯 · 도메인 판단 · 자동 격리 · 알림 · 라이선스).
// 데이터는 /api/info(+stats) 와 로그인 세션의 라이선스(/api/auth/me 의 license — /api/license 와 같은 값). 누르면 설정(해당 탭)
type Tone = 'ok' | 'warn' | 'danger' | 'muted';
interface Pill {
  key: 'gadget' | 'dns' | 'kill' | 'notify' | 'license';
  tone: Tone;
  text: string;
  to: string;
  title: string;
}

const TONE: Record<Tone, string> = {
  ok: 'bg-emerald-50 text-emerald-800 ring-emerald-200',
  warn: 'bg-amber-50 text-amber-900 ring-amber-200',
  danger: 'bg-red-50 text-red-800 ring-red-200',
  muted: 'bg-slate-100 text-slate-600 ring-slate-200',
};
const DOT: Record<Tone, string> = { ok: 'bg-emerald-500', warn: 'bg-amber-500', danger: 'bg-red-600', muted: 'bg-slate-400' };

export function SignalPills() {
  const { info, stats } = useStream();
  const { me, noAuth } = useAuth();
  // 계약 §5: 데이터는 /api/info — WS stats 는 info 가 아직 없을 때만 보조
  const source = info?.source ?? stats?.source;
  const enforce = info?.enforceKill ?? stats?.enforceKill;
  const n = info?.notify;
  const lic = me?.license ?? null;
  const licTone = licenseTone(lic);
  const pills: Pill[] = [
    {
      key: 'gadget',
      tone: source === 'gadget' ? 'ok' : source === 'mock' ? 'warn' : 'muted',
      text: source === 'gadget' ? '가젯 · 커널 감시 중' : source === 'mock' ? '가젯 · 모의 이벤트' : '가젯 · 미확인',
      to: '/settings',
      title: source === 'gadget' ? 'Inspektor Gadget 이 커널 이벤트를 수집합니다' : source === 'mock' ? 'MOCK 소스(모의 이벤트로 동작 중)' : '수집 소스를 아직 모릅니다',
    },
    {
      key: 'dns',
      tone: info?.dnsResolve === 'ok' ? 'ok' : info?.dnsResolve === 'off' ? 'warn' : 'muted',
      text: info?.dnsResolve === 'ok' ? '도메인 판단 켜짐' : info?.dnsResolve === 'off' ? '도메인 판단 · 통과 처리' : '도메인 판단 · 미확인',
      to: '/settings',
      title: info?.dnsResolve === 'off' ? 'trace_dns 가 뜨지 않아 도메인 기준 규칙과 DNS 질의 규칙이 통과 처리됩니다' : 'trace_dns 로 연결 대상 도메인을 판단합니다',
    },
    {
      key: 'kill',
      tone: enforce === true ? 'ok' : enforce === false ? 'warn' : 'muted',
      text: enforce === true ? '자동 격리 켜짐' : enforce === false ? '자동 격리 · 알림만' : '자동 격리 · 미확인',
      to: '/settings',
      title: enforce === false ? 'ENFORCE_KILL=false(kill 정책도 알림만 보냄)' : '「즉시 격리」 정책에 걸리면 컨테이너를 멈춥니다',
    },
    {
      key: 'notify',
      tone: !n ? 'muted' : n.failed > 0 && n.lastError ? 'danger' : !n.enabled || n.channels.length === 0 ? 'warn' : 'ok',
      text: !n ? '알림 · 미확인' : n.failed > 0 && n.lastError ? `알림 · 실패 ${fmtNum(n.failed)}건` : !n.enabled || n.channels.length === 0 ? '알림 · 미설정' : `알림 · 채널 ${n.channels.length}`,
      to: '/settings',
      title: !n ? '이 백엔드는 알림 상태를 알려 주지 않습니다' : n.lastError ? n.lastError : n.channels.length ? n.channels.map((c) => `${c.name} ${c.host}`).join(', ') : 'NOTIFY_WEBHOOK_URL · NOTIFY_SLACK_URL 을 설정하세요',
    },
    {
      key: 'license',
      tone: noAuth ? 'muted' : licTone === 'none' ? 'danger' : licTone,
      text: noAuth ? '인증 없음' : !lic ? '라이선스 없음' : licTone === 'danger' ? '라이선스 만료' : `라이선스 · ${daysLeft(lic)}일 남음`,
      to: '/settings?tab=license',
      title: lic ? `${lic.keyMasked} · 만료 ${lic.expiresAt.slice(0, 10)}` : '관리자가 라이선스를 등록해야 합니다',
    },
  ];
  return (
    <nav aria-label="상태" data-testid="signal-pills" className="flex flex-wrap items-center gap-1.5">
      {pills.map((p) => (
        <Link
          key={p.key}
          to={p.to}
          data-pill={p.key}
          data-tone={p.tone}
          title={p.title}
          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium whitespace-nowrap ring-1 ring-inset hover:brightness-95 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-indigo-500 ${TONE[p.tone]}`}
        >
          <i className={`size-2 rounded-full ${DOT[p.tone]}`} aria-hidden />
          {p.text}
        </Link>
      ))}
    </nav>
  );
}
