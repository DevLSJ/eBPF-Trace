import { dnsKindOf, type DnsKind } from '../lib/evidence';
import type { Event } from '../lib/types';

const TEXT: Record<DnsKind, [string, string]> = {
  traced: ['trace_dns 로 확인', 'text-slate-700'],
  direct: ['도메인 조회 없는 IP 직접 연결', 'text-red-700'],
  private: ['내부 주소(도메인 조회 없음, 직접 연결로 보지 않음)', 'text-slate-500'],
  // connect 는 백엔드가 dnsTraced 를 false 도 명시한다(W20) — false = trace_dns 꺼짐, 필드 없음 = 필드가 생기기 전 옛 기록
  off: ['판단 불가(trace_dns 꺼짐, 도메인 기준 규칙은 통과 처리)', 'text-amber-700'],
  unknown: ['기록 없음(옛 기록)', 'text-slate-400'],
};

// 이벤트 · 감사 상세의 「도메인 조회」 줄(10/20 I) — connect 만. <dl> 안에 dt · dd 로 들어간다
export function DnsRow({ e }: { e: Event }) {
  if (e.kind !== 'connect') return null;
  const kind = dnsKindOf(e);
  const [text, cls] = TEXT[kind];
  return (
    <>
      <dt className="text-slate-500">도메인 조회</dt>
      <dd data-dns={kind} className={`text-xs ${cls}`}>
        {kind === 'direct' ? (
          <>
            <span className="rounded bg-red-100 px-1.5 py-0.5 font-medium">{text}</span>
            <span className="text-slate-500"> C2 · 유출에 흔함. 규칙의 directIp 로 막을 수 있습니다</span>
          </>
        ) : kind === 'traced' ? (
          `${e.dstHost}(${text})`
        ) : (
          text
        )}
      </dd>
    </>
  );
}
