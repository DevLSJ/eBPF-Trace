import type { FlowNode } from '../../components/FlowHero';
import type { Info, IntegrationEnv, IntegrationStatus, Kind } from '../../lib/types';

// 연동 페이지(11/06)의 흐름 그림 · 환경 점검 · 라벨 예시 — 화면과 e2e 가 같이 쓴다. 문구 규칙: 개조식 명사형 종결

export const FLOW: FlowNode[] = [
  { id: 'label', title: '내 컨테이너', sub: '라벨 한 줄', point: '컨테이너에 supplyguard.watch=true 라벨 추가됨' },
  { id: 'kernel', title: '커널 eBPF', sub: '실행 · 파일 · 통신 · 조회', point: '커널에서 실행 · 파일 열기 · 네트워크 연결 · DNS 질의 수집됨' },
  { id: 'judge', title: 'SupplyGuard', sub: '정책으로 판정', point: '정책(YAML)과 비교해 정상 · 경고 · 격리 판정됨' },
  { id: 'act', title: '경고 · 격리', sub: 'supplyguard.enforce', tone: 'danger', point: '위반은 기록 · 알림, 격리 라벨이 있으면 증거 수집 뒤 즉시 격리됨' },
];

export type Tone = 'ok' | 'warn' | 'off';
export interface Check { id: string; label: string; value: string; tone: Tone; hint?: string }

// 환경 점검 — 현상을 먼저, 조치는 hint 로
export function envChecks(env: IntegrationEnv, info: Info | null): Check[] {
  const out: Check[] = [];
  const gadget = env.source === 'gadget';
  out.push(
    gadget
      ? { id: 'source', label: '이벤트 수집', value: '실제 커널(eBPF)', tone: 'ok' }
      : { id: 'source', label: '이벤트 수집', value: '모의 이벤트(개발용)', tone: 'warn', hint: '서버에서는 EVENT_SOURCE=gadget 으로 실행 필요' },
  );
  const k = env.kernel.match(/^(\d+)\.(\d+)/);
  const major = k ? Number(k[1]) : 0;
  const minor = k ? Number(k[2]) : 0;
  out.push(
    !env.kernel
      ? { id: 'kernel', label: '커널', value: '확인 불가(리눅스 아님)', tone: 'off', hint: '리눅스 서버(커널 5.15 이상)에서 실제 수집 가능' }
      : major >= 7
        ? { id: 'kernel', label: '커널', value: env.kernel, tone: 'warn', hint: '커널 7.0 에서 이벤트 유실 확인됨 — Ubuntu 22.04(커널 5.15 · 6.8) 권장' }
        : major > 5 || (major === 5 && minor >= 15)
          ? { id: 'kernel', label: '커널', value: env.kernel, tone: 'ok' }
          : { id: 'kernel', label: '커널', value: env.kernel, tone: 'warn', hint: '커널 5.15 이상 권장' },
  );
  out.push({ id: 'os', label: '운영체제', value: env.os || '—', tone: env.os ? 'ok' : 'off' });
  const g = info?.gadgets ?? [];
  const need: Kind[] = ['exec', 'open', 'connect'];
  const missing = need.filter((x) => !g.includes(x));
  out.push(
    missing.length
      ? { id: 'gadgets', label: '수집 항목', value: `${missing.join(' · ')} 없음`, tone: 'warn', hint: 'GADGETS 설정 확인 필요' }
      : { id: 'gadgets', label: '수집 항목', value: info?.dnsResolve === 'ok' ? '실행 · 파일 · 통신 · DNS' : '실행 · 파일 · 통신', tone: info?.dnsResolve === 'off' ? 'warn' : 'ok', hint: info?.dnsResolve === 'off' ? 'trace_dns 꺼짐 — 도메인 기준 판정 통과 처리됨' : undefined },
  );
  const d = info?.discovery ?? '';
  out.push(
    !d
      ? { id: 'discovery', label: '컨테이너 발견', value: gadget ? '시작 전' : '해당 없음(모의)', tone: 'off' }
      : d === 'fanotify'
        ? { id: 'discovery', label: '컨테이너 발견', value: 'fanotify(시작 순간부터)', tone: 'ok' }
        : { id: 'discovery', label: '컨테이너 발견', value: d, tone: 'warn', hint: info?.discoveryNote || '컨테이너 시작 직후 동작은 놓칠 수 있음' },
  );
  out.push(
    env.enforceKill
      ? { id: 'enforce', label: '격리', value: '켜짐', tone: 'ok' }
      : { id: 'enforce', label: '격리', value: '꺼짐(dry-run)', tone: 'warn', hint: 'ENFORCE_KILL=false — 격리 정책도 알림만 전송됨' },
  );
  return out;
}

// 라벨 한 줄 — compose · docker run
export function labelSnippet(kind: 'compose' | 'run', env: Pick<IntegrationEnv, 'labelWatch' | 'labelEnforce'>, enforce: boolean): string {
  if (kind === 'compose')
    return [
      'services:',
      '  my-app:',
      '    image: my-app:latest',
      '    labels:',
      `      ${env.labelWatch}: "true"`,
      ...(enforce ? [`      ${env.labelEnforce}: "true"`] : []),
    ].join('\n');
  return ['docker run -d --name my-app \\', `  --label ${env.labelWatch}=true \\`, ...(enforce ? [`  --label ${env.labelEnforce}=true \\`] : []), '  my-app:latest'].join('\n');
}


// 대시보드 띠: 실제 수집(gadget)인데 감시 중인 내 컨테이너(sg-install · sg-probe 제외)가 0개
const isOwn = (name: string) => !/^sg-(install|probe)-/.test(name);

export function needsIntegration(st: IntegrationStatus | undefined): boolean {
  if (!st || st.env.source !== 'gadget') return false;
  return !st.containers.some((c) => c.watched && isOwn(c.name));
}

