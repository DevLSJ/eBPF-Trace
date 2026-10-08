'use client';
import { useCallback, useState } from 'react';
import Image from 'next/image';
import type { WsEnvelope, RuntimeIncident } from '@scw/shared-types';
import { useWebSocket } from '@/lib/ws';
import { purlShort, RULE_LABEL, simulate } from '@/lib/runtime';
import { cn } from '@/lib/utils';

const PRODUCTS = [
  { k: 'headphones', title: '무선 헤드폰 블랙 (박스 포함)', area: '중랑구 면목동', price: '89,000원' },
  { k: 'earbuds', title: '무선 이어폰 화이트 S급', area: '광진구 군자동', price: '120,000원' },
  { k: 'bicycle', title: '바구니 달린 클래식 자전거', area: '광진구 구의동', price: '150,000원' },
  { k: 'phone', title: '아이폰 X 실버 64GB', area: '광진구 군자동', price: '230,000원' },
];

const STEPS = ['수상한 프로그램 실행', '외부 도구 실행', '허용되지 않은 서버 접속', '위험 경보 생성'];

export default function DemoshopPage() {
  const [incidents, setIncidents] = useState<RuntimeIncident[]>([]);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const onEvent = useCallback((e: WsEnvelope) => {
    if (e.type === 'runtime.incident') {
      const inc = e.payload as RuntimeIncident;
      setIncidents((prev) => [inc, ...prev.filter((p) => p.incidentKey !== inc.incidentKey)].slice(0, 20));
    }
  }, []);
  useWebSocket(onEvent);

  const run = useCallback(async (scenario: 'pay' | 'image' | 'normal' | 'reset') => {
    setBusy(true);
    try {
      await simulate(scenario);
      if (scenario === 'reset') setIncidents([]);
      setToast(
        scenario === 'normal' ? '정상 사용 — 허용된 곳에만 연결' :
        scenario === 'reset' ? '초기화했습니다' : '시나리오 실행 — 탐지 결과를 확인하세요',
      );
    } catch {
      setToast('모사 스택(edge)에 연결할 수 없습니다. 런타임 스택과 에이전트를 먼저 켜세요.');
    } finally {
      setBusy(false);
      setTimeout(() => setToast(null), 4000);
    }
  }, []);

  const latest = incidents[0];
  const activeSteps = latest ? Math.min(4, latest.rules.length + 1) : 0;

  return (
    <section className="flex h-full flex-col gap-3">
      <div>
        <h1 className="text-[20px] font-semibold tracking-tight">공격 시연</h1>
        <p className="mt-0.5 text-[12px] text-fg-3">
          중고거래 앱 사용 → 오염된 패키지가 외부 서버 접속 시도 → 실시간 탐지를 한 화면에서 보여줍니다.
          (가상 브랜드 · 실제 외부 전송 없음)
        </p>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[300px_1fr]">
        {/* 중고거래 앱 폰 프레임 */}
        <div className="flex flex-col items-center">
          <div className="w-[290px] rounded-[34px] bg-[#111417] p-2.5 shadow-lg">
            <div className="flex h-[560px] flex-col overflow-hidden rounded-[26px] bg-white">
              <div className="flex items-center gap-1.5 px-4 pb-1 pt-2 text-[13px] font-bold text-[#111]">군자동 중고거래</div>
              <div className="min-h-0 flex-1 overflow-auto">
                {PRODUCTS.map((p) => (
                  <div key={p.k} className="flex gap-3 border-b border-[#f2f2f2] p-3">
                    <Image src={`/shop/${p.k}-thumb.jpg`} alt={p.title} width={72} height={72} className="h-[72px] w-[72px] rounded-[10px] object-cover" />
                    <div className="min-w-0">
                      <div className="truncate text-[13.5px] text-[#111]">{p.title}</div>
                      <div className="mt-0.5 text-[12px] text-[#8a9099]">{p.area}</div>
                      <div className="mt-1 text-[14px] font-bold text-[#111]">{p.price}</div>
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-2 border-t border-[#eee] p-3">
                <div className="flex-1 text-[13px] font-bold text-[#111]">89,000원</div>
                <button
                  onClick={() => run('pay')}
                  disabled={busy}
                  className="rounded-[10px] bg-[#17b26a] px-5 py-2.5 text-[14px] font-bold text-white disabled:opacity-60"
                >
                  안전결제
                </button>
              </div>
            </div>
          </div>
          <p className="mt-2 text-center text-[11.5px] text-fg-3"><b className="text-fg-2">중고거래 앱</b> · 안전결제=결제 서비스 호출</p>
        </div>

        {/* 제어 + 실시간 탐지 */}
        <div className="flex min-h-0 flex-col gap-3.5 overflow-auto">
          <div className="rounded-2xl border border-line bg-surface">
            <div className="flex items-center justify-between border-b border-line px-4 py-3">
              <h2 className="text-[14px] font-bold">시연 제어</h2>
              <span className="text-[12px] text-fg-3">버튼을 누르면 실제 비콘이 발생합니다</span>
            </div>
            <div className="grid grid-cols-2 gap-2.5 p-4">
              <ScnButton title="결제 시나리오" desc="결제 중 오염 패키지가 외부 접속" onClick={() => run('pay')} busy={busy} danger />
              <ScnButton title="사진 올리기 시나리오" desc="업로드 중 몰래 명령 실행" onClick={() => run('image')} busy={busy} danger />
              <ScnButton title="정상 사용" desc="허용된 곳에만 연결 · 경보 없음" onClick={() => run('normal')} busy={busy} />
              <ScnButton title="초기화" desc="탐지 결과를 지우고 처음으로" onClick={() => run('reset')} busy={busy} />
            </div>
          </div>

          <div className="rounded-2xl border border-line bg-surface">
            <div className="flex items-center justify-between border-b border-line px-4 py-3">
              <h2 className="text-[14px] font-bold">실시간 탐지</h2>
              <span className="rounded-md bg-surface-2 px-2 py-0.5 text-[11.5px] text-fg-2">서버 내부 실시간 추적</span>
            </div>
            <div className="p-4">
              <div className={cn('flex items-center gap-3 rounded-xl p-3', latest ? 'bg-crit-soft' : 'bg-surface-2')}>
                <div className={cn('text-[30px] font-extrabold', latest ? 'text-crit' : 'text-fg-3')}>
                  {latest ? latest.score : '—'}
                </div>
                <div>
                  <b className="text-[14px]">{latest ? '위험 · 공급망 공격 의심' : '대기 중'}</b>
                  <div className="text-[12px] text-fg-2">
                    {latest ? `원인 패키지 ${purlShort(latest.purl)}` : '시나리오를 실행하면 탐지 과정이 여기에 표시됩니다'}
                  </div>
                </div>
              </div>
              <ol className="mt-3">
                {STEPS.map((label, i) => {
                  const on = i < activeSteps;
                  return (
                    <li key={i} className={cn('flex items-start gap-3 border-b border-dashed border-line py-2.5', !on && 'opacity-40')}>
                      <span className={cn('grid h-5 w-5 place-items-center rounded-full text-[11px] font-bold', on ? 'bg-crit-soft text-crit-ink' : 'bg-surface-2 text-fg-3')}>{i + 1}</span>
                      <span className="text-[13px] font-medium">{label}</span>
                    </li>
                  );
                })}
              </ol>
              <p className="mt-2 text-[11.5px] text-fg-3">
                접속 대상은 데모 내부의 가짜 서버로, 받은 내용을 기록만 합니다. 실제 외부 전송은 없습니다.
                차단은 <b className="text-fg-2">런타임 추적·차단</b> 화면에서 할 수 있습니다.
              </p>
            </div>
          </div>
        </div>
      </div>

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 rounded-xl border border-line-strong bg-surface px-4 py-3 text-[12.5px] shadow-lg" role="status">
          {toast}
        </div>
      )}
    </section>
  );
}

function ScnButton({ title, desc, onClick, busy, danger }: { title: string; desc: string; onClick: () => void; busy: boolean; danger?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className="flex min-w-0 items-center gap-3 rounded-xl border border-line-strong bg-surface p-3 text-left transition hover:bg-surface-2 disabled:opacity-60"
    >
      <span className={cn('grid h-10 w-10 shrink-0 place-items-center rounded-[10px]', danger ? 'bg-crit-soft text-crit-ink' : 'bg-good-soft text-good-ink')}>▶</span>
      <span className="min-w-0">
        <span className="block truncate text-[13.5px] font-bold">{title}</span>
        <span className="block truncate text-[12px] text-fg-2">{desc}</span>
      </span>
    </button>
  );
}
