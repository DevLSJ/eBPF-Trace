import { useState } from 'react';
import { Sparkles, X } from 'lucide-react';

// 처음 방문자 안내. 닫거나 1차 행동(시나리오 열기)을 누르면 localStorage에 기억해 다시 보이지 않는다.
export const ONBOARDING_KEY = 'ebpf.onboarding.dismissed';
const isDismissed = () => { try { return localStorage.getItem(ONBOARDING_KEY) === '1'; } catch { return false; } };

export function OnboardingCard() {
  const [dismissed, setDismissed] = useState(isDismissed);
  if (dismissed) return null;
  const close = () => { try { localStorage.setItem(ONBOARDING_KEY, '1'); } catch { /* 저장이 막힌 브라우저: 이번 세션에서만 닫힘 */ } setDismissed(true); };
  return <section className="onboarding" role="region" aria-labelledby="onboarding-title">
    <div className="onboarding-icon" aria-hidden="true"><Sparkles size={22}/></div>
    <div className="onboarding-body">
      <span className="onboarding-step">처음이신가요?</span>
      <h2 id="onboarding-title">이 화면은 네트워크에 흐르는 트래픽과 이상 징후를 실시간으로 보여줍니다.</h2>
      <p>먼저 <b>탐지 시나리오</b>를 실행해 위협이 어떻게 잡히는지 체험해 보세요. 아래 파란 "탐지 시나리오 체험" 카드에서도 언제든 시작할 수 있어요.</p>
      <div className="onboarding-actions"><a className="primary-button" href="#scenarios" onClick={close}>탐지 시나리오 실행해 보기</a><button className="text-button" type="button" onClick={close}>나중에 볼게요</button></div>
    </div>
    <button className="icon-button onboarding-close" type="button" aria-label="안내 닫기" onClick={close}><X size={18}/></button>
  </section>;
}
