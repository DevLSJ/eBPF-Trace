import { useEffect, useRef } from 'react';
import { Activity, FlaskConical, LayoutDashboard, Shield, ShieldAlert, X } from 'lucide-react';

// 사용 흐름 안내: 처음 사용하는 사람이 "어디부터 눌러야 하는지"를 한 화면에 보여준다.
// 상단바 물음표 버튼 또는 ? 키로 연다. 각 단계는 해당 화면으로 바로 이동한다.
export const GUIDE_STEPS = [
  { href: '#overview', icon: LayoutDashboard, label: '관찰', title: '지금 상태를 확인해요', body: '상단 신호등 배너(정상·주의·문제)로 서버·수집기 상태를 보고, 실시간 트래픽 그래프와 저장된 탐지 이벤트를 훑어봐요. 실시간 검사에서는 내 와이파이·랜선 트래픽을 직접 규칙 → AI → 대응에 통과시켜 볼 수 있어요.' },
  { href: '#scenarios', icon: FlaskConical, label: '체험', title: '탐지 시나리오를 실행해요', body: '외부로 패킷을 보내지 않는 모의 시나리오예요. 정상 접속 → 포트 스캔 → 연결 폭주 → 대용량 전송 → 회복이 어떻게 탐지되는지 15초 안에 볼 수 있어요.' },
  { href: '#events', icon: ShieldAlert, label: '검토', title: '탐지 기록을 검색하고 판정해요', body: '심각도·유형·IP로 검색하고, 이벤트를 열어 사람이 읽는 요약을 확인한 뒤 정탐·오탐을 기록해요(관리자 비밀키 필요).' },
  { href: '#incidents', icon: Shield, label: '대응', title: '사건을 맡고 승인받아 대응해요', body: '담당자 인수 → 조사 → 대응 미리보기 → 다른 승인자의 승인 → 억제 확인 → 해제 → 복구 관찰 → 종결. 차단은 정해진 시간이 지나면 스스로 풀려요.' },
  { href: '#capture', icon: Activity, label: '분석', title: '데이터로 근거를 확인해요', body: '실제 캡처(CIC-IDS-2017)의 정답 매칭률과 모델 비교 결과를 보고, 운영에 규칙 기반을 유지하는 이유를 확인해요.' },
];

export function GuideDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { const dialog = ref.current; if (!dialog) return; if (open && !dialog.open) dialog.showModal(); else if (!open && dialog.open) dialog.close(); }, [open]);
  return <dialog ref={ref} className="guide-dialog" aria-labelledby="guide-title" onCancel={e => { e.preventDefault(); onClose(); }} onClick={e => { if (e.target === ref.current) onClose(); }}>
    <div className="guide-inner">
      <header><div><span className="eyebrow">처음 사용 안내</span><h2 id="guide-title">다섯 단계로 따라가는 eBPF Trace</h2><p>왼쪽 메뉴는 이 순서대로 묶여 있어요. 단계를 누르면 해당 화면으로 이동해요.</p></div><button className="icon-button" type="button" aria-label="안내 닫기" onClick={onClose}><X size={18}/></button></header>
      <ol className="guide-steps">{GUIDE_STEPS.map((step, index) => { const Icon = step.icon; return <li key={step.href}><a href={step.href} onClick={onClose}><span className="guide-index">{index + 1}</span><span className="guide-icon"><Icon size={17}/></span><span className="guide-text"><strong>{step.title}</strong><p>{step.body}</p></span></a></li>; })}</ol>
      <footer><span><kbd>?</kbd> 이 안내 열기 · <kbd>Esc</kbd> 닫기 · 종 아이콘에서 새 탐지와 연결 상태 알림을 볼 수 있어요.</span><button className="primary-button" type="button" onClick={onClose}>알겠어요</button></footer>
    </div>
  </dialog>;
}
