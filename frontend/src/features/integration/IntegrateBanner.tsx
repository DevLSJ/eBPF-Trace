import { ArrowRight, Plug, X } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Link } from 'react-router-dom';
import { useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import type { IntegrationStatus } from '../../lib/types';
import { needsIntegration } from './model';
import './integration.css';

// 대시보드 위 띠(11/06 사용자 결정): 실제 수집(gadget)인데 라벨 · 이름으로 감시 중인 내 컨테이너가 0개면 「연동 시작하기」.
// sg-install · 시험(sg-probe) 컨테이너는 세지 않는다. 닫으면 이 브라우저에서 다시 안 보임(저장이 막혀 있어도 이번 화면만 닫힘)
const KEY = 'supplyguard.integrate.banner';
function hiddenBefore(): boolean {
  try {
    return localStorage.getItem(KEY) === 'hidden';
  } catch {
    return false;
  }
}

export function IntegrateBanner() {
  const load = useCallback(() => api.integration(), []);
  const { data } = useLoad<IntegrationStatus>(load);
  const [closed, setClosed] = useState(hiddenBefore);
  if (closed || !needsIntegration(data)) return null;
  const close = () => {
    setClosed(true);
    try {
      localStorage.setItem(KEY, 'hidden');
    } catch {
      /* 저장이 막혀 있으면 이번 화면만 닫는다 */
    }
  };
  return (
    <div className="int-banner" data-part="integrate-banner" role="status">
      <Plug className="size-4 int-banner-ico" aria-hidden />
      <span className="int-banner-text">
        <b>감시 중인 내 컨테이너 없음</b> — 라벨 한 줄(supplyguard.watch=true)로 연동 가능
      </span>
      <Link to="/integration" className="sg-btn sg-btn-sm sg-btn-primary int-banner-go" data-part="integrate-go">
        연동 시작하기 <ArrowRight className="size-3.5 int-banner-arrow" aria-hidden />
      </Link>
      <button type="button" className="int-banner-close" aria-label="다시 보지 않기" title="다시 보지 않기" data-part="integrate-close" onClick={close}>
        <X className="size-4" aria-hidden />
      </button>
    </div>
  );
}
