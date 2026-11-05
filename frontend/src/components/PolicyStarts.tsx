import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/auth-context';
import { useLoad } from '../hooks/useLoad';
import { api } from '../lib/api';
import { allowLink, blockLink } from '../lib/policyEasy';
import type { Event } from '../lib/types';
import { Section } from './Sheet';

// 이 행동으로 정책 만들기(10/16): 막기 = 값이 채워진 새 정책, 허용 = 걸린 정책에 가장 좁은 예외를 더해 열기.
// 조회자는 정책을 저장할 수 없으니 링크를 그리지 않는다(W18 — 보이는데 못 누르는 버튼 금지)
export function PolicyStarts({ event, ruleId }: { event: Event; ruleId?: string }) {
  const { isAdmin } = useAuth();
  return isAdmin ? <Starts event={event} ruleId={ruleId} /> : null;
}

function Starts({ event, ruleId }: { event: Event; ruleId?: string }) {
  const rules = useLoad(api.listRules);
  const blk = blockLink(event);
  const alw = ruleId ? allowLink(rules.data?.find((r) => r.id === ruleId), event) : null;
  if (!blk && !alw) return null;
  const btn = 'sg-btn sg-btn-sm sg-btn-secondary';
  return (
    <Section title="이 행동으로 정책 만들기">
      <div className="flex flex-wrap gap-2">
        {blk && (
          <Link {...blk} className={btn} data-action="block-this">
            이 행동 막기 →
          </Link>
        )}
        {alw && (
          <Link {...alw} className={btn} data-action="allow-this">
            이 행동 허용({ruleId} 에 예외) →
          </Link>
        )}
      </div>
    </Section>
  );
}
