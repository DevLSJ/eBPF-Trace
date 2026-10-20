import { Link } from 'react-router-dom';
import { useLoad } from '../hooks/useLoad';
import { api } from '../lib/api';
import { allowLink, blockLink } from '../lib/policyEasy';
import type { Event } from '../lib/types';
import { Section } from './Sheet';

// 이 행동으로 정책 만들기(10/16): 막기 = 값이 채워진 새 정책, 허용 = 걸린 정책에 가장 좁은 예외를 더해 열기
export function PolicyStarts({ event, ruleId }: { event: Event; ruleId?: string }) {
  const rules = useLoad(api.listRules);
  const blk = blockLink(event);
  const alw = ruleId ? allowLink(rules.data?.find((r) => r.id === ruleId), event) : null;
  if (!blk && !alw) return null;
  const btn = 'rounded-md border border-slate-300 px-2.5 py-1 text-xs text-slate-700 hover:bg-slate-50';
  return (
    <Section title="이 행동으로 정책 만들기">
      <div className="flex flex-wrap gap-2">
        {blk && (
          <Link to={blk} className={btn} data-action="block-this">
            이 행동 막기 →
          </Link>
        )}
        {alw && (
          <Link to={alw} className={btn} data-action="allow-this">
            이 행동 허용({ruleId} 에 예외) →
          </Link>
        )}
      </div>
    </Section>
  );
}
