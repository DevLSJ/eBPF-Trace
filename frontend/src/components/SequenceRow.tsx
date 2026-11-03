import { seqLine } from '../lib/sequence';
import type { Verdict } from '../lib/types';

// 이벤트 · 감사 상세의 「연쇄」 줄(11/04) — 판정에 sequence 가 있을 때만. <dl> 안에 dt · dd 로 들어간다
export function SequenceRow({ v }: { v: Pick<Verdict, 'ruleId' | 'sequence'> }) {
  const line = seqLine(v);
  if (!line) return null;
  return (
    <>
      <dt className="text-slate-500">연쇄</dt>
      <dd className="font-mono text-xs break-words" data-part="sequence">
        {line}
      </dd>
    </>
  );
}
