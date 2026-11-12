import type { Term as TermValue } from '../labels';
import { termTitle, withOriginal } from '../labels';

// "쉬운 말(원어)" 표기 + 한 줄 툴팁. 색만이 아니라 점선 밑줄로 설명이 있음을 알린다.
export function Term({ term, short }: { term: TermValue; short?: boolean }) {
  return <span className="term" title={termTitle(term)}>{short ? term.label : withOriginal(term)}</span>;
}
