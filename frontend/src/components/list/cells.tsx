import type { HTMLAttributes, ReactNode } from 'react';
import { DASH, fmtLog, fmtTimeKind, isEmptyValue, toDate, type TimeKind } from './cell-format';
import '../table-kit.css';

// 표 칸 부품(11/09 SPEC-1109 §4 — 참고 제품 답변 G5 · G9 · G10 권고). 글자 도우미(빈 값 · 시각 형식)는 cell-format.ts
//   Dash      빈 값 「—」(흐린 글자). 상황 설명이 필요하면 문장을 화면이 직접 쓴다
//   TwoLine   두 줄 칸 — 위 13.5/500 · 아래 12 고정폭 흐림 · 줄간격 1.3(이름 + ID 등), 둘 다 말줄임
//   TimeText  시각 3형식 — 'log' 기록류 YYYY-MM-DD HH:mm:ss 고정폭 · 'status' 현황 MM-DD HH:mm + 전체 시각 툴팁 · 'day' 등록일 날짜만 + 툴팁.
//             상대 시각(「n분 전」)은 쓰지 않는다(내보내기 · 감사 증적과 맞지 않음)
export function Dash() {
  return <span className="tk-empty">{DASH}</span>;
}

export function TwoLine({ top, sub, title, ...rest }: { top: ReactNode; sub?: ReactNode; title?: string } & Omit<HTMLAttributes<HTMLSpanElement>, 'title'>) {
  return (
    <span className="tk-2line" title={title} {...rest}>
      <span className="tk-2l-top">{isEmptyValue(top) ? <Dash /> : top}</span>
      {!isEmptyValue(sub) && <span className="tk-2l-sub">{sub}</span>}
    </span>
  );
}

export function TimeText({ value, kind = 'log', ...rest }: { value: string | number | Date | null | undefined; kind?: TimeKind } & Omit<HTMLAttributes<HTMLElement>, 'children'>) {
  if (value === null || value === undefined || value === '') return <Dash />;
  const d = toDate(value);
  if (Number.isNaN(d.getTime())) return <Dash />;
  return (
    <time dateTime={d.toISOString()} title={kind === 'log' ? undefined : fmtLog(d)} className="tk-time num" data-kind={kind} {...rest}>
      {fmtTimeKind(d, kind)}
    </time>
  );
}
