import { useState, type AnimationEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useCountUp } from '../hooks/useCountUp';
import { fmtNum } from '../lib/format';
import { reducedMotion } from '../lib/motion';
import type { Dest } from '../lib/nav';
import type { KpiDelta, Stripe } from '../lib/kpi';

// KPI 카드(11/04e 목업 U.kpiCard, R1 11/04) — 왼쪽 4px 띠(종류) · 오른쪽 위 아이콘 칩(글자 없이 data-icon) · 이름 13/600 ·
// 값 28/700 tabular(단위 13/500 분리) · 증감 줄 ▲▼(위반 · 격리 증가만 빨강 — kpiDelta 의 up/down 으로 정한다) · 보조 한 줄.
// 값 0(또는 없음)이면 띠만 색(숫자는 기본 색). 처음 그리기는 바로 값, 값이 바뀔 때만 카운트업 + 짧은 링(reduced-motion 이면 없음).
// 길게 눌러 옮기기(useSortable)는 카드 바깥(그리드)이 붙인다 — 카드는 data-kpi 만 준다.
export interface KpiCardProps {
  k: string;
  label: string;
  icon?: string;
  stripe?: Stripe;
  // 숫자(카운트업) — 글자 값(퍼센트 · 「—」)이면 text, 그때 value 는 0 판단용(없으면 null)
  value?: number | null;
  text?: ReactNode;
  unit?: string;
  // 값 > 0 일 때 숫자 색(위반 · 격리 = danger)
  tone?: 'danger' | 'warn';
  // 증감 줄 — 없으면 줄 자체가 없다(평가 지표). 대시보드는 kpiDelta() 결과(이전 기간이 없으면 「이전 기간 정보 없음」)
  delta?: KpiDelta;
  sub?: ReactNode;
  // 보조 줄 전체 문구(말줄임 툴팁)
  subTitle?: string;
  to?: Dest;
  // 칸 안에서 줄 바꿈을 허용(평가 지표처럼 보조 줄이 길 때)
  wrapSub?: boolean;
  className?: string;
  // 바깥(길게 눌러 옮기기 등)이 루트에 붙이는 속성(data-sort-id · tabIndex · aria-describedby)
  attrs?: Record<string, string | number | undefined>;
  // 카드 툴팁 — 무엇을 세는지 한 줄(11/09 G33)
  hint?: string;
}

// 1천만 이상은 만 단위로 줄인다(「1,235만」) — 정확한 값은 값 툴팁(11/09 G36). 그 밑은 천 단위 쉼표 그대로
const BIG = 10_000_000;
const kpiNum = (n: number) => (Math.abs(n) >= BIG ? `${fmtNum(Math.round(n / 10_000))}만` : fmtNum(n));

export function KpiCard({ k, label, icon = '▦', stripe = 'accent', value, text, unit, tone, delta, sub, subTitle, to, wrapSub, className = '', attrs, hint }: KpiCardProps) {
  // 0 · 값 없음(빈 글자)이면 띠만 색 — 글자 값(퍼센트 등)은 value 를 주지 않아도 된다
  const zero = value === 0 || (value == null && (text == null || text === ''));
  const n = useCountUp(value ?? 0);
  const [ring, ringDone] = useRing(value ?? null);
  const onAnim = (e: AnimationEvent) => e.animationName === 'kpi-ring' && e.target === e.currentTarget && ringDone();
  const d: KpiDelta = delta ?? { dir: 'none' };
  const arrow = d.dir === 'up' ? '▲ ' : d.dir === 'down' ? '▼ ' : ''; // 변화 없음은 표시 없이 글자만
  const cls = `kpi-card stripe-${stripe}${zero ? ' is-zero' : ''}${ring ? ' kpi-ring' : ''} ${to ? 'kpi-link' : ''} ${className}`;
  const body = (
    <>
      <span className="kpi-name">{label}</span>
      <i className="kpi-ico" data-icon={icon} aria-hidden />
      <div className="kpi-num" data-value="">
        <b className={`kpi-val num tone-${!zero && tone ? tone : 'default'}`} title={text == null && value != null && Math.abs(value) >= BIG ? fmtNum(value) : undefined}>
          {text ?? kpiNum(n)}
        </b>
        {unit && <small className="kpi-unit">{unit}</small>}
      </div>
      {delta && (
        <div className={`kpi-delta tone-${d.tone ?? 'neutral'}`} data-delta={d.dir} data-delta-tone={d.tone ?? 'neutral'}>
          {d.dir === 'none' ? (
            <small className="kpi-note">{d.note ?? '이전 기간 정보 없음'}</small>
          ) : (
            <>
              <b className="num">{`${arrow}${d.text ?? ''}`}</b>
              {d.note && <small className="kpi-note">{d.note}</small>}
            </>
          )}
        </div>
      )}
      <span className={`kpi-sub${wrapSub ? ' kpi-sub-wrap' : ''}`} data-hint="" title={subTitle}>
        {sub}
      </span>
    </>
  );
  return to ? (
    <Link {...to} className={cls} data-kpi={k} title={hint} onAnimationEnd={onAnim} {...attrs}>
      {body}
    </Link>
  ) : (
    <div className={cls} data-kpi={k} title={hint} onAnimationEnd={onAnim} {...attrs}>
      {body}
    </div>
  );
}

// 값이 바뀌면 짧은 링(--t-slow × 2, CSS) — 처음 그리기에는 없다. 렌더 중에 직전 값과 비교하고, 링 애니메이션이 끝나면(onAnimationEnd) 뗀다
function useRing(value: number | null) {
  const [prev, setPrev] = useState(value);
  const [on, setOn] = useState(false);
  if (prev !== value) {
    setPrev(value);
    if (!reducedMotion()) setOn(true);
  }
  return [on, () => setOn(false)] as const;
}
