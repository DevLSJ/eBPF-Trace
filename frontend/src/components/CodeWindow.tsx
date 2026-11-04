import type { KeyboardEvent, MouseEvent, ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { codeLang } from '../lib/codeLang';
import type { Dest } from '../lib/nav';

// 코드 창(11/04f 목업 U.codeWin, R1 11/04) — macOS 창 모양 카드: 머리줄(점 3개 · 파일명 · 종류 태그) + 어두운 코드 영역(.cw-body = 스크롤 요소).
// 6곳: 공급망 검사 코드 · 이벤트 원본 JSON · 증거 로그 · 시연 원문(R3) · 정책 YAML(입력칸이 곧 코드 영역) · AI 도우미 답 속 코드 블록.
//   body    'pre'(기본 — children 을 <pre class="cw-body"> 로) · 'div' · 'raw'(children 이 스스로 className={CW_BODY} 를 단 요소 — textarea · 줄 번호 코드)
//   wrap    로그 · 원문만 true(pre-wrap). 코드 · YAML · JSON 은 가로 스크롤
//   fill    남은 높이 채움(정책 YAML)
//   to · onClick  눌러서 여는 카드일 때만 — hover 떠오름(translateY -5px) + pointer. 읽기 전용은 그림자만 한 단계(--sh-1 → --sh-2)
// 점 색은 창 장식(위험 의미 아님) — 「빨강은 위험에만」의 예외, 채도를 낮춘 --win-* 토큰
export const CW_BODY = 'cw-body';

export function CodeWindow({
  name,
  lang,
  body = 'pre',
  wrap,
  fill,
  to,
  onClick,
  clickable,
  className = '',
  bodyClassName = '',
  children,
  ...rest
}: {
  name?: string | null;
  lang?: string | null;
  body?: 'pre' | 'div' | 'raw';
  wrap?: boolean;
  fill?: boolean;
  to?: Dest;
  onClick?: (e: MouseEvent | KeyboardEvent) => void;
  // 부품 시험용 — onClick 없이 클릭 카드 모양만
  clickable?: boolean;
  className?: string;
  bodyClassName?: string;
  children?: ReactNode;
} & Record<`data-${string}`, string | undefined>) {
  const kind = codeLang(name, lang);
  const click = !!(to || onClick || clickable);
  const head = (
    <div className="cw-head">
      <span className="cw-dots" aria-hidden>
        <i className="cw-dot cw-close" />
        <i className="cw-dot cw-min" />
        <i className="cw-dot cw-max" />
      </span>
      {name && (
        <span className="cw-name" title={name}>
          {name}
        </span>
      )}
      <span className="cw-tag">{kind}</span>
    </div>
  );
  const inner = body === 'raw' ? children : body === 'div' ? <div className={`${CW_BODY} ${bodyClassName}`}>{children}</div> : <pre className={`${CW_BODY} ${bodyClassName}`}>{children}</pre>;
  const attrs = {
    className: `code-win${fill ? ' cw-fill' : ''} ${className}`,
    'data-codewin': '',
    'data-lang': kind,
    'data-wrap': wrap ? '1' : '0',
    'data-click': click ? '1' : undefined,
    'aria-label': name ? `${name} (${kind})` : kind,
    ...rest,
  };
  if (to)
    return (
      <Link to={to.to} state={to.state} {...attrs}>
        {head}
        {inner}
      </Link>
    );
  if (click)
    return (
      <div
        {...attrs}
        role="button"
        tabIndex={0}
        onClick={(e) => onClick?.(e)}
        onKeyDown={(e) => {
          if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
            e.preventDefault();
            onClick?.(e);
          }
        }}
      >
        {head}
        {inner}
      </div>
    );
  return (
    <figure {...attrs} role="group">
      {head}
      {inner}
    </figure>
  );
}
