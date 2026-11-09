import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import './evaluation.css';
import { STATIC_TARGET_TEXT } from './targets';

// 평가 화면 용어 툴팁(11/09 사용자 결정 「평가 = 요점 3줄 + 쉬운 이름 + 용어 툴팁 + 자세한 표 접기」).
// 점선 밑줄 단추 = 설명 있음. 마우스를 올리거나(툴팁 위로 옮겨도 유지) 키보드로 포커스하면 열리고, 벗어나거나 Esc · 스크롤이면 닫힌다.
// 툴팁(role="tooltip")은 늘 문서에 있고(닫히면 hidden) 단추의 aria-describedby 가 가리킨다 — 화면 낭독기는 포커스 때 설명을 읽는다.
// 단추는 data-action="term"(조회자 읽기 전용 검사에서 「쓰기 단추 아님」), 공통 부품이 없어 이 폴더에만 둔다.
// q = 칸 머리 (?) 모양(11/09 저녁 목록) — 글자 대신 「?」 동그라미, 이름은 aria-label 「○○ 설명」.

interface Entry {
  term: string; // 원래 용어
  easy: string; // 화면에서 쓰는 쉬운 이름
  desc: string;
}
export const GLOSSARY = {
  recall: { term: '재현율', easy: '탐지율', desc: '실제 악성 중 악성으로 잡아낸 비율 · 높을수록 좋음' },
  fpr: { term: '오탐률', easy: '오판율', desc: '정상인데 악성으로 잘못 판정한 비율 · 낮을수록 좋음' },
  precision: { term: '정밀도', easy: '적중률', desc: '악성이라 판정한 것 중 실제 악성인 비율 · 높을수록 좋음' },
  f1: { term: 'F1', easy: '종합 점수', desc: '적중률과 탐지율을 함께 본 점수 · 0~1, 1에 가까울수록 좋음' },
  p50: { term: 'p50', easy: '중간값', desc: '절반은 이 값보다 빠름' },
  p95: { term: 'p95', easy: '95% 이내', desc: '100번 중 95번은 이 값 안에 끝남 · 느린 쪽 경계' },
  p50p95: { term: 'p50 · p95', easy: '중간값 · 95% 이내', desc: 'p50 = 절반이 이 값보다 빠름 · p95 = 100번 중 95번이 이 값 안에 끝남' },
  confusion: { term: '혼동 행렬', easy: '판정 4칸 표', desc: '실제(악성 · 정상) × 판정(악성 · 아님)으로 나눠 센 표 · 잡음 · 놓침 · 오판 · 통과' },
  hgb: { term: 'HistGradientBoosting (HGB)', easy: 'ML 모델', desc: '작은 결정 트리를 여러 개 차례로 더해 판정하는 기계 학습 모델' },
  logreg: { term: '로지스틱 회귀', easy: 'ML 모델', desc: '특징마다 가중치를 곱해 더한 값으로 악성 확률을 내는 기계 학습 모델' },
  guarddog: { term: 'GuardDog', easy: '코드 검사 도구', desc: '패키지 코드에서 위험한 패턴(규칙)을 찾는 공개 검사 도구 · 걸린 규칙으로 위험 점수를 매김' },
  malicious: { term: '악성', easy: '악성 판정', desc: 'GuardDog 점수 5 이상이고 설치 때 실행되는 위험 규칙이 1개 이상 걸림' },
  suspicious: { term: '주의', easy: '주의 판정', desc: 'GuardDog 점수 5 이상이지만 설치 때 실행되는 위험 규칙은 걸리지 않음' },
  vulnerable: { term: '취약', easy: '취약 판정', desc: '알려진 취약점(OSV)이 있는 버전' },
  static: { term: '정적 검사', easy: '패키지 코드 검사', desc: '설치하지 않고 패키지 코드만 검사(GuardDog · OSV)' },
  runtime: { term: '런타임 감시', easy: '설치 · 실행 감시', desc: '실제 커널에서 설치 · 실행 중 동작을 eBPF 로 관찰해 판정 · 위반이면 격리' },
  dryrun: { term: 'dryRun', easy: '시험 운영', desc: '판정만 기록하고 격리는 하지 않는 모드' },
  control: { term: '대조군', easy: '비교용 정상 시나리오', desc: '공격 조건을 일부러 비껴 간 시나리오 · 탐지 0% 가 정답' },
  split: { term: '보정 · 시험 구간', easy: '선택용 · 시험용', desc: '선택용 구간으로 모델 · 기준값을 고르고 시험용 구간으로 성능만 잼 · 시험용은 고를 때 쓰지 않음' },
  killapi: { term: 'kill 호출', easy: '격리 명령', desc: 'Docker API 로 컨테이너를 멈추는 단계' },
  // 11/09 저녁 목록 칸 머리 (?) — 줄마다 설명 문장을 두지 않고 칸 머리에서 한 번만
  colItem: { term: '항목', easy: '항목', desc: '정적 = 설치하지 않고 패키지 코드만 검사(GuardDog · OSV) · 런타임 = 실제 커널에서 설치 · 실행 동작을 eBPF 로 관찰해 판정, 위반이면 격리' },
  colResult: { term: '결과', easy: '결과', desc: '항목마다 핵심 수치 하나와 근거 · 막대는 비율(0~100%) · 줄을 누르면 차트와 표가 펼쳐짐' },
  colState: {
    term: '상태',
    easy: '상태',
    desc: `통과 = 기준 충족(공격 모두 탐지 · 대조군 탐지 0회, 정상 설치 위반 0건, 정적 ${STATIC_TARGET_TEXT}) · 주의 = 기준 미달, 펼쳐서 확인 · 규칙 우세 = 시험에서 규칙 판정의 종합 점수가 ML 모델보다 높음 · 참고 = 통과 기준이 없는 정보 · 결과 없음 = 측정 결과 파일 없음`,
  },
} as const satisfies Record<string, Entry>;
export type TermKey = keyof typeof GLOSSARY;

const GAP = 6;
const EDGE = 8;
const FOCUS_SCROLL_MS = 250;

// 열린 툴팁은 화면에 하나 — 새로 열리면 앞의 것을 닫는다
let closeOpen: (() => void) | null = null;

export function Term({ k, children, q }: { k: TermKey; children?: ReactNode; q?: boolean }) {
  const g: Entry = GLOSSARY[k];
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const tip = useRef<HTMLDivElement>(null);
  const timer = useRef(0);
  const openedAt = useRef(0);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);

  // 함수는 ref · setter 만 써서 처음 한 번 만든 것을 계속 쓴다(열린 툴팁 하나 규칙의 비교 기준)
  const close = useCallback(() => {
    window.clearTimeout(timer.current);
    setOpen(false);
  }, []);
  const show = useCallback(() => {
    window.clearTimeout(timer.current);
    if (closeOpen && closeOpen !== close) closeOpen();
    closeOpen = close;
    openedAt.current = performance.now();
    setOpen(true);
  }, [close]);
  // 단추에서 툴팁으로 옮겨 가는 사이(틈 6px)에는 닫지 않는다
  const closeSoon = useCallback(() => {
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(close, 120);
  }, [close]);

  // 자리: 단추 아래 가운데(넘치면 위), 좌우는 화면 안으로
  const place = useCallback(() => {
    if (!btn.current || !tip.current) return;
    const r = btn.current.getBoundingClientRect();
    const w = tip.current.offsetWidth;
    const h = tip.current.offsetHeight;
    const left = Math.min(Math.max(EDGE, r.left + r.width / 2 - w / 2), window.innerWidth - w - EDGE);
    const below = r.bottom + GAP;
    const top = below + h > window.innerHeight - EDGE ? Math.max(EDGE, r.top - h - GAP) : below;
    setPos({ left: Math.max(EDGE, left), top });
  }, []);
  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  // 열린 동안: Esc · 스크롤 · 창 크기 바뀜이면 닫는다.
  // 단, 열린 직후(FOCUS_SCROLL_MS)의 스크롤은 키보드 포커스가 스크롤 칸 밖의 단추를 보이게 끌어온 것 — 닫지 않고 자리만 다시 잡는다(11/09 저녁 목록)
  useEffect(() => {
    if (!open) return;
    const onKey = (e: globalThis.KeyboardEvent) => e.key === 'Escape' && close();
    const onMove = (e: Event) => (e.type === 'scroll' && performance.now() - openedAt.current < FOCUS_SCROLL_MS ? place() : close());
    document.addEventListener('keydown', onKey);
    window.addEventListener('scroll', onMove, true);
    window.addEventListener('resize', onMove);
    return () => {
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', onMove, true);
      window.removeEventListener('resize', onMove);
    };
  }, [open, close, place]);
  useEffect(
    () => () => {
      window.clearTimeout(timer.current);
      if (closeOpen === close) closeOpen = null;
    },
    [close],
  );

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Escape' && open) {
      e.stopPropagation(); // 툴팁만 닫는다(서랍 · 도우미 Esc 보다 먼저)
      close();
    }
  };

  return (
    <>
      <button
        ref={btn}
        type="button"
        className={q ? 'eval-term eval-q' : 'eval-term'}
        data-action="term"
        data-term={k}
        aria-label={q ? `${g.term} 설명` : undefined}
        aria-describedby={id}
        onMouseEnter={show}
        onMouseLeave={closeSoon}
        onFocus={show}
        onBlur={close}
        onClick={show}
        onKeyDown={onKeyDown}
      >
        {q ? '?' : (children ?? g.term)}
      </button>
      {createPortal(
        <div
          ref={tip}
          id={id}
          role="tooltip"
          data-part="term-tip"
          data-term={k}
          hidden={!open}
          className="eval-term-tip"
          style={pos ? { left: pos.left, top: pos.top } : undefined}
          onMouseEnter={show}
          onMouseLeave={closeSoon}
        >
          <b>
            {g.term}
            {g.easy !== g.term && <span className="eval-term-easy"> · {g.easy}</span>}
          </b>
          <span>{g.desc}</span>
        </div>,
        document.body,
      )}
    </>
  );
}
