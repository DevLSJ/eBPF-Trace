import { Link } from 'react-router-dom';
import { Modal } from '../Modal';

// ? 도움말(10/20 E) — 목업 shared/app.js helpDialog 그대로: 사용 흐름 6단계 + 단축키 표.
// 목업의 「데모 제어」 문장은 목업 전용이라 뺐다. 설명 문장은 「~합니다」체(11/09 G10), 단축키 설명은 개조식 명사형.

const STEPS: [string, string, string][] = [
  ['대시보드에서 판정 대기 확인', '지금 처리할 일이 있는지 봅니다. 판정 대기는 격리 · 경고된 설치와 격리된 런타임 컨테이너입니다.', '/'],
  ['설치 검사에서 판정', '막힌 설치의 공격 체인과 정적 분석(OSV) 결과를 보고 「악성 확정」 또는 「오탐」으로 판정합니다.', '/installs'],
  ['정책에서 제안 적용', '판정이 만든 제안을 미리보기(과거 위반이 어떻게 바뀌는지)로 확인하고 적용하거나 버립니다.', '/policies'],
  ['이벤트로 지금 걸리는 것 보기', '실시간 위반만 봅니다. 행을 누르면 토폴로지로 이어집니다.', '/events'],
  ['토폴로지에서 런타임 판정', '컨테이너가 무엇에 손댔는지 관계로 보고, 격리된 컨테이너를 판정합니다.', '/topology'],
  ['감사 로그로 되짚기', '과거 위반과 판정 결과, 판정 · 정책 변경 이력을 기간으로 찾습니다.', '/audit'],
];

const SHORTCUTS: [string, string][] = [
  ['/', '사이드바 검색으로 이동(화면 · 패키지 · 컨테이너 · 규칙 id · 도메인 · 검사)'],
  ['?', '이 안내 열기'],
  ['Esc', '대화상자 · 패널 · 검색 결과 닫기'],
  ['Enter', '목록에서 고른 행 열기 (Space 도 같음)'],
  ['↑ ↓', '검색 결과 사이 이동'],
  ['[', '사이드바 접기 · 펼치기'],
];

export function HelpDialog({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="사용 안내" kind="help" wide onClose={onClose} foot={<button type="button" onClick={onClose} className="rounded-md bg-primary px-4 py-1.5 text-sm font-medium text-primary-fg hover:bg-primary-hover">닫기</button>}>
      <section className="grid gap-2">
        <h4 className="text-sm font-semibold">사용 흐름</h4>
        <ol data-part="flow" className="grid gap-1.5">
          {STEPS.map(([t, d, to], i) => (
            <li key={to} className="flex items-start gap-3 rounded-md border border-slate-100 px-3 py-2">
              <span className="num mt-0.5 grid size-5 shrink-0 place-items-center rounded-full bg-indigo-50 text-[11px] font-semibold text-accent-text">{i + 1}</span>
              <div className="min-w-0 flex-1">
                <b className="text-sm">{t}</b>
                <p className="text-xs text-slate-500">{d}</p>
              </div>
              <Link to={to} onClick={onClose} className="shrink-0 rounded px-2 py-1 text-xs text-accent-text hover:bg-indigo-50">
                이동
              </Link>
            </li>
          ))}
        </ol>
        <p className="text-xs text-slate-500">키보드 ? 로 이 안내를 엽니다.</p>
      </section>
      <section data-part="shortcuts" className="grid gap-2">
        <h4 className="text-sm font-semibold">단축키</h4>
        <dl className="grid grid-cols-[4.5rem_1fr] gap-x-3 gap-y-1.5 text-sm">
          {SHORTCUTS.map(([k, t]) => (
            <div key={k} className="contents">
              <dt>
                <kbd className="rounded border border-slate-300 bg-slate-50 px-1.5 py-0.5 font-mono text-xs">{k}</kbd>
              </dt>
              <dd className="text-slate-600">{t}</dd>
            </div>
          ))}
        </dl>
      </section>
    </Modal>
  );
}
