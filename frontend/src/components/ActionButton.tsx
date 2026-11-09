import type { ButtonHTMLAttributes } from 'react';
import './table-kit.css';

// 꺼진 단추(11/09 SPEC-1109 §3 — 참고 제품 10/30 규칙): 진짜 disabled 대신 aria-disabled="true" + 사유 툴팁(title).
// 키보드 초점은 가고(화면 읽기가 사유를 읽는다) 누름만 막는다. 조회자에게 쓰기 단추를 아예 그리지 않는 기존 규칙(W16/W18)은 그대로 —
// reason 은 「권한은 있는데 지금은 못 하는」 경우에만 준다.
//   <ActionButton className="sg-btn sg-btn-secondary" reason={picked ? null : '목록에서 먼저 고름'} onClick={…}>삭제</ActionButton>
export function ActionButton({ reason, onClick, title, type = 'button', ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { reason?: string | null | false }) {
  const off = !!reason;
  return (
    <button
      {...rest}
      type={type}
      aria-disabled={off ? 'true' : undefined}
      title={off ? (reason as string) : title}
      onClick={(e) => {
        if (off) return e.preventDefault();
        onClick?.(e);
      }}
    />
  );
}
