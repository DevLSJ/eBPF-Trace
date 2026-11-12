import type { LucideIcon } from 'lucide-react';
import type { ButtonHTMLAttributes } from 'react';
import './table-kit.css';

// 꺼진 단추(11/09 SPEC-1109 §3 — 참고 제품 10/30 규칙): 진짜 disabled 대신 aria-disabled="true" + 사유 툴팁(title).
// 키보드 초점은 가고(화면 읽기가 사유를 읽는다) 누름만 막는다. 조회자에게 쓰기 단추를 아예 그리지 않는 기존 규칙(W16/W18)은 그대로 —
// reason 은 「권한은 있는데 지금은 못 하는」 경우에만 준다.
// 사유 문구(§7): 문장 · 마침표 없음 — 「[무엇]을 [동작]할 권한이 없습니다」 · 「[무엇]을 고르세요」 · 「바뀐 것이 없습니다」 · 「[조건] 뒤 쓸 수 있습니다」.
//   끝 마침표는 여기서 떼어 낸다(화면이 붙여 넘겨도 같은 모양)
//   <ActionButton className="sg-btn sg-btn-secondary" reason={picked ? null : '지울 정책을 고르세요'} onClick={…}>삭제</ActionButton>
const reasonText = (r: string) => r.trim().replace(/[.。]+$/, '');

export function ActionButton({ reason, onClick, title, type = 'button', ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { reason?: string | null | false }) {
  const off = !!reason;
  return (
    <button
      {...rest}
      type={type}
      aria-disabled={off ? 'true' : undefined}
      title={off ? reasonText(reason as string) : title}
      onClick={(e) => {
        if (off) return e.preventDefault();
        onClick?.(e);
      }}
    />
  );
}

// 아이콘 단추(§7): title 과 aria-label 을 같은 이름으로 — 동작 명사구, 대상이 있으면 「동작(대상)」(예: 「되돌리기(chg-0002)」).
// 꺼지면 title 은 사유, aria-label 은 이름 그대로(화면 읽기는 이름 + 사유)
//   <IconAction icon={RotateCcw} label="되돌리기" target={c.id} reason={c.locked && '시스템 규칙은 되돌릴 수 없습니다'} onClick={…} />
export function IconAction({
  icon: Icon,
  label,
  target,
  className = 'tk-icon-btn',
  ...rest
}: { icon: LucideIcon; label: string; target?: string } & Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children' | 'aria-label' | 'title'> & { reason?: string | null | false }) {
  const name = target ? `${label}(${target})` : label;
  return (
    <ActionButton {...rest} className={className} aria-label={name} title={name}>
      <Icon aria-hidden />
    </ActionButton>
  );
}
