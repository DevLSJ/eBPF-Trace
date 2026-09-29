import { useEffect, useState, type ReactNode } from 'react';

// 되돌리기 어려운 동작은 두 번 눌러 확정한다 (브라우저 confirm 대화상자 대신)
export function ConfirmButton({
  onConfirm,
  confirmLabel,
  disabled,
  className,
  children,
}: {
  onConfirm: () => void;
  confirmLabel: string;
  disabled?: boolean;
  className: string;
  children: ReactNode;
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = window.setTimeout(() => setArmed(false), 4000);
    return () => window.clearTimeout(t);
  }, [armed]);
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => {
        if (armed) {
          setArmed(false);
          onConfirm();
        } else setArmed(true);
      }}
      className={`${className} ${armed ? '!bg-red-600 !text-white' : ''}`}
    >
      {armed ? confirmLabel : children}
    </button>
  );
}
