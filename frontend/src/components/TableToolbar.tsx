import { Columns3, Download, RefreshCw } from 'lucide-react';
import { useId, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import type { TableKit } from '../hooks/useTableKit';
import { fmtNum } from '../lib/format';
import { ActionButton } from './ActionButton';
import { BusyBar } from './DataTable';
import { placePop, usePopEvents, type Pop } from './popover';
import './table-kit.css';

// 표 도구줄(11/09, 참고 제품의 목록 틀 — 값 · 배치만): 표 카드 맨 위 한 줄.
//   왼쪽  「총 N건」(+ 화면 도구 children)
//   오른쪽 「N개 선택」 → 새로고침 → 칸 고르기 → CSV 내려받기(아이콘 단추, 각자 줄 때만)
// 칸 고르기는 kit(useTableKit) 을 줄 때만 — 이름 있는 칸의 보이기 체크 · 마지막 하나는 못 끔 · 「칸 기본으로」(보이기 · 폭 · 순서).
//   여러 칸을 연달아 켜고 끄게 고른 뒤에도 열린 채(Esc · 바깥 · 같은 단추로 닫음)
// refreshing(11/09 E1): 다시 받는 동안 이전 줄은 그대로 두고 도구줄 아래 2px 진행 띠 · 새로고침은 aria-disabled + 사유
// 꺼진 단추는 진짜 disabled 대신 aria-disabled + 사유(ActionButton)
export function TableToolbar<T>({
  name,
  total,
  kit,
  onRefresh,
  refreshing,
  onExport,
  exportLabel = 'CSV 내려받기',
  selected,
  children,
}: {
  name: string;
  total?: number | null;
  kit?: TableKit<T>;
  onRefresh?: () => void;
  refreshing?: boolean;
  onExport?: () => void;
  exportLabel?: string;
  selected?: number;
  children?: ReactNode;
}) {
  return (
    <div className="tk-tools" data-table-tools={name}>
      <div className="tk-tools-side">
        {total != null && (
          <span className="tk-total num" data-part="total">
            총 {fmtNum(total)}건
          </span>
        )}
        {children}
      </div>
      <div className="tk-tools-side">
        {!!selected && (
          <span className="tk-total num" data-part="selected">
            {fmtNum(selected)}개 선택
          </span>
        )}
        {onRefresh && (
          <ActionButton className="tk-icon-btn" data-action="table-refresh" aria-label="새로고침" title="새로고침" reason={refreshing && '불러오는 중'} onClick={onRefresh}>
            <RefreshCw className={refreshing ? 'sg-spin' : undefined} aria-hidden />
          </ActionButton>
        )}
        {kit && <ColumnPicker kit={kit} />}
        {onExport && (
          <button type="button" className="tk-icon-btn" data-action="table-export" aria-label={exportLabel} title={exportLabel} onClick={onExport}>
            <Download aria-hidden />
          </button>
        )}
      </div>
      <BusyBar on={!!refreshing} className="tk-tools-busy" />
    </div>
  );
}

export function ColumnPicker<T>({ kit }: { kit: TableKit<T> }) {
  const btn = useRef<HTMLButtonElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const [pop, setPop] = useState<Pop | null>(null);
  const id = useId();
  const close = (focusBack: boolean) => {
    setPop(null);
    if (focusBack) btn.current?.focus();
  };
  usePopEvents(!!pop, [btn, box], close, () => btn.current && setPop(placePop(btn.current, { align: 'end', maxH: 420 })));
  const toggle = (e: MouseEvent<HTMLButtonElement>) => {
    if (pop) return close(false);
    setPop(placePop(e.currentTarget, { align: 'end', maxH: 420 }));
    // 키보드로 열었으면(Enter · Space) 첫 체크로
    if (e.detail === 0) requestAnimationFrame(() => box.current?.querySelector<HTMLElement>('input:not([aria-disabled])')?.focus());
  };
  const shown = kit.picks.filter((p) => p.visible).length;
  return (
    <>
      <button
        ref={btn}
        type="button"
        className="tk-icon-btn"
        data-action="table-columns"
        aria-label="칸 고르기"
        title="칸 고르기"
        aria-haspopup="dialog"
        aria-expanded={!!pop}
        aria-controls={pop ? id : undefined}
        onClick={toggle}
      >
        <Columns3 aria-hidden />
      </button>
      {pop &&
        createPortal(
          <div ref={box} id={id} role="dialog" aria-label="칸 고르기" data-part="column-picker" data-overlay="columns" className="tk-pop tk-colpick" style={pop.style}>
            <div className="tk-pop-title">칸</div>
            {kit.picks.map((p) => {
              const last = p.visible && shown <= 1;
              return (
                <label key={p.key} data-col={p.key} className="tk-check" title={last ? '칸은 하나 이상 보여야 함' : undefined}>
                  <input type="checkbox" checked={p.visible} aria-disabled={last ? 'true' : undefined} onChange={(e) => !last && kit.setVisible(p.key, e.target.checked)} />
                  <span>{p.name}</span>
                </label>
              );
            })}
            <div className="tk-pop-foot">
              <ActionButton className="tk-link" data-action="columns-reset" reason={kit.isDefault && '이미 기본 칸'} onClick={kit.resetColumns} title="보이기 · 폭 · 순서를 기본으로">
                칸 기본으로
              </ActionButton>
            </div>
          </div>,
          pop.host,
        )}
    </>
  );
}
