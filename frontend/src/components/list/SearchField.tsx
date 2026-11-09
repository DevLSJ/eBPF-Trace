import { Search } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import '../table-kit.css';

// 목록 검색칸 · 필터 줄(11/09, 참고 제품의 목록 틀 — 값 · 동작만). 검색 단추 없음:
//   SearchField  쓰는 동안은 적용하지 않고 Enter · 칸 벗어날 때 onApply(앞뒤 공백 뺌) · Esc 는 고치던 글을 적용된 값으로 되돌림
//                (고친 것이 없으면 Esc 를 막지 않는다 — 시트 · 창 닫기가 그대로). 폭 300 · 높이 36 · 최대 100자 · 왼쪽 돋보기
//   FilterBar    검색칸 + 선택 상자 묶음(간격 8 · 줄바꿈), 조건이 하나라도 있으면(active) 끝에 「조건 지우기」
export function SearchField({
  value,
  onApply,
  label,
  placeholder,
  maxLength = 100,
  width,
}: {
  value: string;
  onApply: (value: string) => void;
  // 화면 읽기 이름(예: 「정책 검색」)
  label: string;
  placeholder?: string;
  maxLength?: number;
  width?: number;
}) {
  const [draft, setDraft] = useState(value);
  const [seen, setSeen] = useState(value);
  // 바깥에서 값이 바뀌면(조건 지우기 · 주소 이동) 칸도 따라간다
  if (value !== seen) {
    setSeen(value);
    setDraft(value);
  }
  const apply = () => {
    const v = draft.trim();
    if (v !== draft) setDraft(v);
    if (v !== value) onApply(v);
  };
  return (
    <span className="tk-search" data-part="search" style={width ? { width } : undefined}>
      <Search className="tk-search-ico" aria-hidden />
      <input
        type="text"
        role="searchbox"
        aria-label={label}
        placeholder={placeholder ?? label}
        enterKeyHint="search"
        maxLength={maxLength}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={apply}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            apply();
          } else if (e.key === 'Escape' && draft !== value) {
            e.preventDefault();
            e.stopPropagation();
            setDraft(value);
          }
        }}
      />
    </span>
  );
}

export function FilterBar({ children, active, onClear, name }: { children: ReactNode; active: boolean; onClear: () => void; name?: string }) {
  return (
    <div className="tk-filters" role="search" data-filter-bar={name}>
      {children}
      {active && (
        <button type="button" className="tk-link" data-action="clear-conditions" onClick={onClear}>
          조건 지우기
        </button>
      )}
    </div>
  );
}
