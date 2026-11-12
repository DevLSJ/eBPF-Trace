import { screenNote } from '../lib/screenCopy';
import './table-kit.css';

// 표 아래 안내 한 줄(11/09 SPEC-1109 §7): 설명에서 뺀 제약 · 위치 안내. 작은 흐린 글 한 줄, 넘치면 「…」 + 마우스 올리면 전체(title).
// 문장은 lib/screenCopy.ts SCREEN_NOTE 한 곳 — screen 키로 꺼내거나(권장) text 로 직접 준다. 문장이 없으면 그리지 않는다
//   <ScreenNote screen="policies" />
export function ScreenNote({ screen, text }: { screen?: string; text?: string }) {
  const t = text ?? (screen ? screenNote(screen) : '');
  if (!t) return null;
  return (
    <p className="tk-screen-note" data-part="screen-note" title={t}>
      {t}
    </p>
  );
}
