import { useCallback, useState } from 'react';

// 미저장 판단(11/09): 처음 값(ready 가 된 순간)의 JSON 스냅숏과 지금 값을 비교 — 바꿨다가 되돌리면 「바뀐 것 없음」.
// 수정 창은 값을 불러온 뒤 ready=true 로 스냅숏을 뜬다. 저장해 새 기준이 생기면 reset()(다음 그리기의 값으로 다시 뜸).
//   const unsaved = useUnsaved(form, loaded);
//   <Modal size="xl" guard={() => unsaved.dirty} … />
export function useUnsaved<V>(value: V, ready = true) {
  const cur = JSON.stringify(value) ?? '';
  const [snap, setSnap] = useState<string | null>(() => (ready ? cur : null));
  if (ready && snap === null) setSnap(cur);
  const reset = useCallback(() => setSnap(null), []);
  return { dirty: ready && snap !== null && snap !== cur, reset };
}
