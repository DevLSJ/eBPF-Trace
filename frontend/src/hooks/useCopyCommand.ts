import { useCallback } from 'react';
import { useToast } from './toast-context';

// 명령 복사 — 성공 · 실패 모두 토스트로 알린다(실패하면 직접 입력하도록 명령을 보여 준다)
export function useCopyCommand() {
  const toast = useToast();
  return useCallback(
    (cmd: string) => {
      const ok = () => toast(`명령을 복사했습니다 — ${cmd}`, { key: 'copy', tone: 'ok' });
      const fail = () => toast(`복사하지 못했습니다 — 직접 입력하세요: ${cmd}`, { key: 'copy', tone: 'warn' });
      try {
        navigator.clipboard.writeText(cmd).then(ok, fail);
      } catch {
        fail();
      }
    },
    [toast],
  );
}
