import { useCallback } from 'react';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import type { IntegrationStatus } from '../../lib/types';

// 연동 세 페이지(연동 · 환경 점검 · 감시 중 컨테이너, 11/09 밤)가 같이 쓰는 GET /api/integration — 3초마다(연결 테스트 진행 중엔 1초)
export function useIntegration() {
  const load = useCallback(() => api.integration(), []);
  const { data, error, reload } = useLoad<IntegrationStatus>(load);
  useInterval(reload, data?.test?.state === 'running' ? 1000 : 3000);
  return { data, error, reload };
}
