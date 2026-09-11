import { useMemo } from 'react';
import type { DetectionEvent, Severity } from '../types';

export function useEventFilter(events: DetectionEvent[], severity: Severity | '', since: number) {
  return useMemo(() => events.filter(event => (!severity || event.severity === severity)
    && (!since || Date.parse(event.detected_at) >= since)), [events, severity, since]);
}
