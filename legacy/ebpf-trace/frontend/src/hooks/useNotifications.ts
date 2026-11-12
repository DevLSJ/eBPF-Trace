import { useEffect, useRef } from 'react';
import { useEventStore } from '../store/eventStore';
import { useNotifyStore } from '../store/notifyStore';
import type { DetectionEvent, Health } from '../types';
import { SEVERITY, attackTypeLabel } from '../labels';

// 실시간 스트림·서버 상태의 변화를 알림 센터 기록과 토스트로 바꾼다.
// 토스트는 "지금 알아야 하는 것"(긴급·높음 실제 탐지, 연결 끊김·복구, 수집기 상태 변화)에만 쓰고,
// 나머지는 드로어에만 조용히 쌓는다. 훈련(모의) 이벤트는 드로어에 남기되 토스트로 방해하지 않는다.
export function useNotifications(health: Health | null, healthFailed: boolean) {
  const events = useEventStore(s => s.events);
  const status = useEventStore(s => s.status);
  const notify = useNotifyStore(s => s.notify), toast = useNotifyStore(s => s.toast);
  const seen = useRef<Set<number> | null>(null);
  const lastToast = useRef(0);

  useEffect(() => {
    if (!seen.current) { seen.current = new Set(events.map(e => e.event_id)); return; }
    const fresh: DetectionEvent[] = [];
    for (const event of events) { if (seen.current.has(event.event_id)) break; seen.current.add(event.event_id); fresh.push(event); }
    if (!fresh.length) return;
    for (const event of [...fresh].reverse()) {
      const simulation = event.source === 'simulation';
      notify({ kind: 'event', level: event.severity === 'critical' || event.severity === 'high' ? 'warn' : 'info', eventId: event.event_id, at: Date.parse(event.detected_at) || Date.now(),
        title: `${simulation ? '모의 ' : ''}${attackTypeLabel(event.attack_type)} · ${SEVERITY[event.severity]?.label ?? event.severity}`,
        body: `${event.flow.src_ip} → ${event.flow.dst_ip}:${event.flow.dst_port} · ${simulation ? '훈련용 SIMULATION 기록' : '실제 수집기 관측'}` });
    }
    const urgent = fresh.filter(e => e.source !== 'simulation' && (e.severity === 'critical' || e.severity === 'high'));
    if (urgent.length && Date.now() - lastToast.current > 3000) {
      lastToast.current = Date.now();
      const first = urgent[0];
      toast({ level: 'warn', duration: 6000, action: { label: '기록 보기', href: '#events' },
        text: urgent.length === 1 ? `새 탐지 · ${attackTypeLabel(first.attack_type)} (${SEVERITY[first.severity]?.label}) · ${first.flow.src_ip}` : `새 탐지 ${urgent.length}건 · 가장 최근 ${attackTypeLabel(first.attack_type)} (${SEVERITY[first.severity]?.label})` });
    }
  }, [events, notify, toast]);

  const previousStatus = useRef(status), everConnected = useRef(false);
  useEffect(() => {
    const before = previousStatus.current; previousStatus.current = status;
    if (before === status) return;
    if (status === 'connected' && !everConnected.current) {
      // 첫 접속: 드로어에만 남긴다(토스트로 방해하지 않음). 이후 끊김→복구는 토스트로 알린다.
      everConnected.current = true;
      notify({ kind: 'system', level: 'ok', title: '서버와 실시간으로 연결됐어요', body: '새 탐지 이벤트와 트래픽이 이 화면으로 바로 전달돼요.' });
      return;
    }
    if (status === 'connected') { notify({ kind: 'system', level: 'ok', title: '실시간 연결이 복구됐어요', body: '끊긴 동안의 기록은 저장된 탐지 기록에서 확인할 수 있어요.' }); toast({ level: 'ok', text: '실시간 연결이 복구됐어요.' }); }
    else if (status === 'reconnecting') { notify({ kind: 'system', level: 'warn', title: '실시간 연결이 끊겨 다시 연결하고 있어요', body: '잠시 기다리면 자동으로 이어져요.' }); toast({ level: 'warn', text: '실시간 연결이 끊겨 다시 연결하고 있어요.' }); }
    else { notify({ kind: 'system', level: 'error', title: '실시간 연결이 끊겼어요', body: '네트워크 연결을 확인하거나 새로고침해 주세요. 저장된 탐지 기록은 계속 볼 수 있어요.' }); toast({ level: 'error', duration: 6000, text: '실시간 연결이 끊겼어요. 네트워크를 확인해 주세요.', action: { label: '새로고침', onClick: () => location.reload() } }); }
  }, [status, notify, toast]);

  const previousCollector = useRef<boolean | null>(null), previousFailed = useRef(false);
  useEffect(() => {
    if (healthFailed !== previousFailed.current) {
      previousFailed.current = healthFailed;
      if (healthFailed) { notify({ kind: 'system', level: 'error', title: '분석 서버가 응답하지 않아요', body: '서버 실행 상태나 네트워크를 확인한 뒤 대시보드에서 [다시 시도]를 눌러 보세요.', href: '#overview' }); toast({ level: 'error', text: '분석 서버가 응답하지 않아요.' }); }
      else if (health) { notify({ kind: 'system', level: 'ok', title: '분석 서버 응답이 돌아왔어요' }); }
    }
    if (!health) return;
    const connected = health.collector_connected;
    if (previousCollector.current === null) { previousCollector.current = connected; if (!connected) notify({ kind: 'system', level: 'warn', title: '네트워크 수집기(Collector)가 아직 연결되지 않았어요', body: '연결될 때까지 실시간 그래프는 비어 있고, 저장된 탐지 기록은 계속 볼 수 있어요.', href: '#system' }); return; }
    if (connected === previousCollector.current) return;
    previousCollector.current = connected;
    if (connected) { notify({ kind: 'system', level: 'ok', title: '네트워크 수집기(Collector)가 연결됐어요', body: '실시간 트래픽 그래프가 곧 채워져요.', href: '#system' }); toast({ level: 'ok', text: '네트워크 수집기가 연결됐어요.', action: { label: '그래프 보기', href: '#system' } }); }
    else { notify({ kind: 'system', level: 'warn', title: '네트워크 수집기(Collector) 연결이 끊겼어요', body: '규칙 탐지는 저장된 기록으로 계속 볼 수 있어요. 수집기 서비스 상태를 확인하세요.', href: '#system' }); toast({ level: 'warn', text: '네트워크 수집기 연결이 끊겼어요.', action: { label: '상태 보기', href: '#system' } }); }
  }, [health, healthFailed, notify, toast]);
}
