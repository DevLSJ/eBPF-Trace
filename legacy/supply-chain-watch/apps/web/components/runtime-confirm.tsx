'use client';
import { useEffect, useRef, useState } from 'react';
import { blockIncident, getIncidentPreview, killIncident, type IncidentPreview } from '@/lib/runtime';
import { cn } from '@/lib/utils';

export type RuntimeAction = 'kill' | 'block';

// 종료·차단 전 확인 창 + 예상 결과 (ADR-020 U3). 미리보기를 불러온 뒤에만 실행 버튼이 켜진다.
export function RuntimeConfirm({
  incidentKey,
  action,
  onClose,
}: {
  incidentKey: string;
  action: RuntimeAction;
  onClose: (result?: { ok: boolean; message: string }) => void;
}) {
  const [preview, setPreview] = useState<IncidentPreview | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    getIncidentPreview(incidentKey).then(setPreview).catch((e: Error) => setLoadErr(e.message));
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') closeRef.current(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [incidentKey]);

  const isKill = action === 'kill';
  const blockedReason = !preview
    ? null
    : !preview.agentOnline
      ? '런타임 에이전트가 연결되어 있지 않아 실행할 수 없습니다'
      : !isKill && !preview.block.destIp
        ? '차단할 접속 주소가 기록되지 않았습니다'
        : null;
  const dangerous = !isKill && !!preview?.block.internalService;

  const run = async () => {
    setRunning(true);
    try {
      await (isKill ? killIncident(incidentKey) : blockIncident(incidentKey));
      onClose({ ok: true, message: isKill ? `${preview?.service}의 수상한 프로그램 종료를 요청했습니다` : `${preview?.block.destIp} 접속 차단을 요청했습니다` });
    } catch (e) {
      onClose({ ok: false, message: `실행하지 못했습니다: ${(e as Error).message}` });
    }
  };

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4" onClick={() => onClose()}>
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="rc-title"
        onClick={(e) => e.stopPropagation()}
        className="flex max-h-full w-[480px] max-w-full flex-col gap-3 overflow-auto rounded-2xl bg-surface p-5 shadow-card"
      >
        <h2 id="rc-title" className="text-[16px] font-bold">
          {isKill ? '수상한 프로그램을 종료할까요?' : '이 주소로의 접속을 막을까요?'}
        </h2>

        {!preview && !loadErr && <div className="text-[13px] text-fg-3">예상 결과를 확인하는 중…</div>}
        {loadErr && <div className="rounded-lg bg-crit-soft px-3 py-2 text-[13px] text-crit-ink">{loadErr}</div>}

        {preview && isKill && (
          <dl className="flex flex-col gap-2.5 text-[13px]">
            <Row label="대상 서비스">{preview.service}</Row>
            <Row label="꺼질 프로그램">
              {preview.kill.loops.length === 0 ? (
                <span className="text-fg-3">기록된 실행이 없습니다. 에이전트가 반복 실행 중인 프로그램을 찾아 종료합니다.</span>
              ) : (
                <ul className="flex flex-col gap-1">
                  {preview.kill.loops.map((l) => (
                    <li key={l.ppid}>
                      반복 실행 프로그램 <span className="font-mono text-[12px]">PID {l.ppid}</span>와 그 하위 실행
                      <div className="text-[12px] text-fg-2">
                        실행한 도구 {l.tools.map((t) => <code key={t} className="mx-0.5 rounded bg-surface-2 px-1">{t}</code>)} · {l.runs}회
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Row>
            <Row label="그대로 유지">{preview.kill.keeps}</Row>
          </dl>
        )}

        {preview && !isKill && (
          <dl className="flex flex-col gap-2.5 text-[13px]">
            <Row label="막힐 주소">
              <span className="font-mono">{preview.block.destIp ?? '—'}{preview.block.ports.length ? `:${preview.block.ports.join(', ')}` : ''}</span>
              <span className="ml-1.5 text-fg-2">({preview.block.destLabel})</span>
            </Row>
            <Row label="적용 범위">모사 서비스 전체 — 어느 서비스에서든 이 주소로는 더 이상 접속할 수 없습니다</Row>
            <Row label="영향받는 서비스">
              {preview.block.affected.length ? preview.block.affected.join(', ') : '최근 24시간 이 주소로 접속한 서비스 없음'}
              <span className="text-fg-3"> (최근 24시간 접속 기록 기준)</span>
            </Row>
            <Row label="되돌리기">{preview.block.undo}</Row>
          </dl>
        )}

        {dangerous && (
          <div className="rounded-lg bg-crit-soft px-3 py-2 text-[13px] font-semibold text-crit-ink">
            이 주소는 {preview?.block.internalService}입니다. 막으면 정상 서비스가 멈출 수 있습니다.
          </div>
        )}
        {blockedReason && <div className="rounded-lg bg-warn-soft px-3 py-2 text-[13px] text-warn-ink">{blockedReason}</div>}

        <div className="mt-1 flex justify-end gap-2">
          <button ref={cancelRef} onClick={() => onClose()} className="rounded-lg border border-line-strong px-4 py-2 text-[13px] font-semibold">
            취소
          </button>
          <button
            onClick={() => void run()}
            disabled={!preview || !!blockedReason || running}
            className={cn('rounded-lg px-4 py-2 text-[13px] font-bold text-white disabled:opacity-40', 'bg-crit')}
          >
            {running ? '요청 중…' : isKill ? '종료하기' : dangerous ? '그래도 차단하기' : '차단하기'}
          </button>
        </div>
      </div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[96px_minmax(0,1fr)] gap-2">
      <dt className="text-fg-3">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
