'use client';
import { useEffect, useState } from 'react';
import {
  DEFAULT_WHITELIST,
  getRuntimeConfig,
  pushWhitelist,
  setAutoBlock as apiSetAutoBlock,
} from '@/lib/runtime';
import { cn } from '@/lib/utils';

export default function SettingsPage() {
  const [autoBlock, setAutoBlock] = useState(false);
  const [wl, setWl] = useState(JSON.stringify(DEFAULT_WHITELIST, null, 2));
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    void getRuntimeConfig()
      .then((c) => {
        setAutoBlock(c.autoBlock);
        if (c.whitelist && typeof c.whitelist === 'object') setWl(JSON.stringify(c.whitelist, null, 2));
      })
      .catch(() => {});
  }, []);

  const flash = (m: string, isErr = false) => {
    setMsg(m);
    setErr(isErr);
    setTimeout(() => setMsg(null), 4000);
  };

  const toggle = async () => {
    const next = !autoBlock;
    setAutoBlock(next);
    try {
      await apiSetAutoBlock(next);
      flash(next ? '위험 시 자동 차단을 켰습니다' : '자동 차단을 껐습니다');
    } catch {
      setAutoBlock(!next);
      flash('설정 저장 실패', true);
    }
  };

  const save = async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(wl);
    } catch {
      flash('화이트리스트 JSON 형식이 올바르지 않습니다', true);
      return;
    }
    try {
      const r = await pushWhitelist(parsed);
      flash(`화이트리스트를 에이전트 ${r.pushed}대에 적용했습니다`);
    } catch {
      flash('화이트리스트 적용 실패', true);
    }
  };

  return (
    <section className="flex flex-col gap-3">
      <h1 className="text-[20px] font-semibold tracking-tight">설정 · 백오피스</h1>

      <div className="rounded-2xl border border-line bg-surface">
        <div className="border-b border-line px-4 py-3">
          <h2 className="text-[14px] font-bold">런타임 추적·차단</h2>
          <p className="mt-0.5 text-[12px] text-fg-3">eBPF 에이전트의 자동 차단 정책과 허용 목록을 관리합니다.</p>
        </div>
        <div className="flex flex-col gap-5 p-4">
          <label className="flex items-center justify-between gap-4">
            <span>
              <b className="text-[13.5px]">위험 시 자동 차단</b>
              <span className="mt-0.5 block text-[12px] text-fg-2">
                위험(HIGH) 외부 접속이 탐지되면 관리자 확인 없이 목적지를 즉시 차단합니다.
              </span>
            </span>
            <button
              role="switch"
              aria-checked={autoBlock}
              onClick={toggle}
              className={cn('relative h-6 w-11 shrink-0 rounded-full transition', autoBlock ? 'bg-accent' : 'bg-line-strong')}
            >
              <span className={cn('absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all', autoBlock ? 'left-[22px]' : 'left-0.5')} />
            </button>
          </label>

          <div>
            <div className="flex items-center justify-between">
              <b className="text-[13.5px]">허용 목록(화이트리스트)</b>
              <button onClick={save} className="rounded-lg bg-accent px-3 py-1.5 text-[12px] font-bold text-white">
                저장 후 에이전트에 적용
              </button>
            </div>
            <p className="mt-0.5 text-[12px] text-fg-2">
              여기 해당하는 프로세스·목적지는 정상으로 보고 경보를 내지 않습니다. 저장하면 연결된 에이전트에 즉시 반영됩니다.
            </p>
            <textarea
              value={wl}
              onChange={(e) => setWl(e.target.value)}
              spellCheck={false}
              className="mt-2 h-72 w-full resize-y rounded-lg border border-line-strong bg-surface-2 p-3 font-mono text-[12px] leading-relaxed"
            />
          </div>

          {msg && (
            <div className={cn('rounded-lg px-3 py-2 text-[12.5px]', err ? 'bg-crit-soft text-crit-ink' : 'bg-good-soft text-good-ink')}>
              {msg}
            </div>
          )}
        </div>
      </div>

      <div className="rounded-2xl border border-line bg-surface p-4 text-[12.5px] text-fg-3">
        알림 · AI 지침 · 검사 규칙 · 배포 검사 · 시스템 탭은 이후 단계에서 구현됩니다.
      </div>
    </section>
  );
}
