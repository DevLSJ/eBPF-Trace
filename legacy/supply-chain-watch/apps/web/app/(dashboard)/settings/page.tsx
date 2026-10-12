'use client';
import { useEffect, useState } from 'react';
import {
  DEFAULT_WHITELIST,
  getRuntimeConfig,
  pushWhitelist,
  setAutoBlock as apiSetAutoBlock,
} from '@/lib/runtime';
import { cn } from '@/lib/utils';
import { WhitelistEditor } from '@/components/whitelist-editor';
import { validateWhitelist, type Whitelist } from '@/lib/whitelist';

export default function SettingsPage() {
  const [autoBlock, setAutoBlock] = useState(false);
  const [wl, setWl] = useState<Whitelist>(DEFAULT_WHITELIST);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    void getRuntimeConfig()
      .then((c) => {
        setAutoBlock(c.autoBlock);
        const v = c.whitelist ? validateWhitelist(c.whitelist).value : undefined;
        if (v) setWl(v);
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

  const save = async (next: Whitelist) => {
    try {
      const r = await pushWhitelist(next);
      setWl(next);
      flash(r.pushed > 0 ? `검사 기준을 에이전트 ${r.pushed}대에 적용했습니다` : '저장했지만 연결된 에이전트가 없어 아직 적용되지 않았습니다', r.pushed === 0);
    } catch (e) {
      flash(`적용하지 못했습니다: ${(e as Error).message}`, true);
      throw e;
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
                위험 단계의 외부 접속이 탐지되면 관리자 확인 없이 그 주소를 즉시 차단합니다.
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

          <WhitelistEditor value={wl} defaults={DEFAULT_WHITELIST} onSave={save} />

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
