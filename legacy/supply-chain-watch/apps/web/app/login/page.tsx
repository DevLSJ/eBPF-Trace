'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { GATEWAY_URL } from '@/lib/utils';

export default function LoginPage() {
  const router = useRouter();
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr('');
    try {
      const res = await fetch(`${GATEWAY_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ password: pw }),
      });
      if (res.ok) {
        router.replace('/');
        router.refresh();
      } else {
        const d = await res.json().catch(() => null);
        setErr(d?.error?.message ?? '로그인에 실패했습니다');
      }
    } catch {
      setErr('gateway에 연결할 수 없습니다 (localhost:4000)');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid h-screen place-items-center p-4">
      <form
        onSubmit={submit}
        className="flex w-[360px] max-w-full flex-col gap-4 rounded-2xl border border-line bg-surface p-7 shadow-card"
      >
        <div className="flex items-center gap-2.5">
          <div className="grid h-9 w-9 place-items-center rounded-[10px] bg-fg text-[15px] font-bold text-surface">
            SW
          </div>
          <div>
            <b className="block text-[14px]">Supply Chain Watch</b>
            <small className="text-[11.5px] text-fg-3">관리자 로그인</small>
          </div>
        </div>
        <label className="flex flex-col gap-1.5 text-[12px] font-medium text-fg-2">
          관리자 비밀번호
          <input
            type="password"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            autoFocus
            className="rounded-lg border border-line-strong bg-surface px-3 py-2 text-[13.5px] outline-none focus:border-accent focus:ring-2 focus:ring-accent-soft"
            placeholder="••••••••"
          />
        </label>
        {err && <div className="rounded-lg bg-crit-soft px-3 py-2 text-[12.5px] text-crit">{err}</div>}
        <button
          type="submit"
          disabled={busy}
          className="rounded-lg bg-accent px-3 py-2.5 text-[13px] font-semibold text-white disabled:opacity-50"
        >
          {busy ? '확인 중…' : '로그인'}
        </button>
      </form>
    </div>
  );
}
