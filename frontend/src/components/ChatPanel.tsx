import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { api, ApiError, errorText } from '../lib/api';
import { splitHref } from '../lib/nav';
import { engineFootnote, engineHeader } from '../lib/chatEngine';
import type { ChatEngine, ChatLink } from '../lib/types';
import { CodeWindow } from './CodeWindow';

// 「AI 도우미」 탭 본문 (10/20 W13, 목업 mock/shared/chat.js). POST /api/chat → 서버가 고른 모델(11/09: Claude 기본 · 로컬 Ollama 예비)의 답을 SSE 로 받아 흘려 보인다.
// - 판정 상태(facts.status) · 관련 화면(links)은 모델이 아니라 서버가 붙인 값 — 상태 칩은 모델 문장보다 우선이라고 표시한다
// - 대화는 이 탭(sessionStorage supplyguard.chat)에만 최근 30개. 서버에는 최근 6턴만 문맥으로 보낸다
// - 읽기 전용: 판정 · 정책을 바꾸지 않는다
// 패널이 닫혀도(화면 이동) 이 컴포넌트는 남아 있어 답을 계속 받는다.
const KEY = 'supplyguard.chat';
const KEEP = 30;
const HISTORY = 6;
const SUGGEST = ['판정 대기 요약해 줘', '오늘 가장 많이 걸린 정책은?', '이 화면은 뭘 하는 곳이야?', '최근 공급망 검사 결과 알려 줘'];
const STATUS_TITLE = '서버가 기록에서 확정한 상태입니다. 모델 문장보다 이 값이 우선입니다';

interface Msg {
  role: 'user' | 'assistant';
  text: string;
  links?: ChatLink[];
  status?: string;
  facts?: string[];
  error?: string;
  stopped?: boolean;
  pending?: boolean;
}

// 앱 안 경로만 링크로 쓴다(서버 값이라도 바깥 주소 · 스킴은 받지 않는다)
const inApp = (l: ChatLink) => typeof l?.href === 'string' && l.href.startsWith('/') && !l.href.startsWith('//') && typeof l.label === 'string';

function load(): Msg[] {
  try {
    const v = JSON.parse(sessionStorage.getItem(KEY) ?? '[]') as unknown;
    if (!Array.isArray(v)) return [];
    return v
      .filter((m): m is Msg => !!m && (m.role === 'user' || m.role === 'assistant') && typeof m.text === 'string')
      .map((m) => ({ ...m, pending: false, links: Array.isArray(m.links) ? m.links.filter(inApp) : [] }))
      .slice(-KEEP);
  } catch {
    return [];
  }
}
function save(msgs: Msg[]) {
  try {
    if (msgs.length) sessionStorage.setItem(KEY, JSON.stringify(msgs.slice(-KEEP).map(({ pending: _p, ...m }) => (void _p, m))));
    else sessionStorage.removeItem(KEY);
  } catch {
    /* 저장 차단 — 이 화면에서만 */
  }
}

export function ChatPanel({ active, engine }: { active: boolean; engine?: ChatEngine }) {
  const { pathname, search } = useLocation();
  const [msgs, setMsgs] = useState<Msg[]>(load);
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const ctl = useRef<AbortController | null>(null);
  const gen = useRef(0); // 지우기마다 올린다 — 지운 뒤 늦게 온 조각이 새 대화에 붙지 않게
  const inputRef = useRef<HTMLInputElement>(null);
  // 새로 붙은 줄만 등장 애니메이션(.is-new) — 이 번호부터가 새 줄. 저장돼 있던 줄 · 흘려보내며 다시 그리는 줄은 움직이지 않는다
  const [newFrom, setNewFrom] = useState(() => msgs.length);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!busy) save(msgs);
  }, [msgs, busy]);
  useEffect(() => () => ctl.current?.abort(), []);
  useEffect(() => {
    if (active) inputRef.current?.focus();
  }, [active]);
  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [msgs, active]);

  const thinking = busy && msgs.at(-1)?.pending === true;
  useEffect(() => {
    if (!thinking) return;
    const t0 = Date.now();
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 250);
    return () => clearInterval(t);
  }, [thinking]);

  const ask = useCallback(
    async (raw?: string) => {
      const q = (raw ?? text).trim();
      if (!q || busy) return;
      const g = gen.current;
      // 지금 답하는 마지막 메시지만 고친다
      const patch = (f: (m: Msg) => Msg) => {
        if (g === gen.current) setMsgs((ms) => (ms.length && ms[ms.length - 1].role === 'assistant' ? [...ms.slice(0, -1), f(ms[ms.length - 1])] : ms));
      };
      const history = msgs
        .filter((m) => m.text.trim())
        .slice(-HISTORY)
        .map((m) => ({ role: m.role, text: m.text }));
      const ac = new AbortController();
      ctl.current = ac;
      setNotice(null);
      setText('');
      setElapsed(0);
      setBusy(true);
      setNewFrom(msgs.length);
      setMsgs((ms) => [...ms, { role: 'user', text: q }, { role: 'assistant', text: '', pending: true }]);
      try {
        const r = await api.chat(
          { question: q, page: pathname + search, history },
          {
            token: (t) => patch((m) => ({ ...m, text: m.text + t, pending: false })),
            facts: (f) => patch((m) => ({ ...m, status: f.status || undefined, facts: Array.isArray(f.sentences) ? f.sentences : [] })),
            links: (l) => patch((m) => ({ ...m, links: l.filter(inApp) })),
          },
          ac.signal,
        );
        patch((m) => ({ ...m, pending: false, error: r.error ?? undefined }));
      } catch (e) {
        if (ac.signal.aborted) patch((m) => ({ ...m, pending: false, stopped: true }));
        else if (e instanceof ApiError && e.json && (e.status === 429 || e.status === 400)) {
          // 시작 전 거절(생성 중 · 빈 질문 · 500자 초과): 대화에 남기지 않고 입력을 되돌린다
          if (g === gen.current) setMsgs((ms) => ms.slice(0, -2));
          setText(q);
          setNotice(e.message);
        } else patch((m) => ({ ...m, pending: false, error: errorText(e) }));
      } finally {
        if (ctl.current === ac) ctl.current = null;
        setBusy(false);
        inputRef.current?.focus();
      }
    },
    [text, busy, msgs, pathname, search],
  );

  const clear = () => {
    gen.current++;
    ctl.current?.abort();
    setMsgs([]);
    setNewFrom(0);
    setNotice(null);
  };

  return (
    <section data-part="chat" aria-label="AI 도우미" className="flex min-h-0 flex-1 flex-col">
      <header className="flex shrink-0 items-center gap-2 border-b border-slate-100 px-3 py-1.5">
        <span data-part="chat-engine" data-provider={engine?.provider ?? 'ollama'} className="text-xs text-slate-500">
          {engineHeader(engine)}
        </span>
        <button type="button" aria-label="대화 지우기" onClick={clear} className="ml-auto rounded px-2 py-0.5 text-xs text-slate-500 hover:bg-slate-100 hover:text-slate-800">
          지우기
        </button>
      </header>
      {/* 11/04f 채팅 화면 ⓑ(R1 11/04) — 말풍선 대신 한 턴 한 줄 띠(사용자 --surface-2 · 도우미 --surface), 대화 칸만 스크롤 */}
      <div ref={listRef} data-part="chat-list" aria-live="polite" className="chat-list min-h-0 flex-1 overflow-x-hidden overflow-y-auto">
        {msgs.length === 0 ? (
          <div data-part="chat-greeting" className="chat-msg assistant">
            <div className="bubble">무엇이든 물어보세요. 판정 대기 · 위반 기록 · 정책 · 공급망 검사 결과를 찾아 답합니다.</div>
          </div>
        ) : (
          msgs.map((m, i) => <Message key={i} m={m} elapsed={elapsed} fresh={i >= newFrom} />)
        )}
      </div>
      {msgs.length === 0 && (
        <div data-part="chat-sugg" className="flex shrink-0 flex-wrap gap-1.5 px-3 pt-2.5 pb-2">
          {SUGGEST.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => void ask(q)}
              className="rounded-full border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-xs text-indigo-700 hover:bg-indigo-100"
            >
              {q}
            </button>
          ))}
        </div>
      )}
      {notice && (
        <p data-part="chat-notice" role="status" className="mx-3 mb-1.5 shrink-0 rounded bg-amber-50 px-2 py-1 text-xs text-amber-800">
          {notice}
        </p>
      )}
      {/* 11/04f 채팅 화면 ⓒ — 한 줄 입력칸(반경 7 · 말줄임 · Enter 로 보내기, Shift+Enter 줄바꿈은 없어짐 — 사용자 승인) + 30×30 보내기(빈 입력이면 잠김 · 흐림).
          답을 기다리는 동안 같은 자리가 「멈추기」(React 기존 기능 유지) */}
      <div className="chat-form shrink-0 border-t border-slate-100">
        <input
          ref={inputRef}
          type="text"
          maxLength={500}
          aria-label="질문"
          placeholder="예: pkg-reqeusts 는 왜 격리됐어?"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.nativeEvent.isComposing) {
              e.preventDefault();
              void ask();
            }
          }}
          className="chat-input"
        />
        {busy ? (
          <button type="button" onClick={() => ctl.current?.abort()} aria-label="멈추기" title="멈추기" className="chat-send chat-stop">
            ■
          </button>
        ) : (
          <button type="button" onClick={() => void ask()} aria-label="보내기" title="보내기 (Enter)" disabled={!text.trim()} className="chat-send">
            ➤
          </button>
        )}
      </div>
      <p className="shrink-0 px-3 pt-1 pb-2 text-[11px] text-slate-400">{engineFootnote(engine)}</p>
    </section>
  );
}

// 답 속 코드 블록(```종류 [파일명] … ```) → 코드 창. 흘려보내는 중 안 닫힌 블록도 그때까지의 코드를 창에 둔다(11/04f)
// 코드 밖 글자의 **굵게** 는 굵은 글자로(11/09 — Claude 답이 가끔 쓴다). 그 밖의 마크다운은 글자 그대로
const FENCE = /```([^\n`]*)\n([\s\S]*?)(?:\n?```|$)/g;
const BOLD = /\*\*([^*\n]+?)\*\*/g;
function inline(text: string, key: number): ReactNode[] {
  const out: ReactNode[] = [];
  let at = 0;
  BOLD.lastIndex = 0;
  for (let m = BOLD.exec(text); m; m = BOLD.exec(text)) {
    if (m.index > at) out.push(text.slice(at, m.index));
    out.push(<strong key={`${key}-${m.index}`}>{m[1]}</strong>);
    at = BOLD.lastIndex;
  }
  if (at < text.length) out.push(text.slice(at));
  return out;
}
function rich(text: string) {
  if (!text.includes('```')) return text.includes('**') ? inline(text, 0) : text;
  const out: ReactNode[] = [];
  let at = 0;
  FENCE.lastIndex = 0;
  for (let m = FENCE.exec(text); m; m = FENCE.exec(text)) {
    if (m.index > at) out.push(...inline(text.slice(at, m.index).replace(/\n$/, ''), at));
    const [lang, name] = m[1].trim().split(/\s+/);
    out.push(
      <CodeWindow key={m.index} name={name || null} lang={lang || null}>
        {m[2]}
      </CodeWindow>,
    );
    at = FENCE.lastIndex;
    if (!m[0].length) break;
  }
  if (at < text.length) out.push(...inline(text.slice(at).replace(/^\n/, ''), at));
  return out;
}

function Message({ m, elapsed, fresh }: { m: Msg; elapsed: number; fresh: boolean }) {
  if (m.role === 'user')
    return (
      <div data-part="chat-msg" data-role="user" className={`chat-msg user${fresh ? ' is-new' : ''}`}>
        <div data-part="chat-bubble" className="bubble">
          {m.text}
        </div>
      </div>
    );
  const facts = m.error && m.facts?.length ? m.facts : null;
  return (
    <div data-part="chat-msg" data-role="assistant" className={`chat-msg assistant${fresh ? ' is-new' : ''}`}>
      {m.status && (
        <div data-part="chat-status" title={STATUS_TITLE} className="inline-flex w-fit items-center gap-1.5 rounded-full border border-indigo-200 bg-white px-2 py-0.5 text-xs text-slate-800">
          <span className="rounded bg-indigo-100 px-1 text-[10px] font-semibold text-indigo-700">서버 확정</span>
          {m.status}
        </div>
      )}
      {(m.text || m.pending) && (
        <div data-part="chat-bubble" className="bubble">
          {rich(m.text) || (
            <span data-part="chat-thinking" className="text-slate-500">
              생각하는 중… {elapsed}초
            </span>
          )}
        </div>
      )}
      {m.stopped && (
        <p data-part="chat-stopped" className="mt-1 text-xs text-slate-500">
          멈췄습니다
        </p>
      )}
      {m.error && (
        <p data-part="chat-error" className="mt-1 text-xs font-medium text-red-700">
          {m.error}
        </p>
      )}
      {facts && (
        <div data-part="chat-facts" className="mt-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-2 text-xs text-slate-700">
          <b className="mb-1 block text-slate-900">모델 없이 찾은 사실</b>
          <ul className="list-disc space-y-0.5 pl-4">
            {facts.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
        </div>
      )}
      {!!m.links?.length && (
        <div data-part="chat-links" className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="text-[11px] text-slate-400">관련 화면</span>
          {m.links.map((l, i) => (
            <Link key={i} {...splitHref(l.href)} className="text-xs text-indigo-600 hover:underline">
              {l.label} →
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
