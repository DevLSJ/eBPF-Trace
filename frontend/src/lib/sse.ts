// SSE(text/event-stream) 파서 — POST 응답을 fetch 로 읽기 위해(EventSource 는 POST 를 못 한다). 10/20 AI 도우미.
// HTML 표준의 해석 규칙 중 쓰는 것만: 줄 끝 \n · \r\n · \r, 「:」로 시작하는 줄은 주석(ping), data 여러 줄은 \n 으로 잇기,
// 빈 줄에서 이벤트 하나를 내보낸다(data 가 없으면 버림), event 가 없으면 「message」. id · retry 는 쓰지 않는다.
export interface SSEEvent {
  event: string;
  data: string;
}

export class SSEParser {
  private buf = '';
  private event = '';
  private data: string[] = [];

  // 받은 조각 하나 → 이번에 끝난 이벤트들. 줄이 조각 경계에서 잘려도 다음 조각과 이어서 읽는다
  push(chunk: string): SSEEvent[] {
    this.buf += chunk;
    const out: SSEEvent[] = [];
    let start = 0;
    for (let i = 0; i < this.buf.length; i++) {
      const ch = this.buf[i];
      if (ch !== '\n' && ch !== '\r') continue;
      // 조각 끝의 \r 은 다음 조각의 \n 과 짝일 수 있다 — 다음 조각까지 기다린다
      if (ch === '\r' && i === this.buf.length - 1) break;
      this.line(this.buf.slice(start, i), out);
      if (ch === '\r' && this.buf[i + 1] === '\n') i++;
      start = i + 1;
    }
    this.buf = this.buf.slice(start);
    return out;
  }

  // 스트림 끝: 마지막 빈 줄이 없어도 모인 이벤트를 내보낸다
  end(): SSEEvent[] {
    const out: SSEEvent[] = [];
    if (this.buf) this.line(this.buf.replace(/\r$/, ''), out);
    this.buf = '';
    this.line('', out);
    return out;
  }

  private line(l: string, out: SSEEvent[]) {
    if (l === '') {
      if (this.data.length) out.push({ event: this.event || 'message', data: this.data.join('\n') });
      this.event = '';
      this.data = [];
      return;
    }
    if (l.startsWith(':')) return;
    const c = l.indexOf(':');
    const field = c < 0 ? l : l.slice(0, c);
    let value = c < 0 ? '' : l.slice(c + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') this.event = value;
    else if (field === 'data') this.data.push(value);
  }
}

// 응답 본문을 끝까지 읽으며 이벤트마다 on 을 부른다. on 이 true 를 돌려주면 그 자리에서 읽기를 멈춘다(done · error)
export async function readSSE(body: ReadableStream<Uint8Array>, on: (e: SSEEvent) => boolean | void): Promise<void> {
  const reader = body.getReader();
  const dec = new TextDecoder();
  const p = new SSEParser();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      const evs = done ? [...p.push(dec.decode()), ...p.end()] : p.push(dec.decode(value, { stream: true }));
      for (const e of evs) if (on(e)) return;
      if (done) return;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
}
