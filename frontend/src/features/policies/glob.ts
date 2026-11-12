import type { IntegrationContainer } from '../../lib/types';

// 정책 적용 컨테이너 패턴 — 백엔드 rules/engine.go appliesTo 와 같은 규칙(Go path.Match):
//   *  「/」를 뺀 아무 글자들 · ?  「/」를 뺀 한 글자 · [..] 글자 묶음(^ 부정 · a-z 범위) · \ 다음 글자 그대로
//   이름 또는 이미지 중 하나라도 맞으면 적용. 틀린 패턴(닫히지 않은 [ 등)은 아무것도 맞지 않는다(Go 는 ErrBadPattern → false)
const cache = new Map<string, RegExp | null>();
const esc = (c: string) => c.replace(/[\\^$.*+?()[\]{}|/-]/g, '\\$&');

function compile(p: string): RegExp | null {
  let out = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '*') out += '[^/]*';
    else if (c === '?') out += '[^/]';
    else if (c === '\\') {
      if (i + 1 >= p.length) return null;
      out += esc(p[++i]);
    } else if (c === '[') {
      let j = i + 1;
      let cls = '';
      if (p[j] === '^') {
        cls += '^';
        j++;
      }
      const start = j;
      for (; j < p.length && p[j] !== ']'; j++) {
        if (p[j] === '\\') {
          if (j + 1 >= p.length) return null;
          cls += esc(p[++j]);
        } else if (p[j] === '-' && j > start && j + 1 < p.length && p[j + 1] !== ']') cls += '-';
        else cls += esc(p[j]);
      }
      if (j >= p.length || j === start) return null;
      out += `[${cls}]`;
      i = j;
    } else out += esc(c);
  }
  return new RegExp(`^${out}$`);
}

export function globMatch(pattern: string, s: string): boolean {
  if (!cache.has(pattern)) cache.set(pattern, compile(pattern));
  const re = cache.get(pattern);
  return !!re && re.test(s);
}

export const containerMatches = (pattern: string, c: Pick<IntegrationContainer, 'name' | 'image'>) => globMatch(pattern, c.name) || globMatch(pattern, c.image);
