import { useCallback, useState } from 'react';
import type { DemoScenario } from '../../lib/types';

// 시나리오 묶음(11/09 — 사용자 11/06 결정 「묶음 접기」). 묶음 순서 · 안의 순서는 백엔드 DEMO_SCENARIOS 순서 그대로(이어 붙이면 8개 원래 순서)
export type GroupId = 'attack' | 'network' | 'control';
export const GROUPS: { id: GroupId; name: string; keys: DemoScenario[] }[] = [
  { id: 'attack', name: '공격 재현', keys: ['all', 'shell', 'revshell'] },
  { id: 'network', name: '네트워크 · DNS', keys: ['direct-ip', 'domain', 'dns-exfil'] },
  { id: 'control', name: '대조군 · 연쇄', keys: ['benign', 'chain'] },
];

// 접힌 묶음 — 이 브라우저에만(localStorage). 읽기 · 쓰기가 막히거나 값이 깨져 있으면 기본(모두 펼침)
export const FOLD_KEY = 'supplyguard.demo.folded';
const IDS = new Set<string>(GROUPS.map((g) => g.id));

function load(): GroupId[] {
  try {
    const raw = window.localStorage.getItem(FOLD_KEY);
    if (!raw) return [];
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? (v.filter((x) => typeof x === 'string' && IDS.has(x)) as GroupId[]) : [];
  } catch {
    return [];
  }
}
function save(v: GroupId[]) {
  try {
    window.localStorage.setItem(FOLD_KEY, JSON.stringify(v));
  } catch {
    /* 저장 못 해도 화면은 그대로 */
  }
}

export function useFolds() {
  const [folded, setFolded] = useState<GroupId[]>(load);
  const toggle = useCallback((id: GroupId) => {
    setFolded((cur) => {
      const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
      save(next);
      return next;
    });
  }, []);
  return { folded, toggle };
}
