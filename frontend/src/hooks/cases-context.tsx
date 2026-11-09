import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, isUnsupported } from '../lib/api';
import { dest } from '../lib/nav';
import { isInstallContainer } from '../lib/topology';
import { levelOf, type Case } from '../lib/types';
import { useStream } from './stream-context';
import { useToast } from './toast-context';

interface Ctx {
  cases: Case[] | null; // null = 아직 못 받음
  error: unknown;
  unsupported: boolean;
  reload: () => void;
  upsert: (c: Case) => void;
}

const CasesContext = createContext<Ctx | null>(null);

// 건(판정할 묶음) 목록을 앱 전체에서 하나로 들고, WS {type:"case"} 로 바로 갱신한다.
// 같은 구독에서 격리 토스트도 띄운다(같은 컨테이너끼리 묶음).
export function CasesProvider({ children }: { children: ReactNode }) {
  const { subscribe, connected } = useStream();
  const toast = useToast();
  const [cases, setCases] = useState<Case[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    api.cases().then(
      (cs) => {
        if (!live) return;
        setCases(cs);
        setError(null);
      },
      (e: unknown) => live && setError(e),
    );
    return () => {
      live = false;
    };
  }, [nonce, connected]);

  const upsert = useCallback((c: Case) => {
    setCases((cur) => {
      const xs = cur ?? [];
      const i = xs.findIndex((x) => x.id === c.id);
      if (i < 0) return [c, ...xs];
      const next = [...xs];
      next[i] = c;
      return next;
    });
  }, []);

  useEffect(
    () =>
      subscribe((m) => {
        if (m.type === 'case') upsert(m.data);
        else if (m.type === 'verdict' && levelOf(m.data) === 'killed') {
          const name = m.data.event.containerName;
          const install = isInstallContainer(name);
          const why = m.data.reason ?? m.data.ruleId ?? '';
          toast(`${install ? '설치 검사 격리' : `${name} 격리됨`}${why ? `(${why})` : ''}`, {
            key: `kill:${name}`,
            tone: 'danger',
            action: install ? { label: '설치 검사', to: '/installs' } : { label: '이벤트 보기', ...dest('/events', { container: name }) },
          });
        }
      }),
    [subscribe, upsert, toast],
  );

  const value = useMemo(
    () => ({ cases, error, unsupported: isUnsupported(error), reload: () => setNonce((n) => n + 1), upsert }),
    [cases, error, upsert],
  );
  return <CasesContext.Provider value={value}>{children}</CasesContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useCases(): Ctx {
  const c = useContext(CasesContext);
  if (!c) throw new Error('useCases must be used inside CasesProvider');
  return c;
}
