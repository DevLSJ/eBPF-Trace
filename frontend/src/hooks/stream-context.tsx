import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api } from '../lib/api';
import type { Info } from '../lib/types';
import { useEventStream, type EventStream } from './useEventStream';

interface Ctx extends EventStream {
  info: Info | null;
}

const StreamContext = createContext<Ctx | null>(null);

// 화면을 옮겨 다녀도 연결·피드·토폴로지가 유지되도록 셸 바깥에서 한 번만 구독한다
export function StreamProvider({ children }: { children: ReactNode }) {
  const stream = useEventStream();
  const [info, setInfo] = useState<Info | null>(null);
  useEffect(() => {
    api.info().then(setInfo).catch(() => {});
  }, [stream.connected]);
  return <StreamContext.Provider value={{ ...stream, info }}>{children}</StreamContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useStream(): Ctx {
  const c = useContext(StreamContext);
  if (!c) throw new Error('useStream must be used inside StreamProvider');
  return c;
}
