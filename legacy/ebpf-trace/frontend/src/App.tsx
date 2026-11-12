import { lazy, Suspense, useEffect, useState } from 'react';
import Workspace from './Workspace';

const SupplyDemo = lazy(() => import('./demo/SupplyDemo'));
const SUPPLY = '#supply';
export default function App() {
  const [hash, setHash] = useState(location.hash || '#overview');
  useEffect(() => { const update = () => setHash(location.hash || '#overview'); addEventListener('hashchange', update); return () => removeEventListener('hashchange', update); }, []);
  const supply = hash === SUPPLY || hash.startsWith(SUPPLY + '/');
  return supply ? <Suspense fallback={<div role="status" style={{ padding: 32 }}>공급망 안내 시연을 불러오는 중…</div>}><SupplyDemo hash={hash}/></Suspense> : <Workspace/>;
}
