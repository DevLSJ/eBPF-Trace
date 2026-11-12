import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
// 토큰·셸 CSS를 먼저 읽고, 화면별 CSS(App 안에서 import)는 그 뒤에, 공통 UI 레이어(ui.css)는 Workspace에서 마지막으로 읽는다.
import './styles.css';
import './benchmark.css';
import App from './App';
createRoot(document.getElementById('root')!).render(<StrictMode><App/></StrictMode>);
