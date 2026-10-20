import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// eBPF-project와 같은 구성: dev 서버 127.0.0.1:5173 → 백엔드 127.0.0.1:8000
// 로컬 8000이 사용 중이면 API_TARGET=http://127.0.0.1:18000 처럼 바꿔 띄운다.
const api = process.env.API_TARGET || 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rollupOptions: {
      output: { manualChunks: { flow: ['@xyflow/react'], yaml: ['yaml'] } },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': api,
      '/health': api,
      '/ws': { target: api.replace(/^http/, 'ws'), ws: true },
    },
  },
});
