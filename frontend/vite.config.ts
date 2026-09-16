import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: { rollupOptions: { output: { manualChunks: { charts: ['recharts'] } } } },
  server: { proxy: {
    '/api': process.env.E2E_API_TARGET || 'http://127.0.0.1:8000',
    '/health': process.env.E2E_API_TARGET || 'http://127.0.0.1:8000',
    '/ws': { target: process.env.E2E_API_TARGET || 'ws://127.0.0.1:8000', ws: true },
  } },
});
