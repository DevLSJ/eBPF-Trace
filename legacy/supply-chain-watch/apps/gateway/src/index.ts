import { env } from './env.js';

// Phase 1 feature 3에서 Express + ws + /health 구현.
console.log(`[gateway] env loaded. port=${env.GATEWAY_PORT} engine=${env.ENGINE_URL}`);
