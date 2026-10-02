import { env } from '../env.js';
import { AnalysisQueue } from './queue.js';
import { processCommit } from './worker.js';

const CONCURRENCY = Number(process.env.AGENT_CONCURRENCY ?? 6);
void env; // env 로딩 보장

export const analysisQueue = new AnalysisQueue(CONCURRENCY, (commitId, onStep) =>
  processCommit(commitId, onStep),
);
