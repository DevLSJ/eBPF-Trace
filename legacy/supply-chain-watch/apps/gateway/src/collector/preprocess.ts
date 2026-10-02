// Diff 전처리 (docs/02 §6, docs/03 §2). 순수 함수 — 제외·절삭·민감 파일 판별.
import { createHash } from 'node:crypto';

export interface InputFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  patch?: string;
}

export interface PreprocessResult {
  diffText: string;
  diffHash: string;
  sizeBytes: number;
  truncated: boolean;
  excludedFiles: string[];
  sensitiveFiles: string[];
  files: Array<{ filename: string; status: string; additions: number; deletions: number }>;
}

const TOTAL_CAP = 120 * 1024;
const FILE_CAP = 20 * 1024;
const LONG_LINE = 2000;

const EXCLUDE_EXACT = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'uv.lock', 'Cargo.lock', 'composer.lock',
]);
const EXCLUDE_RE =
  /(^|\/)(node_modules|dist|build|vendor)\/|\.(min\.js|map|png|jpe?g|gif|webp|ico|woff2?|ttf|eot|pdf|zip|gz|lock)$/i;

const SENSITIVE_RE =
  /(^|\/)(package\.json|setup\.py|setup\.cfg|pyproject\.toml|\.npmrc|\.pypirc|Dockerfile[^/]*|Makefile|index\.js|main\.js|__init__\.py)$|^\.github\/workflows\/|(^|\/)bin\/|\.env|\.pem$|\.key$|credentials/i;

export function isExcluded(filename: string): boolean {
  const base = filename.split('/').pop() ?? filename;
  return EXCLUDE_EXACT.has(base) || EXCLUDE_RE.test(filename);
}

export function isSensitive(filename: string): boolean {
  return SENSITIVE_RE.test(filename);
}

// 긴 라인(난독화 의심)은 앞 500자만 유지
function clampLongLines(patch: string): string {
  return patch
    .split('\n')
    .map((l) => (l.length > LONG_LINE ? `${l.slice(0, 500)} …[OBFUSCATION_SUSPECT ${l.length}자]` : l))
    .join('\n');
}

export function preprocessDiff(files: InputFile[]): PreprocessResult {
  const excludedFiles: string[] = [];
  const sensitiveFiles: string[] = [];
  const kept: Array<{ f: InputFile; sensitive: boolean }> = [];

  for (const f of files) {
    if (isExcluded(f.filename)) {
      excludedFiles.push(f.filename);
      continue;
    }
    const sensitive = isSensitive(f.filename);
    if (sensitive) sensitiveFiles.push(f.filename);
    kept.push({ f, sensitive });
  }

  // 민감 파일 우선 보존
  kept.sort((a, b) => Number(b.sensitive) - Number(a.sensitive));

  let total = 0;
  let truncated = false;
  const parts: string[] = [];
  const outFiles: PreprocessResult['files'] = [];

  for (const { f } of kept) {
    outFiles.push({ filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions });
    if (!f.patch) continue;
    let patch = clampLongLines(f.patch);
    if (patch.length > FILE_CAP) {
      patch = `${patch.slice(0, FILE_CAP)}\n…[파일 절삭]`;
      truncated = true;
    }
    const header = `diff --- ${f.filename} (${f.status}, +${f.additions} -${f.deletions})\n`;
    const block = header + patch + '\n';
    if (total + block.length > TOTAL_CAP) {
      truncated = true;
      break;
    }
    parts.push(block);
    total += block.length;
  }

  const diffText = parts.join('');
  return {
    diffText,
    diffHash: createHash('sha256').update(diffText).digest('hex'),
    sizeBytes: Buffer.byteLength(diffText, 'utf8'),
    truncated,
    excludedFiles,
    sensitiveFiles,
    files: outFiles,
  };
}
