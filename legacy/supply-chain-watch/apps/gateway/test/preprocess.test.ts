import { describe, expect, it } from 'vitest';
import { isExcluded, isSensitive, preprocessDiff, type InputFile } from '../src/collector/preprocess.js';

describe('preprocess', () => {
  it('락파일·번들·바이너리 제외', () => {
    expect(isExcluded('package-lock.json')).toBe(true);
    expect(isExcluded('dist/bundle.js')).toBe(true);
    expect(isExcluded('a/b.min.js')).toBe(true);
    expect(isExcluded('logo.png')).toBe(true);
    expect(isExcluded('src/index.js')).toBe(false);
  });

  it('민감 파일 판별', () => {
    expect(isSensitive('package.json')).toBe(true);
    expect(isSensitive('.github/workflows/ci.yml')).toBe(true);
    expect(isSensitive('setup.py')).toBe(true);
    expect(isSensitive('.env.production')).toBe(true);
    expect(isSensitive('src/util/math.js')).toBe(false);
  });

  it('제외 파일은 diff에서 빠지고 excludedFiles에 기록', () => {
    const files: InputFile[] = [
      { filename: 'src/a.js', status: 'modified', additions: 1, deletions: 0, patch: '+a' },
      { filename: 'pnpm-lock.yaml', status: 'modified', additions: 999, deletions: 0, patch: '+lock' },
    ];
    const r = preprocessDiff(files);
    expect(r.excludedFiles).toContain('pnpm-lock.yaml');
    expect(r.diffText).toContain('src/a.js');
    expect(r.diffText).not.toContain('+lock');
  });

  it('민감 파일을 앞으로 정렬하고 sensitiveFiles에 기록', () => {
    const files: InputFile[] = [
      { filename: 'src/z.js', status: 'modified', additions: 1, deletions: 0, patch: '+z' },
      { filename: 'package.json', status: 'modified', additions: 1, deletions: 0, patch: '+p' },
    ];
    const r = preprocessDiff(files);
    expect(r.sensitiveFiles).toEqual(['package.json']);
    expect(r.diffText.indexOf('package.json')).toBeLessThan(r.diffText.indexOf('src/z.js'));
  });

  it('긴 라인은 OBFUSCATION_SUSPECT로 절삭', () => {
    const files: InputFile[] = [{ filename: 'src/a.js', status: 'added', additions: 1, deletions: 0, patch: '+' + 'A'.repeat(3000) }];
    const r = preprocessDiff(files);
    expect(r.diffText).toContain('OBFUSCATION_SUSPECT');
    expect(r.diffText).not.toContain('A'.repeat(3000));
  });

  it('전체 120KB 초과 시 truncated', () => {
    const big = '+short line of code here;\n'.repeat(850); // ~19KB, 짧은 라인 다수
    const files: InputFile[] = Array.from({ length: 10 }, (_, i) => ({
      filename: `src/f${i}.js`, status: 'added', additions: 1, deletions: 0, patch: big,
    }));
    const r = preprocessDiff(files);
    expect(r.truncated).toBe(true);
    expect(r.sizeBytes).toBeLessThanOrEqual(120 * 1024 + 1024);
  });

  it('diffHash는 내용 결정적', () => {
    const files: InputFile[] = [{ filename: 'a.js', status: 'added', additions: 1, deletions: 0, patch: '+a' }];
    expect(preprocessDiff(files).diffHash).toBe(preprocessDiff(files).diffHash);
    expect(preprocessDiff(files).diffHash).toHaveLength(64);
  });
});
