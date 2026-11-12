// 새 커밋 1건 처리: dedup → 메타·diff 적재 → 전처리 → (feature 5: 분석 큐).
import { github } from '../github/client.js';
import { logger } from '../logger.js';
import type { RepoRow } from '../repo/repos.js';
import { fromCommitDetail, insertCommit, updateCommitDiff } from '../repo/commits.js';
import { broadcast } from '../ws.js';
import { seenBefore } from './dedup.js';
import { preprocessDiff, type InputFile } from './preprocess.js';
import { analysisQueue } from '../analysis/index.js';

export async function handleNewCommit(
  repo: RepoRow,
  sha: string,
  branch: string,
  source: string,
): Promise<void> {
  // 1차 dedup (Redis NX). 이미 본 커밋이면 종료.
  if (await seenBefore(repo.id, sha)) return;
  try {
    const detail = await github.getCommitDetail(repo.owner, repo.name, sha);
    if (!detail.data) return;

    // DB 삽입 (UNIQUE = 최종 방어선). 이미 있으면 재처리 안 함.
    const meta = fromCommitDetail(repo.id, branch, source, detail.data);
    const inserted = await insertCommit(meta);
    if (!inserted?.inserted) return;

    // Diff 전처리 (제외·절삭·민감 파일)
    const files: InputFile[] = (detail.data.files ?? []).map((f) => ({
      filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions, patch: f.patch,
    }));
    const pre = preprocessDiff(files);
    await updateCommitDiff(inserted.id, {
      diffText: pre.diffText, diffHash: pre.diffHash, sizeBytes: pre.sizeBytes, truncated: pre.truncated,
      filesJson: pre.files, filesChanged: pre.files.length,
      additions: detail.data.stats?.additions ?? 0, deletions: detail.data.stats?.deletions ?? 0,
    });

    broadcast('commit.received', {
      id: inserted.id, repoId: repo.id, repoFullName: repo.full_name,
      sha, shortSha: sha.slice(0, 7), branch, source, status: 'QUEUED',
      // 피드가 재조회 없이 바로 그릴 수 있도록 메타 동봉 (이메일은 제외)
      message: meta.message, authorLogin: meta.authorLogin, authorName: meta.authorName,
      committedAt: meta.committedAt, htmlUrl: meta.htmlUrl,
      filesChanged: pre.files.length, additions: meta.additions, deletions: meta.deletions,
      sensitiveFiles: pre.sensitiveFiles, truncated: pre.truncated,
    });
    await analysisQueue.enqueue({ commitId: inserted.id, repoFullName: repo.full_name, sha });
    logger.info(
      { repo: repo.full_name, sha: sha.slice(0, 7), source, files: pre.files.length, sensitive: pre.sensitiveFiles.length, bytes: pre.sizeBytes },
      'new commit processed + enqueued',
    );
  } catch (err) {
    logger.warn({ repo: repo.full_name, sha: sha.slice(0, 7), err: (err as Error).message }, 'handleNewCommit failed');
  }
}
