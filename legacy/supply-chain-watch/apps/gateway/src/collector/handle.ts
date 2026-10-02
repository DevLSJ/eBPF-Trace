// 새 커밋 1건 처리 진입점. feature 4(dedup·diff)·5(큐)에서 확장. 지금은 메타 적재 + 통지.
import { github } from '../github/client.js';
import { logger } from '../logger.js';
import type { RepoRow } from '../repo/repos.js';
import { fromCommitDetail, insertCommit } from '../repo/commits.js';
import { broadcast } from '../ws.js';

export async function handleNewCommit(
  repo: RepoRow,
  sha: string,
  branch: string,
  source: string,
): Promise<void> {
  try {
    const detail = await github.getCommitDetail(repo.owner, repo.name, sha);
    if (!detail.data) return;
    const inserted = await insertCommit(fromCommitDetail(repo.id, branch, source, detail.data));
    if (inserted?.inserted) {
      broadcast('commit.received', {
        id: inserted.id, repoId: repo.id, repoFullName: repo.full_name,
        sha, shortSha: sha.slice(0, 7), branch, source, status: 'QUEUED',
      });
      logger.info({ repo: repo.full_name, sha: sha.slice(0, 7), source }, 'new commit');
    }
  } catch (err) {
    logger.warn({ repo: repo.full_name, sha: sha.slice(0, 7), err: (err as Error).message }, 'handleNewCommit failed');
  }
}
