// 단순 SQL 마이그레이션 러너 (docs/04 §3). infra/sql/*.sql을 번호 순으로 1회 적용.
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';
import { env } from '../env.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SQL_DIR = resolve(__dirname, '../../../../infra/sql');

async function main(): Promise<void> {
  const pool = new Pool({ connectionString: env.DATABASE_URL });
  try {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS schema_migrations (
         id TEXT PRIMARY KEY,
         applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
       )`,
    );
    const files = (await readdir(SQL_DIR)).filter((f) => f.endsWith('.sql')).sort();
    const applied = new Set(
      (await pool.query<{ id: string }>('SELECT id FROM schema_migrations')).rows.map((r) => r.id),
    );
    let count = 0;
    for (const file of files) {
      if (applied.has(file)) {
        console.log(`[migrate] skip ${file} (applied)`);
        continue;
      }
      const sql = await readFile(join(SQL_DIR, file), 'utf8');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (id) VALUES ($1)', [file]);
        await client.query('COMMIT');
        console.log(`[migrate] applied ${file}`);
        count++;
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`migration ${file} failed: ${(err as Error).message}`);
      } finally {
        client.release();
      }
    }
    console.log(`[migrate] done. ${count} new migration(s).`);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
