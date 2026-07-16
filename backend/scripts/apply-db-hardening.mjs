#!/usr/bin/env node
// Applies prisma/hardening.sql (RLS policies, append-only trigger, role
// grants) via `docker compose exec` against the running postgres container,
// or via local psql binary if docker compose is not available.
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dir = path.dirname(fileURLToPath(import.meta.url));
const sqlPath = path.join(dir, '..', 'prisma', 'hardening.sql');
const sql = readFileSync(sqlPath, 'utf8');

// Try docker first
let result = spawnSync(
  'docker',
  ['compose', 'exec', '-T', 'postgres', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'platform_owner', '-d', 'secrets_platform'],
  { input: sql, stdio: ['pipe', 'ignore', 'ignore'], shell: process.platform === 'win32' },
);

if (result.status !== 0) {
  console.log('[*] Docker compose exec not available, running local psql client...');
  const localPsql = path.join(dir, '..', 'pgsql', 'bin', 'psql.exe');
  let connectionUrl = process.env.MIGRATION_DATABASE_URL || 'postgresql://platform_owner:postgresownerpass123!@127.0.0.1:5433/secrets_platform';
  connectionUrl = connectionUrl.split('?')[0];
  
  if (existsSync(localPsql)) {
    result = spawnSync(
      localPsql,
      ['-d', connectionUrl, '-v', 'ON_ERROR_STOP=1'],
      { input: sql, stdio: ['pipe', 'inherit', 'inherit'], shell: process.platform === 'win32' }
    );
  } else {
    // Try system psql if not in local directory
    result = spawnSync(
      'psql',
      ['-d', connectionUrl, '-v', 'ON_ERROR_STOP=1'],
      { input: sql, stdio: ['pipe', 'inherit', 'inherit'], shell: process.platform === 'win32' }
    );
  }
} else {
  // Re-run with inherit stdio for proper logging if docker compose worked
  spawnSync(
    'docker',
    ['compose', 'exec', '-T', 'postgres', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'platform_owner', '-d', 'secrets_platform'],
    { input: sql, stdio: ['pipe', 'inherit', 'inherit'], shell: process.platform === 'win32' },
  );
}

process.exit(result.status ?? 1);
