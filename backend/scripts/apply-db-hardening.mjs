#!/usr/bin/env node
// Applies prisma/hardening.sql (RLS policies, append-only trigger, role
// grants) via `docker compose exec` against the running postgres container,
// as the owner role. Run after every `migrate:dev` / `migrate:deploy`.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dir = path.dirname(fileURLToPath(import.meta.url));
const sqlPath = path.join(dir, '..', 'prisma', 'hardening.sql');
const sql = readFileSync(sqlPath, 'utf8');

const result = spawnSync(
  'docker',
  ['compose', 'exec', '-T', 'postgres', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'platform_owner', '-d', 'secrets_platform'],
  { input: sql, stdio: ['pipe', 'inherit', 'inherit'], shell: process.platform === 'win32' },
);

process.exit(result.status ?? 1);
