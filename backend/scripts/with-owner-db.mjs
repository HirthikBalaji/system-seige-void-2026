#!/usr/bin/env node
// Runs a command with DATABASE_URL temporarily replaced by
// MIGRATION_DATABASE_URL, so `prisma migrate` executes DDL as the
// table-owning role instead of the restricted runtime role.
// Usage: node --env-file=.env scripts/with-owner-db.mjs <command> [args...]
import { spawnSync } from 'node:child_process';

const [, , ...cmd] = process.argv;

if (cmd.length === 0) {
  console.error('usage: with-owner-db.mjs <command> [args...]');
  process.exit(1);
}

if (!process.env.MIGRATION_DATABASE_URL) {
  console.error('MIGRATION_DATABASE_URL is not set — load .env first (node --env-file=.env ...)');
  process.exit(1);
}

const env = { ...process.env, DATABASE_URL: process.env.MIGRATION_DATABASE_URL };
const result = spawnSync(cmd[0], cmd.slice(1), {
  stdio: 'inherit',
  env,
  shell: process.platform === 'win32',
});

process.exit(result.status ?? 1);
