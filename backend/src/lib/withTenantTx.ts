import { Prisma } from '@prisma/client';
import { prisma } from './prisma';

/**
 * Runs `fn` inside a transaction with `app.current_tenant` set for the RLS
 * policies to key off. Uses `set_config(...)` (a plain function call) rather
 * than string-interpolated `SET LOCAL app.current_tenant = '<id>'` — SET
 * doesn't support bind parameters, so building it via string concatenation
 * would be the one place in this codebase that violates the
 * no-string-concatenated-SQL rule. set_config is a regular SQL function and
 * takes a normal parameterized argument instead.
 *
 * Also idempotently provisions the `tenants` row for this tenant_id via the
 * narrow `provision_tenant` SECURITY DEFINER function (see
 * prisma/hardening.sql) — the gateway that verifies identity and issues our
 * JWT is the source of truth for which tenants exist, so the first
 * authenticated request for a given tenant_id transparently creates it here.
 * app_user still has zero direct grants on `tenants`; this is a one-purpose
 * RPC, not a raw table grant.
 */
export async function withTenantTx<T>(
  tenantId: string,
  fn: (tx: Prisma.TransactionClient) => Promise<T>,
  tenantName?: string,
): Promise<T> {
  return prisma.$transaction(
    async (tx) => {
      await tx.$executeRaw`SELECT provision_tenant(${tenantId}::uuid, ${tenantName ?? tenantId})`;
      await tx.$executeRaw`SELECT set_config('app.current_tenant', ${tenantId}, true)`;
      return fn(tx);
    },
    // Defaults (maxWait 2s / timeout 5s) are tight for dev: the cert
    // lifecycle background job and interactive requests can briefly
    // contend for the same small connection pool. Raising both avoids
    // spurious "unable to start a transaction" errors under that
    // contention — this governs transaction acquisition/duration, not the
    // connection pool size itself (that's `connection_limit` on the URL).
    { maxWait: 10_000, timeout: 10_000 },
  );
}
