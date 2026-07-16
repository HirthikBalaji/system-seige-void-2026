import crypto from 'node:crypto';
import { Prisma } from '@prisma/client';

export const GENESIS_HASH = '0'.repeat(64);

export interface AppendAuditEntryInput {
  tenantId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  details?: Record<string, unknown>;
}

/**
 * Deterministic JSON serialization with sorted keys so the hash is
 * reproducible regardless of property insertion order — plain
 * JSON.stringify does not promise stable key ordering for all inputs.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export function computeEntryHash(params: {
  prevHash: string;
  tenantId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  createdAtIso: string;
  details: unknown;
}): string {
  return crypto
    .createHash('sha256')
    .update(params.prevHash)
    .update(params.tenantId)
    .update(params.actorId)
    .update(params.action)
    .update(params.resourceType)
    .update(params.resourceId ?? '')
    .update(params.createdAtIso)
    .update(canonicalJson(params.details))
    .digest('hex');
}

/**
 * Appends one entry to the single, platform-wide hash chain, inside the same
 * transaction as the business-logic change it records (atomic — a
 * secret.create and its audit row commit together or not at all).
 *
 * Because the chain spans every tenant, two concurrent appends must not read
 * the same "last row" and both build on it — that would fork the chain. A
 * Postgres advisory lock, held for the rest of this transaction, serializes
 * appends across the whole platform without needing to lock the audit_log
 * table itself.
 */
export async function appendAuditEntry(tx: Prisma.TransactionClient, input: AppendAuditEntryInput): Promise<string> {
  const details = input.details ?? {};
  const resourceId = input.resourceId ?? null;

  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('global_audit_chain'))`;

  const last = await tx.$queryRaw<Array<{ last_id: bigint | null; last_hash: string | null }>>`
    SELECT * FROM get_last_audit_entry()
  `;
  const prevHash = last[0]?.last_hash ?? GENESIS_HASH;

  const createdAt = new Date();
  const createdAtIso = createdAt.toISOString();

  const entryHash = computeEntryHash({
    prevHash,
    tenantId: input.tenantId,
    actorId: input.actorId,
    action: input.action,
    resourceType: input.resourceType,
    resourceId,
    createdAtIso,
    details,
  });

  await tx.auditLog.create({
    data: {
      tenantId: input.tenantId,
      actorId: input.actorId,
      action: input.action,
      resourceType: input.resourceType,
      resourceId,
      details: details as Prisma.InputJsonValue,
      prevHash,
      entryHash,
      createdAt,
    },
  });

  return entryHash;
}
