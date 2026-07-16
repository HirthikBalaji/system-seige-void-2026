import { Router } from 'express';
import { z } from 'zod';
import { verifyJwt } from '../../middleware/auth';
import { requirePermission } from '../../middleware/rbac';
import { validateQuery } from '../../middleware/validate';
import { asyncHandler } from '../../middleware/errorHandler';
import { withTenantTx } from '../../lib/withTenantTx';
import { prisma } from '../../lib/prisma';
import { GENESIS_HASH, computeEntryHash } from '../../lib/audit';

const router = Router();
router.use(verifyJwt);
// Audit log access (including chain verification) requires the 'audit'
// permission — held by admin and auditor, never by viewer/operator, even
// for their own tenant.
router.use(requirePermission('audit'));

const listQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(200).default(50),
  cursor: z.coerce.bigint().optional(),
});

interface AuditRow {
  id: bigint;
  tenantId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  details: unknown;
  prevHash: string;
  entryHash: string;
  createdAt: Date;
}

function serializeEntry(e: AuditRow) {
  return {
    id: e.id.toString(),
    tenantId: e.tenantId,
    actorId: e.actorId,
    action: e.action,
    resourceType: e.resourceType,
    resourceId: e.resourceId,
    details: e.details,
    prevHash: e.prevHash,
    entryHash: e.entryHash,
    createdAt: e.createdAt,
  };
}

// Paginated, tenant-scoped view of the caller's own audit trail.
router.get(
  '/log',
  validateQuery(listQuerySchema),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { limit, cursor } = res.locals.query as z.infer<typeof listQuerySchema>;

    const entries = await withTenantTx(auth.tenantId, (tx) =>
      tx.auditLog.findMany({
        where: {
          tenantId: auth.tenantId,
          ...(cursor !== undefined ? { id: { lt: cursor } } : {}),
        },
        orderBy: { id: 'desc' },
        take: limit,
      }),
    );

    res.json({
      entries: entries.map(serializeEntry),
      nextCursor: entries.length === limit ? (entries[entries.length - 1] as AuditRow).id.toString() : null,
    });
  }),
);

interface RawAuditRow {
  id: bigint;
  tenant_id: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  details: unknown;
  prev_hash: string;
  entry_hash: string;
  created_at: Date;
}

// Walks the ENTIRE platform-wide chain and recomputes every hash from
// genesis. Deliberately global — see prisma/hardening.sql's
// get_full_audit_chain() for why, and what it does/doesn't leak. The
// response here stays minimal on purpose: only a boolean and a bare row id,
// never another tenant's action/resource/details.
router.get(
  '/verify',
  asyncHandler(async (_req, res) => {
    const rows = await prisma.$queryRaw<RawAuditRow[]>`SELECT * FROM get_full_audit_chain()`;

    let expectedPrev = GENESIS_HASH;
    let brokenAtId: number | null = null;

    for (const row of rows) {
      const recomputed = computeEntryHash({
        prevHash: expectedPrev,
        tenantId: row.tenant_id,
        actorId: row.actor_id,
        action: row.action,
        resourceType: row.resource_type,
        resourceId: row.resource_id,
        createdAtIso: row.created_at.toISOString(),
        details: row.details,
      });

      if (row.prev_hash !== expectedPrev || row.entry_hash !== recomputed) {
        brokenAtId = Number(row.id);
        break;
      }

      expectedPrev = row.entry_hash;
    }

    res.json({ valid: brokenAtId === null, brokenAtId, totalRecords: rows.length });
  }),
);

export default router;
