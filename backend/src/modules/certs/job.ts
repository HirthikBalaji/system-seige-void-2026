import { prisma } from '../../lib/prisma';
import { withTenantTx } from '../../lib/withTenantTx';
import { appendAuditEntry } from '../../lib/audit';
import { computeStatus } from './status';

const RENEWAL_PERIOD_DAYS = 365;
// Nil UUID — this action is taken by the system, not any authenticated user;
// audit_log.actor_id is NOT NULL so we need a stable, recognizable sentinel
// rather than a fabricated per-run value.
const SYSTEM_ACTOR_ID = '00000000-0000-0000-0000-000000000000';

async function processTenant(tenantId: string): Promise<void> {
  await withTenantTx(tenantId, async (tx) => {
    const certs = await tx.certificate.findMany({ where: { tenantId } });
    const now = new Date();

    for (const cert of certs) {
      const newStatus = computeStatus(cert.expiresAt, now);
      if (newStatus === cert.status) {
        continue;
      }

      if ((newStatus === 'expiring_soon' || newStatus === 'expired') && cert.autoRenew) {
        const newExpiresAt = new Date(now.getTime() + RENEWAL_PERIOD_DAYS * 24 * 60 * 60 * 1000);

        await tx.certificate.update({
          where: { id: cert.id },
          data: { issuedAt: now, expiresAt: newExpiresAt, status: 'active' },
        });

        await appendAuditEntry(tx, {
          tenantId,
          actorId: SYSTEM_ACTOR_ID,
          action: 'cert.renew',
          resourceType: 'certificate',
          resourceId: cert.id,
          details: {
            commonName: cert.commonName,
            previousExpiresAt: cert.expiresAt.toISOString(),
            newExpiresAt: newExpiresAt.toISOString(),
            trigger: 'auto',
          },
        });
      } else {
        await tx.certificate.update({ where: { id: cert.id }, data: { status: newStatus } });
      }
    }
  });
}

/**
 * Polls every tenant's certificates and flips status / auto-renews as
 * needed. Runs per-tenant, each in its own RLS-scoped transaction — the job
 * intentionally never reads across tenants in one query, so it doesn't need
 * (and doesn't get) any RLS bypass. It only needs the list of tenant ids,
 * which it gets from a narrow SECURITY DEFINER function that returns ids
 * only, not tenant names or anything else (see prisma/hardening.sql).
 */
export function startCertLifecycleJob(intervalMs = 60_000): () => void {
  let running = false;

  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const tenantIds = await prisma.$queryRaw<Array<{ id: string }>>`SELECT * FROM get_all_tenant_ids() AS id`;
      for (const { id } of tenantIds) {
        await processTenant(id);
      }
    } catch (err) {
      console.error('[cert-lifecycle-job]', err instanceof Error ? err.message : 'unknown error');
    } finally {
      running = false;
    }
  };

  void tick();
  const handle = setInterval(tick, intervalMs);
  return () => clearInterval(handle);
}
