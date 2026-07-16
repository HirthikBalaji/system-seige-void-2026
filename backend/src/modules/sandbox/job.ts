import { prisma } from '../../lib/prisma';
import { withTenantTx } from '../../lib/withTenantTx';
import { cleanupExpiredSandboxes } from './sandbox';

export function startSandboxLifecycleJob(intervalMs = 60_000): () => void {
  let running = false;

  const tick = async () => {
    if (running) return;
    running = true;
    try {
      // Fetch tenant IDs using the RLS-isolated SECURITY DEFINER helper function
      const tenantIds = await prisma.$queryRaw<Array<{ id: string }>>`SELECT * FROM get_all_tenant_ids() AS id`;
      
      for (const { id } of tenantIds) {
        await withTenantTx(id, async (tx) => {
          await cleanupExpiredSandboxes(tx);
        });
      }
    } catch (err) {
      console.error('[sandbox-lifecycle-job]', err instanceof Error ? err.message : 'unknown error');
    } finally {
      running = false;
    }
  };

  void tick();
  const handle = setInterval(tick, intervalMs);
  return () => clearInterval(handle);
}
