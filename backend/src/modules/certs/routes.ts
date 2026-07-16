import { Router } from 'express';
import { z } from 'zod';
import { verifyJwt } from '../../middleware/auth';
import { requirePermission } from '../../middleware/rbac';
import { validateBody, validateParams } from '../../middleware/validate';
import { asyncHandler, HttpError } from '../../middleware/errorHandler';
import { withTenantTx } from '../../lib/withTenantTx';
import { appendAuditEntry } from '../../lib/audit';
import { computeStatus } from './status';

const router = Router();
router.use(verifyJwt);

const RENEWAL_PERIOD_DAYS = 365;

const createSchema = z.object({
  name: z.string().trim().min(1).max(255).optional(),
  commonName: z.string().trim().min(1).max(255),
  issuedAt: z.string().datetime().optional(),
  expiresAt: z.string().datetime(),
  autoRenew: z.boolean().optional().default(true),
});

const idParams = z.object({ id: z.string().uuid() });

interface CertRow {
  id: string;
  name: string | null;
  commonName: string;
  issuedAt: Date;
  expiresAt: Date;
  status: string;
  autoRenew: boolean;
  createdAt: Date;
}

function serializeCert(cert: CertRow) {
  return {
    id: cert.id,
    name: cert.name ?? cert.commonName,
    commonName: cert.commonName,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
    status: computeStatus(cert.expiresAt),
    autoRenew: cert.autoRenew,
    createdAt: cert.createdAt,
  };
}

router.post(
  '/',
  requirePermission('write'),
  validateBody(createSchema),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { name, commonName, issuedAt, expiresAt, autoRenew } = req.body as z.infer<typeof createSchema>;
    const issuedAtDate = issuedAt ? new Date(issuedAt) : new Date();
    const expiresAtDate = new Date(expiresAt);

    if (expiresAtDate <= issuedAtDate) {
      throw new HttpError(400, 'invalid request');
    }

    const created = await withTenantTx(auth.tenantId, async (tx) => {
      const cert = await tx.certificate.create({
        data: {
          tenantId: auth.tenantId,
          name: name ?? null,
          commonName,
          issuedAt: issuedAtDate,
          expiresAt: expiresAtDate,
          status: computeStatus(expiresAtDate, issuedAtDate),
          autoRenew,
        },
      });

      await appendAuditEntry(tx, {
        tenantId: auth.tenantId,
        actorId: auth.userId,
        action: 'cert.create',
        resourceType: 'certificate',
        resourceId: cert.id,
        details: { commonName, name, expiresAt: expiresAtDate.toISOString() },
      });

      return cert;
    });

    res.status(201).json(serializeCert(created));
  }),
);

router.get(
  '/',
  requirePermission('read'),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const certs = await withTenantTx(auth.tenantId, (tx) =>
      tx.certificate.findMany({ where: { tenantId: auth.tenantId }, orderBy: { createdAt: 'desc' } }),
    );
    res.json({ certificates: certs.map(serializeCert) });
  }),
);

router.get(
  '/:id',
  requirePermission('read'),
  validateParams(idParams),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;

    const cert = await withTenantTx(auth.tenantId, (tx) =>
      tx.certificate.findFirst({ where: { id, tenantId: auth.tenantId } }),
    );

    if (!cert) {
      throw new HttpError(404, 'not found');
    }
    res.json(serializeCert(cert));
  }),
);

router.patch(
  '/:id/renew',
  requirePermission('write'),
  validateParams(idParams),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;

    const renewed = await withTenantTx(auth.tenantId, async (tx) => {
      const existing = await tx.certificate.findFirst({ where: { id, tenantId: auth.tenantId } });
      if (!existing) return null;

      const now = new Date();
      const newExpiresAt = new Date(now.getTime() + RENEWAL_PERIOD_DAYS * 24 * 60 * 60 * 1000);

      const cert = await tx.certificate.update({
        where: { id: existing.id },
        data: { issuedAt: now, expiresAt: newExpiresAt, status: 'active' },
      });

      await appendAuditEntry(tx, {
        tenantId: auth.tenantId,
        actorId: auth.userId,
        action: 'cert.renew',
        resourceType: 'certificate',
        resourceId: cert.id,
        details: {
          commonName: cert.commonName,
          previousExpiresAt: existing.expiresAt.toISOString(),
          newExpiresAt: newExpiresAt.toISOString(),
          trigger: 'manual',
        },
      });

      return cert;
    });

    if (!renewed) {
      throw new HttpError(404, 'not found');
    }
    res.json(serializeCert(renewed));
  }),
);

router.delete(
  '/:id',
  requirePermission('write'),
  validateParams(idParams),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;

    const deleted = await withTenantTx(auth.tenantId, async (tx) => {
      const existing = await tx.certificate.findFirst({ where: { id, tenantId: auth.tenantId } });
      if (!existing) return null;

      await tx.certificate.delete({ where: { id: existing.id } });

      await appendAuditEntry(tx, {
        tenantId: auth.tenantId,
        actorId: auth.userId,
        action: 'cert.delete',
        resourceType: 'certificate',
        resourceId: existing.id,
        details: { commonName: existing.commonName },
      });

      return existing;
    });

    if (!deleted) {
      throw new HttpError(404, 'not found');
    }
    res.status(204).send();
  }),
);

export default router;
