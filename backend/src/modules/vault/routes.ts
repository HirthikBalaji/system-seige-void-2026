import { Router } from 'express';
import { z } from 'zod';
import { verifyJwt } from '../../middleware/auth';
import { requirePermission } from '../../middleware/rbac';
import { validateBody, validateParams } from '../../middleware/validate';
import { asyncHandler, HttpError } from '../../middleware/errorHandler';
import { withTenantTx } from '../../lib/withTenantTx';
import { appendAuditEntry } from '../../lib/audit';
import { decryptValue, encryptValue, generateDek, unwrapDek, wipe, wrapDek } from '../../lib/crypto';

const router = Router();
router.use(verifyJwt);

const createSchema = z.object({
  name: z.string().trim().min(1).max(255),
  value: z.string().min(1).max(65536),
});

const updateSchema = z.object({
  value: z.string().min(1).max(65536),
});

const idParams = z.object({ id: z.string().uuid() });

// Create — operator or above.
router.post(
  '/secrets',
  requirePermission('write'),
  validateBody(createSchema),
  asyncHandler(async (req, res) => {
    const { name, value } = req.body as z.infer<typeof createSchema>;
    const auth = req.auth!;

    const dek = generateDek();
    try {
      const { ciphertext, iv, authTag } = encryptValue(dek, Buffer.from(value, 'utf8'));
      const wrappedDek = wrapDek(dek);

      const created = await withTenantTx(auth.tenantId, async (tx) => {
        const secret = await tx.secret.create({
          data: {
            tenantId: auth.tenantId,
            name,
            encryptedValue: ciphertext,
            iv,
            authTag,
            wrappedDek,
            createdBy: auth.userId,
          },
        });

        await appendAuditEntry(tx, {
          tenantId: auth.tenantId,
          actorId: auth.userId,
          action: 'secret.create',
          resourceType: 'secret',
          resourceId: secret.id,
          details: { name },
        });

        return secret;
      });

      res.status(201).json({
        id: created.id,
        name: created.name,
        version: created.version,
        createdAt: created.createdAt,
      });
    } finally {
      wipe(dek);
    }
  }),
);

// List — metadata only, never decrypted values. Viewer or above.
router.get(
  '/secrets',
  requirePermission('read'),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;

    const secrets = await withTenantTx(auth.tenantId, (tx) =>
      tx.secret.findMany({
        where: { tenantId: auth.tenantId },
        select: {
          id: true,
          name: true,
          version: true,
          createdBy: true,
          createdAt: true,
          updatedAt: true,
        },
        orderBy: { createdAt: 'desc' },
      }),
    );

    res.json({ secrets });
  }),
);

// Get one, decrypted — always writes its own secret.read audit entry.
// Viewer or above (viewer is "read-only", not "no-read").
router.get(
  '/secrets/:id',
  requirePermission('read'),
  validateParams(idParams),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;

    const result = await withTenantTx(auth.tenantId, async (tx) => {
      const secret = await tx.secret.findFirst({ where: { id, tenantId: auth.tenantId } });
      if (!secret) return null;

      const dek = unwrapDek(secret.wrappedDek);
      let plaintext: Buffer;
      try {
        plaintext = decryptValue(dek, secret.encryptedValue, secret.iv, secret.authTag);
      } finally {
        wipe(dek);
      }

      await appendAuditEntry(tx, {
        tenantId: auth.tenantId,
        actorId: auth.userId,
        action: 'secret.read',
        resourceType: 'secret',
        resourceId: secret.id,
        details: { name: secret.name },
      });

      const value = plaintext.toString('utf8');
      plaintext.fill(0);

      return { id: secret.id, name: secret.name, value, version: secret.version };
    });

    if (!result) {
      throw new HttpError(404, 'not found');
    }
    res.json(result);
  }),
);

// Update — bumps version, re-wraps with a fresh DEK. Operator or above.
router.patch(
  '/secrets/:id',
  requirePermission('write'),
  validateParams(idParams),
  validateBody(updateSchema),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;
    const { value } = req.body as z.infer<typeof updateSchema>;

    const dek = generateDek();
    try {
      const { ciphertext, iv, authTag } = encryptValue(dek, Buffer.from(value, 'utf8'));
      const wrappedDek = wrapDek(dek);

      const updated = await withTenantTx(auth.tenantId, async (tx) => {
        const existing = await tx.secret.findFirst({ where: { id, tenantId: auth.tenantId } });
        if (!existing) return null;

        const secret = await tx.secret.update({
          where: { id: existing.id },
          data: {
            encryptedValue: ciphertext,
            iv,
            authTag,
            wrappedDek,
            version: { increment: 1 },
          },
        });

        await appendAuditEntry(tx, {
          tenantId: auth.tenantId,
          actorId: auth.userId,
          action: 'secret.update',
          resourceType: 'secret',
          resourceId: secret.id,
          details: { name: secret.name, version: secret.version },
        });

        return secret;
      });

      if (!updated) {
        throw new HttpError(404, 'not found');
      }
      res.json({ id: updated.id, name: updated.name, version: updated.version, updatedAt: updated.updatedAt });
    } finally {
      wipe(dek);
    }
  }),
);

// Delete — operator or above.
router.delete(
  '/secrets/:id',
  requirePermission('write'),
  validateParams(idParams),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;

    const deleted = await withTenantTx(auth.tenantId, async (tx) => {
      const existing = await tx.secret.findFirst({ where: { id, tenantId: auth.tenantId } });
      if (!existing) return null;

      await tx.secret.delete({ where: { id: existing.id } });

      await appendAuditEntry(tx, {
        tenantId: auth.tenantId,
        actorId: auth.userId,
        action: 'secret.delete',
        resourceType: 'secret',
        resourceId: existing.id,
        details: { name: existing.name },
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
