import { Router } from 'express';
import { z } from 'zod';
import { verifyJwt } from '../../middleware/auth';
import { requirePermission } from '../../middleware/rbac';
import { validateParams, validateBody } from '../../middleware/validate';
import { asyncHandler, HttpError } from '../../middleware/errorHandler';
import { withTenantTx } from '../../lib/withTenantTx';
import { provisionSandbox, destroySandbox, maskSensitiveData } from './sandbox';

const router = Router();
router.use(verifyJwt);

const idParams = z.object({ id: z.string().uuid() });

const provisionSchema = z.object({
  prompt: z.string().trim().min(3).max(1000),
  expiresInHours: z.number().int().min(1).max(24).default(1)
});

const maskSchema = z.object({
  fieldName: z.string().min(1).max(255),
  rawValue: z.string().min(1).max(65536)
});

// List sandbox sessions
router.get(
  '/sessions',
  requirePermission('read'),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    
    const sessions = await withTenantTx(auth.tenantId, (tx) =>
      tx.sandboxSession.findMany({
        where: { tenantId: auth.tenantId },
        orderBy: { createdAt: 'desc' }
      })
    );

    res.json({ sessions });
  })
);

// Provision a new sandbox using natural language
router.post(
  '/provision',
  requirePermission('write'),
  validateBody(provisionSchema),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { prompt, expiresInHours } = req.body as z.infer<typeof provisionSchema>;

    const session = await withTenantTx(auth.tenantId, async (tx) => {
      return await provisionSandbox(tx, auth.tenantId, auth.userId, prompt, expiresInHours);
    });

    res.status(201).json({
      message: 'Sandbox environment successfully provisioned',
      session
    });
  })
);

// Destroy a sandbox manually and generate destruction certificate
router.post(
  '/destroy/:id',
  requirePermission('write'),
  validateParams(idParams),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;

    const session = await withTenantTx(auth.tenantId, async (tx) => {
      return await destroySandbox(tx, auth.tenantId, auth.userId, id);
    });

    res.json({
      message: 'Sandbox environment successfully destroyed and resources purged',
      session
    });
  })
);

// Utility endpoint to mask production fields for testing
router.post(
  '/mask',
  requirePermission('read'),
  validateBody(maskSchema),
  asyncHandler(async (req, res) => {
    const { fieldName, rawValue } = req.body as z.infer<typeof maskSchema>;
    const maskedValue = maskSensitiveData(fieldName, rawValue);
    res.json({ fieldName, maskedValue });
  })
);

export default router;
