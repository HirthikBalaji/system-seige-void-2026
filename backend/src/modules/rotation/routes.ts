import { Router } from 'express';
import { z } from 'zod';
import { verifyJwt } from '../../middleware/auth';
import { requirePermission } from '../../middleware/rbac';
import { validateParams, validateBody } from '../../middleware/validate';
import { asyncHandler, HttpError } from '../../middleware/errorHandler';
import { withTenantTx } from '../../lib/withTenantTx';
import { getRiskScore, rotateSecret, rollbackSecret, RiskSignals } from './rotation';

const router = Router();
router.use(verifyJwt);

const idParams = z.object({ id: z.string().uuid() });

const evaluateSchema = z.object({
  failedLogins: z.number().nonnegative().default(0),
  travelAnomalies: z.number().nonnegative().default(0),
  leakAlerts: z.number().nonnegative().default(0),
  insiderThreats: z.number().nonnegative().default(0)
});

// List rotation logs
router.get(
  '/logs',
  requirePermission('read'),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    
    const logs = await withTenantTx(auth.tenantId, (tx) =>
      tx.rotationLog.findMany({
        where: { tenantId: auth.tenantId },
        orderBy: { createdAt: 'desc' }
      })
    );

    res.json({ logs });
  })
);

// Secret Health Dashboard metrics
router.get(
  '/dashboard',
  requirePermission('read'),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;

    const result = await withTenantTx(auth.tenantId, async (tx) => {
      const secrets = await tx.secret.findMany({
        where: { tenantId: auth.tenantId }
      });

      const logs = await tx.rotationLog.findMany({
        where: { tenantId: auth.tenantId, status: 'COMPLETED' },
        orderBy: { createdAt: 'desc' },
        take: 5
      });

      // Calculate overall score (average of (100 - riskScore))
      let overallScore = 100;
      let criticalSecretsCount = 0;
      let highRiskCount = 0;
      let mediumRiskCount = 0;
      let lowRiskCount = 0;

      if (secrets.length > 0) {
        const totalRisk = secrets.reduce((acc, s) => acc + s.riskScore, 0);
        overallScore = Math.round(100 - (totalRisk / secrets.length));
        
        secrets.forEach(s => {
          if (s.riskLevel === 'CRITICAL') criticalSecretsCount++;
          else if (s.riskLevel === 'HIGH') highRiskCount++;
          else if (s.riskLevel === 'MEDIUM') mediumRiskCount++;
          else lowRiskCount++;
        });
      }

      // Identify upcoming rotations (secrets whose last rotation + rotationFrequencyDays is closest to now)
      const upcoming = secrets
        .filter(s => s.isRotatable)
        .map(s => {
          const nextRotation = new Date(s.lastRotationTime);
          nextRotation.setDate(nextRotation.getDate() + s.rotationFrequencyDays);
          const daysLeft = Math.round((nextRotation.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          return {
            id: s.id,
            name: s.name,
            riskLevel: s.riskLevel,
            riskScore: s.riskScore,
            daysLeft: Math.max(0, daysLeft),
            nextRotation: nextRotation.toISOString()
          };
        })
        .sort((a, b) => a.daysLeft - b.daysLeft)
        .slice(0, 5);

      const criticalSecrets = secrets
        .filter(s => s.riskLevel === 'CRITICAL' || s.riskLevel === 'HIGH')
        .map(s => ({
          id: s.id,
          name: s.name,
          riskLevel: s.riskLevel,
          riskScore: s.riskScore,
          lastRotationTime: s.lastRotationTime
        }));

      return {
        overallScore,
        riskDistribution: {
          critical: criticalSecretsCount,
          high: highRiskCount,
          medium: mediumRiskCount,
          low: lowRiskCount
        },
        criticalSecrets,
        upcomingRotations: upcoming,
        recentRotations: logs.map(l => ({
          id: l.id,
          secretId: l.secretId,
          triggerType: l.triggerType,
          riskScoreBefore: l.riskScoreBefore,
          rotationReason: l.rotationReason,
          createdAt: l.createdAt
        })),
        aiRecommendations: secrets
          .filter(s => s.riskScore > 30)
          .map(s => ({
            secretId: s.id,
            secretName: s.name,
            recommendation: s.riskLevel === 'CRITICAL' || s.riskLevel === 'HIGH'
              ? `CRITICAL: Rotate secret "${s.name}" immediately to prevent exploit.`
              : `Warning: Secret "${s.name}" has moderate risks (${s.riskScore} score). Consider scheduling rotation.`
          })),
        trendingRisks: [
          'Aging secrets without regular rotation updates',
          'Increased geographic impossible-travel login activity in production',
          'Recent public credential leak notifications matching repository prefixes'
        ]
      };
    });

    res.json(result);
  })
);

// Evaluate risk score for a secret, automatically rotating if score >= 70
router.post(
  '/evaluate/:id',
  requirePermission('write'),
  validateParams(idParams),
  validateBody(evaluateSchema),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;
    const signals = req.body as RiskSignals;

    const result = await withTenantTx(auth.tenantId, async (tx) => {
      const secret = await tx.secret.findFirst({
        where: { id, tenantId: auth.tenantId }
      });

      if (!secret) {
        throw new HttpError(404, 'Secret not found');
      }

      // Calculate risk score
      const riskData = await getRiskScore(secret, signals);

      // Save risk score and level back to Secret
      await tx.secret.update({
        where: { id },
        data: {
          riskScore: riskData.score,
          riskLevel: riskData.level
        }
      });

      let rotated = false;
      let rotationLog = null;

      // Auto-rotation trigger: If risk is HIGH or CRITICAL (score >= 70)
      if (riskData.score >= 70 && secret.isRotatable) {
        rotated = true;
        rotationLog = await rotateSecret(
          tx,
          auth.tenantId,
          auth.userId,
          id,
          'AUTO',
          `AI Risk Engine triggered autonomous rotation (Score: ${riskData.score}, Level: ${riskData.level}). Reason: ${riskData.explanation}`,
          riskData
        );
      }

      return {
        secretId: id,
        secretName: secret.name,
        evaluatedAt: new Date(),
        riskScore: riskData.score,
        riskLevel: riskData.level,
        explanation: riskData.explanation,
        confidence: riskData.confidence,
        riskFactors: riskData.riskFactors,
        trendingRisks: riskData.trendingRisks,
        autoRotated: rotated,
        rotationLog
      };
    });

    res.json(result);
  })
);

// Force manual rotation
router.post(
  '/rotate/:id',
  requirePermission('write'),
  validateParams(idParams),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;

    const log = await withTenantTx(auth.tenantId, async (tx) => {
      const secret = await tx.secret.findFirst({
        where: { id, tenantId: auth.tenantId }
      });

      if (!secret) {
        throw new HttpError(404, 'Secret not found');
      }

      const dummySignals: RiskSignals = { failedLogins: 0, travelAnomalies: 0, leakAlerts: 0, insiderThreats: 0 };
      const riskData = await getRiskScore(secret, dummySignals);

      return await rotateSecret(
        tx,
        auth.tenantId,
        auth.userId,
        id,
        'MANUAL',
        'Administrator triggered manual rotation sequence.',
        riskData
      );
    });

    res.json({ message: 'Rotation completed successfully', log });
  })
);

// Rollback to previous version
router.post(
  '/rollback/:id',
  requirePermission('write'),
  validateParams(idParams),
  asyncHandler(async (req, res) => {
    const auth = req.auth!;
    const { id } = res.locals.params as z.infer<typeof idParams>;

    const log = await withTenantTx(auth.tenantId, async (tx) => {
      return await rollbackSecret(tx, auth.tenantId, auth.userId, id);
    });

    res.json({ message: 'Secret rolled back successfully to previous version', log });
  })
);

export default router;
