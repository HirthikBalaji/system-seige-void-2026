import { withTenantTx } from '../../lib/withTenantTx';
import { appendAuditEntry } from '../../lib/audit';

export class RiskCardService {
  /**
   * Generates a Risk Card for an event/target and writes to DB & Audit logs
   */
  static async createRiskCard(
    tenantId: string,
    params: {
      targetType: 'SECRET' | 'CERTIFICATE' | 'WORKLOAD';
      targetId: string;
      targetName: string;
      riskScore: number;
      confidenceScore: number;
      triggerEvent: string;
      evidence: any;
      timeline: any[];
      assetsAffected: any[];
      businessImpact: string;
      complianceImpact: string;
      recommendedAction: string;
      executedAction?: string;
      validationPerformed?: string;
      rollbackPlan?: string;
    },
  ) {
    return withTenantTx(tenantId, async (tx) => {
      const riskCard = await tx.riskCard.create({
        data: {
          tenantId,
          targetType: params.targetType,
          targetId: params.targetId,
          riskScore: params.riskScore,
          confidenceScore: params.confidenceScore,
          triggerEvent: params.triggerEvent,
          evidence: params.evidence,
          timeline: params.timeline,
          assetsAffected: params.assetsAffected,
          businessImpact: params.businessImpact,
          complianceImpact: params.complianceImpact,
          recommendedAction: params.recommendedAction,
          executedAction: params.executedAction || 'Under analysis',
          validationPerformed: params.validationPerformed || 'Scheduled',
          rollbackPlan: params.rollbackPlan || 'Automatic rotation rollback configuration',
        },
      });

      // Write explainable card reference to the audit log
      await appendAuditEntry(tx, {
        tenantId,
        actorId: '00000000-0000-0000-0000-000000000000',
        action: 'riskcard.generate',
        resourceType: 'risk_card',
        resourceId: riskCard.id,
        details: {
          targetName: params.targetName,
          riskScore: params.riskScore,
          trigger: params.triggerEvent,
        },
      });

      return riskCard;
    });
  }

  /**
   * Generates sample risk cards if empty
   */
  static async seedRiskCardsIfEmpty(tenantId: string) {
    return withTenantTx(tenantId, async (tx) => {
      const count = await tx.riskCard.count({ where: { tenantId } });
      if (count > 0) return;

      console.log(`[RiskCard] Seeding initial explainable AI risk cards for tenant ${tenantId}...`);

      const sampleCards = [
        {
          targetType: 'SECRET' as const,
          targetId: 'db-credentials-uuid',
          targetName: 'Customer DB Credentials',
          riskScore: 88,
          confidenceScore: 0.95,
          triggerEvent: 'Git repository leak detected on public GitHub commit',
          evidence: {
            leakLocation: 'https://github.com/hirthik-org/public-repo/commit/1a2b3c4d',
            snippetMatched: 'DATABASE_URL=postgresql://app_user:******@localhost:5432/db',
            entropyScore: 4.82,
          },
          timeline: [
            { step: 'Commit pushed', time: new Date(Date.now() - 3600000).toISOString() },
            { step: 'AI Scanner detection', time: new Date(Date.now() - 3500000).toISOString() },
            { step: 'Autonomous adapter trigger', time: new Date(Date.now() - 3400000).toISOString() },
          ],
          assetsAffected: [
            { name: 'Customer Database', type: 'DATABASE' },
            { name: 'Payment Processing Service', type: 'APPLICATION' },
          ],
          businessImpact: 'High risk of Customer PII leak. Potential financial liability due to payment integration exposure.',
          complianceImpact: 'GDPR Article 32 violation (failure to ensure security of processing), PCI-DSS Requirement 3 non-compliance.',
          recommendedAction: 'Immediate revocation of credentials, rotate DB passwords, check database logs for access anomaly.',
          executedAction: 'Credential revoked automatically. Replacement secret generated in platform vault and redeployed to K8s.',
          validationPerformed: 'mTLS handshake and DB connection health checks verified successfully for payment service.',
          rollbackPlan: 'Deploy key rollback to version 3 using Vault Rollback console.',
        },
        {
          targetType: 'CERTIFICATE' as const,
          targetId: 'auth-server-cert-uuid',
          targetName: 'Auth Server TLS Cert',
          riskScore: 45,
          confidenceScore: 0.88,
          triggerEvent: 'Certificate expiration warning (expires in 5 days)',
          evidence: {
            expirationDate: new Date(Date.now() + 5 * 24 * 3600000).toISOString(),
            autoRenewFailed: 'DNS challenge timeout',
          },
          timeline: [
            { step: 'Expiry alert threshold hit', time: new Date(Date.now() - 7200000).toISOString() },
            { step: 'DNS challenge auto-renew fail', time: new Date(Date.now() - 7100000).toISOString() },
          ],
          assetsAffected: [
            { name: 'K8s Production Cluster', type: 'K8S_CLUSTER' },
          ],
          businessImpact: 'Authentication endpoints will throw SSL/TLS connection warnings, locking developers out of core API integrations.',
          complianceImpact: 'Internal security policy violation (expired service certificates).',
          recommendedAction: 'Re-trigger DNS challenge manually or complete renewal via HTTP-01 challenge.',
          executedAction: 'Alert sent to Security Administrator. Renewal queued.',
          validationPerformed: 'DNS record availability verified.',
          rollbackPlan: 'Restore backup Lets Encrypt config.',
        }
      ];

      for (const card of sampleCards) {
        await tx.riskCard.create({
          data: {
            tenantId,
            targetType: card.targetType,
            targetId: card.targetId,
            riskScore: card.riskScore,
            confidenceScore: card.confidenceScore,
            triggerEvent: card.triggerEvent,
            evidence: card.evidence,
            timeline: card.timeline,
            assetsAffected: card.assetsAffected,
            businessImpact: card.businessImpact,
            complianceImpact: card.complianceImpact,
            recommendedAction: card.recommendedAction,
            executedAction: card.executedAction,
            validationPerformed: card.validationPerformed,
            rollbackPlan: card.rollbackPlan,
          },
        });
      }
    });
  }

  /**
   * Retrieves all risk cards for a tenant
   */
  static async getRiskCards(tenantId: string) {
    await this.seedRiskCardsIfEmpty(tenantId);
    return withTenantTx(tenantId, async (tx) => {
      return tx.riskCard.findMany({
        where: { tenantId },
        orderBy: { createdAt: 'desc' },
      });
    });
  }
}
