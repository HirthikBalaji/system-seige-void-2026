import crypto from 'node:crypto';
import { prisma } from '../../lib/prisma';
import { withTenantTx } from '../../lib/withTenantTx';
import { HttpError } from '../../middleware/errorHandler';
import { appendAuditEntry } from '../../lib/audit';

// Generate a long-lived CA keypair for the platform tenant
const caKeys = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

export class WorkloadIdentityService {
  /**
   * Registers a workload
   */
  static async registerWorkload(
    tenantId: string,
    actorId: string,
    name: string,
    type: 'KUBERNETES' | 'DOCKER' | 'MICROSERVICE',
    attestationType: 'K8S_SA' | 'TPM' | 'SPIFFE',
    selector: any,
  ) {
    return withTenantTx(tenantId, async (tx) => {
      const workload = await tx.workloadIdentity.create({
        data: {
          tenantId,
          name,
          type,
          attestationType,
          status: 'ACTIVE',
          selector,
        },
      });

      await appendAuditEntry(tx, {
        tenantId,
        actorId,
        action: 'workload.register',
        resourceType: 'workload',
        resourceId: workload.id,
        details: { name, type, attestationType },
      });

      return workload;
    });
  }

  /**
   * Attests a workload and issues a short-lived workload certificate
   */
  static async attestAndIssueCertificate(
    tenantId: string,
    workloadId: string,
    attestationData: { token?: string; hostIp?: string; containerId?: string },
  ) {
    return withTenantTx(tenantId, async (tx) => {
      const workload = await tx.workloadIdentity.findFirst({
        where: { id: workloadId, tenantId },
      });

      if (!workload) {
        throw new HttpError(404, 'Workload identity not found');
      }

      if (workload.status !== 'ACTIVE') {
        throw new HttpError(403, 'Workload identity is not active');
      }

      // Attestation Verification (Prototype)
      // Verify token / container metadata matches selectors
      const selector = workload.selector as any;
      if (workload.attestationType === 'K8S_SA') {
        if (!attestationData.token || !attestationData.token.startsWith('eyJ')) {
          throw new HttpError(401, 'Kubernetes ServiceAccount Token attestation failed');
        }
        // Validate Kubernetes namespace/serviceaccount selector if configured
        if (selector.namespace && !attestationData.token.includes(selector.namespace)) {
          throw new HttpError(401, 'Attestation token namespace mismatch');
        }
      } else if (workload.attestationType === 'SPIFFE') {
        if (!attestationData.token || !attestationData.token.startsWith('spiffe://')) {
          throw new HttpError(401, 'SPIFFE ID attestation failed');
        }
      } else if (workload.attestationType === 'TPM') {
        if (!attestationData.hostIp || (selector.hostIp && selector.hostIp !== attestationData.hostIp)) {
          throw new HttpError(401, 'TPM Host IP attestation failed');
        }
      }

      // Generate a cryptographic Workload Identity Certificate (Prototype)
      // We generate a client keypair
      const clientKeyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const serialNumber = crypto.randomBytes(16).toString('hex');
      const commonName = `workload:${workload.name}:${workload.id}`;
      const sans = [`spiffe://${tenantId}/ns/default/sa/${workload.name}`, `dns:${workload.name}.local`];
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes short-lived cert

      const certContent = {
        serialNumber,
        commonName,
        sans,
        workloadId: workload.id,
        tenantId,
        publicKey: clientKeyPair.publicKey,
        expiresAt: expiresAt.toISOString(),
      };

      // Sign the certificate metadata using the CA Private Key
      const signer = crypto.createSign('SHA256');
      signer.update(JSON.stringify(certContent));
      const signature = signer.sign(caKeys.privateKey, 'base64');

      // Construct a PEM-formatted Workload Certificate
      const certPem = [
        '-----BEGIN WORKLOAD CERTIFICATE-----',
        Buffer.from(JSON.stringify({ ...certContent, signature })).toString('base64'),
        '-----END WORKLOAD CERTIFICATE-----',
      ].join('\n');

      const workloadCertificate = await tx.workloadCertificate.create({
        data: {
          workloadId: workload.id,
          serialNumber,
          commonName,
          sans,
          certificatePem: certPem,
          expiresAt,
          status: 'ACTIVE',
        },
      });

      await appendAuditEntry(tx, {
        tenantId,
        actorId: workload.id,
        action: 'workload.certificate.issue',
        resourceType: 'workload_certificate',
        resourceId: workloadCertificate.id,
        details: { commonName, serialNumber, expiresAt },
      });

      return {
        certificatePem: certPem,
        privateKeyPem: clientKeyPair.privateKey,
        expiresAt,
      };
    });
  }

  /**
   * Validates a certificate at runtime
   */
  static async validateCertificate(certPem: string): Promise<any> {
    try {
      const base64Body = certPem
        .replace('-----BEGIN WORKLOAD CERTIFICATE-----', '')
        .replace('-----END WORKLOAD CERTIFICATE-----', '')
        .replace(/\s+/g, '');
      const rawJson = Buffer.from(base64Body, 'base64').toString('utf8');
      const certData = JSON.parse(rawJson);

      const { signature, ...certContent } = certData;

      // Verify RSA signature using CA Public Key
      const verifier = crypto.createVerify('SHA256');
      verifier.update(JSON.stringify(certContent));
      const isValid = verifier.verify(caKeys.publicKey, signature, 'base64');

      if (!isValid) {
        throw new Error('Certificate signature verification failed');
      }

      // Check Expiration
      if (new Date() > new Date(certContent.expiresAt)) {
        throw new Error('Certificate is expired');
      }

      // Check DB Revocation List
      const cert = await prisma.workloadCertificate.findFirst({
        where: { serialNumber: certContent.serialNumber, status: 'ACTIVE' },
      });

      if (!cert) {
        throw new Error('Certificate has been revoked or is not registered');
      }

      return certContent;
    } catch (err: any) {
      throw new HttpError(401, `Invalid workload identity: ${err.message}`);
    }
  }

  /**
   * Revokes a workload certificate or entire identity
   */
  static async revokeCertificate(tenantId: string, actorId: string, serialNumber: string, reason: string) {
    return withTenantTx(tenantId, async (tx) => {
      const cert = await tx.workloadCertificate.findFirst({
        where: { serialNumber },
      });

      if (!cert) {
        throw new HttpError(404, 'Certificate not found');
      }

      const updatedCert = await tx.workloadCertificate.update({
        where: { id: cert.id },
        data: {
          status: 'REVOKED',
          revokedAt: new Date(),
          revocationReason: reason,
        },
      });

      await appendAuditEntry(tx, {
        tenantId,
        actorId,
        action: 'workload.certificate.revoke',
        resourceType: 'workload_certificate',
        resourceId: cert.id,
        details: { serialNumber, reason },
      });

      return updatedCert;
    });
  }

  /**
   * Revokes workload identity completely
   */
  static async revokeWorkload(tenantId: string, actorId: string, workloadId: string) {
    return withTenantTx(tenantId, async (tx) => {
      const workload = await tx.workloadIdentity.findFirst({
        where: { id: workloadId, tenantId },
      });

      if (!workload) {
        throw new HttpError(404, 'Workload not found');
      }

      const updatedWorkload = await tx.workloadIdentity.update({
        where: { id: workloadId },
        data: { status: 'REVOKED' },
      });

      // Revoke all certificates belonging to this workload
      await tx.workloadCertificate.updateMany({
        where: { workloadId },
        data: {
          status: 'REVOKED',
          revokedAt: new Date(),
          revocationReason: 'Workload identity revoked',
        },
      });

      await appendAuditEntry(tx, {
        tenantId,
        actorId,
        action: 'workload.revoke',
        resourceType: 'workload',
        resourceId: workloadId,
        details: { name: workload.name },
      });

      return updatedWorkload;
    });
  }
}
