import crypto from 'crypto';
import prisma from './prisma';

const HMAC_SECRET = process.env.AUDIT_HMAC_SECRET || 'super-secure-hmac-signing-key-for-audit-logs-validation';
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

interface AuditLogInput {
  userId?: string | null;
  email?: string | null;
  tenantId?: string | null;
  ipAddress: string;
  userAgent: string;
  action: string;
  result: 'SUCCESS' | 'FAILURE' | 'DENIED';
  details?: Record<string, any>;
}

export function computeRowHash(data: {
  timestamp: string;
  userId?: string | null;
  email?: string | null;
  tenantId?: string | null;
  ipAddress: string;
  userAgent: string;
  action: string;
  result: string;
  details: string;
  prevHash: string;
}): string {
  const payload = [
    data.timestamp,
    data.userId || '',
    data.email || '',
    data.tenantId || '',
    data.ipAddress,
    data.userAgent,
    data.action,
    data.result,
    data.details,
    data.prevHash
  ].join('|');

  return crypto.createHash('sha256').update(payload).digest('hex');
}

export function computeSignature(rowHash: string): string {
  return crypto.createHmac('sha256', HMAC_SECRET).update(rowHash).digest('hex');
}

export async function logEvent(input: AuditLogInput) {
  try {
    const detailsStr = input.details ? JSON.stringify(input.details) : '{}';
    const timestamp = new Date();
    
    // Find the latest audit log entry to chain them together
    const prevLog = await prisma.auditLog.findFirst({
      orderBy: { timestamp: 'desc' }
    });
    
    const prevHash = prevLog ? prevLog.rowHash : GENESIS_HASH;
    
    const rowHash = computeRowHash({
      timestamp: timestamp.toISOString(),
      userId: input.userId,
      email: input.email,
      tenantId: input.tenantId,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      action: input.action,
      result: input.result,
      details: detailsStr,
      prevHash
    });
    
    const signature = computeSignature(rowHash);
    
    return await prisma.auditLog.create({
      data: {
        timestamp,
        userId: input.userId || null,
        email: input.email || null,
        tenantId: input.tenantId || null,
        ipAddress: input.ipAddress,
        userAgent: input.userAgent,
        action: input.action,
        result: input.result,
        details: detailsStr,
        prevHash,
        rowHash,
        signature
      }
    });
  } catch (error) {
    console.error('Failed to write audit log:', error);
  }
}

export async function verifyAuditChain() {
  const logs = await prisma.auditLog.findMany({
    orderBy: { timestamp: 'asc' }
  });
  
  const errors: Array<{ id: string; index: number; error: string }> = [];
  let expectedPrevHash = GENESIS_HASH;
  
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];
    
    // 1. Recalculate row hash
    const recomputedHash = computeRowHash({
      timestamp: log.timestamp.toISOString(),
      userId: log.userId,
      email: log.email,
      tenantId: log.tenantId,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      action: log.action,
      result: log.result,
      details: log.details,
      prevHash: log.prevHash
    });
    
    if (recomputedHash !== log.rowHash) {
      errors.push({
        id: log.id,
        index: i,
        error: `Row hash mismatch. Data has been modified.`
      });
      continue;
    }
    
    // 2. Verify signature
    const recomputedSig = computeSignature(log.rowHash);
    if (recomputedSig !== log.signature) {
      errors.push({
        id: log.id,
        index: i,
        error: `Signature invalid. HMAC signature verification failed.`
      });
      continue;
    }
    
    // 3. Verify link integrity
    if (log.prevHash !== expectedPrevHash) {
      errors.push({
        id: log.id,
        index: i,
        error: `Chain link broken. Previous hash does not match previous record.`
      });
    }
    
    expectedPrevHash = log.rowHash;
  }
  
  return {
    valid: errors.length === 0,
    totalRecords: logs.length,
    errors
  };
}
