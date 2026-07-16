import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError } from '@/lib/api-helper';
import prisma from '@/lib/prisma';
import { verifyAuditChain, logEvent } from '@/lib/audit';

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'audit:view');
    const { searchParams } = new URL(req.url);
    const verify = searchParams.get('verify') === 'true';

    if (verify) {
      const result = await verifyAuditChain();
      
      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Audit Chain Verified',
        result: result.valid ? 'SUCCESS' : 'FAILURE',
        details: { valid: result.valid, recordCount: result.totalRecords, errorCount: result.errors.length }
      });

      return NextResponse.json(result);
    }

    // List logs. If SUPER_ADMIN, allow viewing all logs. Otherwise, strictly filter by tenantId.
    const whereClause = user.role === 'SUPER_ADMIN' ? {} : { tenantId };
    
    const logs = await prisma.auditLog.findMany({
      where: whereClause,
      orderBy: { timestamp: 'desc' },
      take: 200 // Cap at 200 latest logs for API speed
    });

    return NextResponse.json(logs);
  } catch (error) {
    return handleApiError(error);
  }
}
