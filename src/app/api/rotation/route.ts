import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import { callBackend } from '@/lib/backendClient';
import { logEvent } from '@/lib/audit';

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:read');
    const { searchParams } = new URL(req.url);
    const tab = searchParams.get('tab');

    const identity = { tenantId, userId: user.id, role: user.role };

    if (tab === 'logs') {
      const result = await callBackend<{ logs: any[] }>('/internal/rotation/logs', identity);
      return NextResponse.json(result);
    }

    const dashboardData = await callBackend<any>('/internal/rotation/dashboard', identity);
    return NextResponse.json(dashboardData);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:create');
    const body = await req.json();
    const { action, secretId, signals } = body;

    if (!action || !secretId) {
      throw new ApiError(400, 'Action and Secret ID are required');
    }

    const identity = { tenantId, userId: user.id, role: user.role };

    let result;
    if (action === 'evaluate') {
      result = await callBackend<any>(`/internal/rotation/evaluate/${secretId}`, identity, {
        method: 'POST',
        body: signals || { failedLogins: 0, travelAnomalies: 0, leakAlerts: 0, insiderThreats: 0 }
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'AI Risk Evaluation',
        result: 'SUCCESS',
        details: { secretId, score: result.riskScore, level: result.riskLevel, autoRotated: result.autoRotated }
      });
    } else if (action === 'rotate') {
      result = await callBackend<any>(`/internal/rotation/rotate/${secretId}`, identity, {
        method: 'POST'
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Manual Secret Rotation',
        result: 'SUCCESS',
        details: { secretId, logId: result.log?.id }
      });
    } else if (action === 'rollback') {
      result = await callBackend<any>(`/internal/rotation/rollback/${secretId}`, identity, {
        method: 'POST'
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Rollback Secret Version',
        result: 'SUCCESS',
        details: { secretId, logId: result.log?.id }
      });
    } else {
      throw new ApiError(400, 'Invalid action specified');
    }

    return NextResponse.json(result);
  } catch (error) {
    return handleApiError(error);
  }
}
