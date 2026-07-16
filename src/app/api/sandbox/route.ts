import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import { callBackend } from '@/lib/backendClient';
import { logEvent } from '@/lib/audit';

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:read');
    const identity = { tenantId, userId: user.id, role: user.role };

    const result = await callBackend<{ sessions: any[] }>('/internal/sandbox/sessions', identity);
    return NextResponse.json(result);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:create');
    const body = await req.json();
    const { action, prompt, expiresInHours, sessionId, fieldName, rawValue } = body;

    if (!action) {
      throw new ApiError(400, 'Action is required');
    }

    const identity = { tenantId, userId: user.id, role: user.role };

    let result;
    if (action === 'provision') {
      if (!prompt) {
        throw new ApiError(400, 'Prompt is required for sandbox provisioning');
      }

      result = await callBackend<any>('/internal/sandbox/provision', identity, {
        method: 'POST',
        body: { prompt, expiresInHours }
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Provision Secret Sandbox',
        result: 'SUCCESS',
        details: { sessionId: result.session?.id, name: result.session?.name }
      });
    } else if (action === 'destroy') {
      if (!sessionId) {
        throw new ApiError(400, 'Session ID is required for destruction');
      }

      result = await callBackend<any>(`/internal/sandbox/destroy/${sessionId}`, identity, {
        method: 'POST'
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Destroy Secret Sandbox',
        result: 'SUCCESS',
        details: { sessionId }
      });
    } else if (action === 'mask') {
      if (!fieldName || !rawValue) {
        throw new ApiError(400, 'Field name and raw value are required for masking');
      }

      result = await callBackend<any>('/internal/sandbox/mask', identity, {
        method: 'POST',
        body: { fieldName, rawValue }
      });
    } else {
      throw new ApiError(400, 'Invalid action specified');
    }

    return NextResponse.json(result);
  } catch (error) {
    return handleApiError(error);
  }
}
