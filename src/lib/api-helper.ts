import { cookies } from 'next/headers';
import { verifySession, hasPermission } from './auth';
import { logEvent } from './audit';

export class ApiError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function verifyApiRequest(req: Request, requiredPermission?: string) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get('session-token')?.value;

  const ipAddress = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  if (!sessionToken) {
    await logEvent({
      ipAddress,
      userAgent,
      action: requiredPermission ? `API Access: ${requiredPermission}` : 'API Access',
      result: 'FAILURE',
      details: { error: 'Missing session-token cookie' }
    });
    throw new ApiError(401, 'Unauthorized: No session token');
  }

  try {
    const user = await verifySession(sessionToken);
    
    if (requiredPermission && !hasPermission(user.role, requiredPermission)) {
      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId: user.tenantId,
        ipAddress,
        userAgent,
        action: `API Access: ${requiredPermission}`,
        result: 'DENIED',
        details: { role: user.role, error: 'Forbidden: Insufficient permissions' }
      });
      throw new ApiError(403, 'Forbidden: Insufficient permissions');
    }

    return { user, tenantId: user.tenantId, ipAddress, userAgent };
  } catch (err: any) {
    await logEvent({
      ipAddress,
      userAgent,
      action: requiredPermission ? `API Access: ${requiredPermission}` : 'API Access',
      result: 'FAILURE',
      details: { error: err.message }
    });
    
    const statusCode = err instanceof ApiError ? err.statusCode : 401;
    throw new ApiError(statusCode, err.message || 'Unauthorized');
  }
}

export function handleApiError(err: any) {
  console.error('API Error:', err);
  const statusCode = err instanceof ApiError ? err.statusCode : 500;
  const message = err.message || 'Internal Server Error';
  
  return new Response(JSON.stringify({ error: message }), {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
}
