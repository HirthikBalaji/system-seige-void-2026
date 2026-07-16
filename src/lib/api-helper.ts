import { cookies } from 'next/headers';
import { verifySession, hasPermission, getOrCreateUserAndTenant, createSession } from './auth';
import { verifyCloudflareJWT } from './cloudflare';
import { logEvent } from './audit';

export class ApiError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function verifyApiRequest(req: Request, requiredPermission?: string) {
  const cookieStore = await cookies();
  let sessionToken = cookieStore.get('session-token')?.value;

  const ipAddress = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  let user;

  // Auto-login: If local session is missing, check if a valid Cloudflare token is present
  if (!sessionToken) {
    const cfJwt = req.headers.get('CF-Access-Jwt-Assertion') || cookieStore.get('CF_Authorization')?.value;
    
    if (cfJwt) {
      try {
        const identity = await verifyCloudflareJWT(cfJwt);
        user = await getOrCreateUserAndTenant(identity);
        sessionToken = await createSession(user.id);

        cookieStore.set('session-token', sessionToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          path: '/',
          maxAge: 2 * 60 * 60, // 2 hours
        });

        await logEvent({
          userId: user.id,
          email: user.email,
          tenantId: user.tenantId,
          ipAddress,
          userAgent,
          action: 'Session Auto-Created from Cloudflare JWT',
          result: 'SUCCESS',
        });
      } catch (err: any) {
        console.error('Auto session provisioning failed:', err.message);
      }
    }
  }

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
    if (!user) {
      user = await verifySession(sessionToken);
    }
    
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

import { BackendError } from './backendClient';

export function handleApiError(err: any) {
  console.error('API Error:', err);
  
  let statusCode = 500;
  if (err instanceof ApiError) {
    statusCode = err.statusCode;
  } else if (err instanceof BackendError) {
    statusCode = err.status;
  }
  
  const message = err.message || 'Internal Server Error';
  
  return new Response(JSON.stringify({ error: message }), {
    status: statusCode,
    headers: { 'Content-Type': 'application/json' },
  });
}
