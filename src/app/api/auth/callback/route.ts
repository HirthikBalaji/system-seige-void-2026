import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { verifyCloudflareJWT } from '@/lib/cloudflare';
import { getOrCreateUserAndTenant, createSession } from '@/lib/auth';
import { logEvent } from '@/lib/audit';

export async function GET(req: NextRequest) {
  const ipAddress = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  // Read the Cloudflare JWT Assertion
  // 1. From header
  let jwt: string | null | undefined = req.headers.get('CF-Access-Jwt-Assertion');
  
  // 2. From query string (useful for redirect logins/testing)
  if (!jwt) {
    jwt = req.nextUrl.searchParams.get('token');
  }

  // 3. From cookies
  if (!jwt) {
    const cookieStore = await cookies();
    jwt = cookieStore.get('CF_Authorization')?.value || cookieStore.get('cf-access-token')?.value;
  }

  if (!jwt) {
    await logEvent({
      ipAddress,
      userAgent,
      action: 'Authentication Callback',
      result: 'FAILURE',
      details: { error: 'No Cloudflare Access JWT found' }
    });
    return NextResponse.json({ error: 'Missing Cloudflare Access JWT' }, { status: 400 });
  }

  try {
    const identity = await verifyCloudflareJWT(jwt);
    const user = await getOrCreateUserAndTenant(identity);
    const sessionId = await createSession(user.id);

    const cookieStore = await cookies();
    cookieStore.set('session-token', sessionId, {
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
      action: 'User Login',
      result: 'SUCCESS',
      details: { idp: identity.identityProvider, groups: identity.groups }
    });

    // Redirect to dynamic destination
    const { searchParams } = new URL(req.url);
    const redirectPath = searchParams.get('redirect') || '/dashboard';
    return NextResponse.redirect(new URL(redirectPath, req.nextUrl.origin));
  } catch (error: any) {
    await logEvent({
      ipAddress,
      userAgent,
      action: 'User Login',
      result: 'FAILURE',
      details: { error: error.message }
    });
    return NextResponse.json({ error: `Authentication failed: ${error.message}` }, { status: 401 });
  }
}
