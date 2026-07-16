import { NextRequest, NextResponse } from 'next/server';
import { generateMockJWT } from '@/lib/cloudflare';
import { logEvent } from '@/lib/audit';

export async function POST(req: NextRequest) {
  // Security guard: Ensure this is only runnable in mock/dev environments
  const isMock = process.env.NEXT_PUBLIC_MOCK_CF_ACCESS === 'true';
  if (!isMock) {
    return NextResponse.json({ error: 'Sandbox mode is disabled in production' }, { status: 403 });
  }

  const ipAddress = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  try {
    const body = await req.json();
    const { email, name, role, tenant, groups = [] } = body;

    if (!email || !role || !tenant) {
      return NextResponse.json({ error: 'Email, Role, and Tenant are required' }, { status: 400 });
    }

    // Build Cloudflare-style groups
    const resolvedGroups = [
      `tenant-${tenant.toLowerCase().replace(/[^a-z0-9]/g, '')}`,
      `role-${role.toLowerCase().replace(/_/g, '-')}`,
      ...groups
    ];

    // Build user ID
    const userId = `cf_${email.toLowerCase().replace(/[^a-z0-9]/g, '_')}`;

    // Generate mock JWT assertion token
    const mockToken = await generateMockJWT({
      id: userId,
      email,
      name: name || email.split('@')[0],
      identityProvider: 'Mock Auth Provider',
      groups: resolvedGroups
    });

    await logEvent({
      ipAddress,
      userAgent,
      action: 'Sandbox Identity Switched',
      result: 'SUCCESS',
      details: { email, role, tenant, groups: resolvedGroups }
    });

    return NextResponse.json({
      token: mockToken,
      redirectUrl: `/api/auth/callback?token=${mockToken}`
    });
  } catch (error: any) {
    console.error('Failed to create mock session:', error);
    return NextResponse.json({ error: `Sandbox session failure: ${error.message}` }, { status: 500 });
  }
}
