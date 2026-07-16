import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { revokeSession } from '@/lib/auth';
import { logEvent } from '@/lib/audit';
import prisma from '@/lib/prisma';

export async function POST(req: NextRequest) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get('session-token')?.value;

  const ipAddress = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  if (sessionToken) {
    try {
      const session = await prisma.session.findUnique({
        where: { id: sessionToken },
        include: { user: true }
      });

      if (session) {
        await revokeSession(sessionToken);
        await logEvent({
          userId: session.user.id,
          email: session.user.email,
          tenantId: session.user.tenantId,
          ipAddress,
          userAgent,
          action: 'User Logout',
          result: 'SUCCESS',
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    }
  }

  // Clear cookies
  cookieStore.set('session-token', '', { maxAge: 0, path: '/' });
  cookieStore.set('CF_Authorization', '', { maxAge: 0, path: '/' });

  const isMock = process.env.NEXT_PUBLIC_MOCK_CF_ACCESS === 'true';
  if (!isMock) {
    const teamDomain = process.env.NEXT_PUBLIC_CF_TEAM_DOMAIN || 'hirthikbalaji.cloudflareaccess.com';
    const origin = req.nextUrl.origin;
    return NextResponse.json({ 
      success: true, 
      redirectUrl: `https://${teamDomain}/cdn-cgi/access/logout?return_to=${encodeURIComponent(origin)}`
    });
  }

  return NextResponse.json({ success: true });
}
