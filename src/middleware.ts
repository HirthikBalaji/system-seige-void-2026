import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const sessionToken = req.cookies.get('session-token')?.value;
  const { pathname } = req.nextUrl;

  // Let static files, public files, callback, and dev tools pass through
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/static') ||
    pathname.startsWith('/favicon.ico') ||
    pathname.startsWith('/api/auth/callback') ||
    pathname.startsWith('/api/dev/session') ||
    pathname === '/'
  ) {
    return NextResponse.next();
  }

  // If session token is missing, redirect to auth
  if (!sessionToken) {
    const cfJwt = req.headers.get('CF-Access-Jwt-Assertion') || req.cookies.get('CF_Authorization')?.value;

    if (cfJwt) {
      // Expose Cloudflare token to callback to establish local session
      return NextResponse.redirect(new URL(`/api/auth/callback?token=${cfJwt}&redirect=${pathname}`, req.nextUrl.origin));
    }

    const isMock = process.env.NEXT_PUBLIC_MOCK_CF_ACCESS === 'true';
    if (isMock) {
      // For local development, redirect to the sandbox selection landing page
      return NextResponse.redirect(new URL('/', req.nextUrl.origin));
    } else {
      // For production, redirect to the Cloudflare Access portal
      const teamDomain = process.env.NEXT_PUBLIC_CF_TEAM_DOMAIN || 'hirthikbalaji.cloudflareaccess.com';
      return NextResponse.redirect(`https://${teamDomain}/cdn-cgi/access/login`);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/api/secrets/:path*',
    '/api/certificates/:path*',
    '/api/audit-logs/:path*',
    '/api/users/:path*',
    '/api/scan/:path*',
    '/api/rotation/:path*',
    '/api/sandbox/:path*',
  ],
};
