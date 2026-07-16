import * as jose from 'jose';

const TEAM_DOMAIN = process.env.NEXT_PUBLIC_CF_TEAM_DOMAIN || 'hirthikbalaji.cloudflareaccess.com';
const AUDIENCE_TAG = process.env.CF_AUDIENCE_TAG || 'mock-audience-tag-for-cloudflare-access';
const MOCK_SECRET_KEY = new TextEncoder().encode(process.env.ENCRYPTION_SECRET || '0123456789abcdef0123456789abcdef');

export interface CloudflareUserIdentity {
  id: string; // sub
  email: string;
  name?: string;
  identityProvider?: string; // idp
  groups: string[];
  loginTimestamp: number; // auth_time
}

function getJWKSUri() {
  return `https://${TEAM_DOMAIN}/cdn-cgi/access/certs`;
}

export async function verifyCloudflareJWT(jwt: string): Promise<CloudflareUserIdentity> {
  const isMock = process.env.NEXT_PUBLIC_MOCK_CF_ACCESS === 'true';

  if (isMock) {
    try {
      // Verify signature using local secret key in mock mode
      const { payload } = await jose.jwtVerify(jwt, MOCK_SECRET_KEY, {
        issuer: `https://${TEAM_DOMAIN}`,
        audience: AUDIENCE_TAG,
      });

      return {
        id: payload.sub as string,
        email: payload.email as string,
        name: (payload.name as string) || undefined,
        identityProvider: (payload.idp as string) || 'Mock IDP',
        groups: (payload.groups as string[]) || [],
        loginTimestamp: (payload.auth_time as number) || Math.floor(Date.now() / 1000),
      };
    } catch (err: any) {
      console.error('Mock JWT Verification failed:', err);
      throw new Error(`Invalid mock JWT: ${err.message}`);
    }
  }

  // Real verification against Cloudflare Access
  if (!TEAM_DOMAIN || !AUDIENCE_TAG) {
    throw new Error('Cloudflare Access Team Domain or Audience Tag not configured.');
  }

  try {
    const JWKS = jose.createRemoteJWKSet(new URL(getJWKSUri()));
    const { payload } = await jose.jwtVerify(jwt, JWKS, {
      issuer: `https://${TEAM_DOMAIN}`,
      audience: AUDIENCE_TAG,
    });

    return {
      id: payload.sub as string,
      email: payload.email as string,
      name: (payload.name as string) || undefined,
      identityProvider: (payload.idp as string) || undefined,
      groups: (payload.groups as string[]) || [],
      loginTimestamp: (payload.auth_time as number) || Math.floor(Date.now() / 1000),
    };
  } catch (err: any) {
    console.error('Cloudflare JWT Verification failed:', err);
    throw new Error(`Cloudflare JWT verification failed: ${err.message}`);
  }
}

// Generate a mock JWT for the developer portal / testing harness
export async function generateMockJWT(identity: Omit<CloudflareUserIdentity, 'loginTimestamp'>): Promise<string> {
  const timestamp = Math.floor(Date.now() / 1000);
  return await new jose.SignJWT({
    email: identity.email,
    name: identity.name,
    idp: identity.identityProvider || 'Mock IDP',
    groups: identity.groups,
    auth_time: timestamp,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(identity.id)
    .setIssuer(`https://${TEAM_DOMAIN}`)
    .setAudience(AUDIENCE_TAG)
    .setExpirationTime('2h')
    .setIssuedAt(timestamp)
    .sign(MOCK_SECRET_KEY);
}
