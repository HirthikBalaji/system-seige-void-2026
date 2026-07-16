import * as jose from 'jose';
import { deriveUuid } from './uuidBridge';
import type { UserRole } from './auth';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:4000';
const BACKEND_JWT_SECRET = new TextEncoder().encode(
  process.env.BACKEND_JWT_SECRET || 'change-me-shared-secret-with-backend',
);

export type BackendRole = 'viewer' | 'operator' | 'admin' | 'auditor';

// This gateway's 7-tier RBAC maps onto the backend's 4-tier permission
// model (read / write / audit — see backend/src/middleware/rbac.ts). Each
// mapping preserves the *real* permission the role should have; nothing
// here is rounded up to a broader role than the source role actually grants.
const ROLE_MAP: Record<UserRole, BackendRole> = {
  SUPER_ADMIN: 'admin',
  ORG_ADMIN: 'admin',
  SECURITY_ADMIN: 'admin',
  DEVELOPER: 'operator',
  SERVICE_ACCOUNT: 'operator',
  AUDITOR: 'auditor',
  READ_ONLY: 'viewer',
};

export function mapRole(role: string): BackendRole {
  return ROLE_MAP[role as UserRole] ?? 'viewer';
}

interface BackendIdentity {
  tenantId: string; // already a real UUID in this app's own Tenant model
  userId: string; // Cloudflare subject / sandbox id — NOT guaranteed UUID-shaped
  role: string;
}

async function mintBackendToken(identity: BackendIdentity): Promise<string> {
  return await new jose.SignJWT({
    tenant_id: identity.tenantId,
    user_id: deriveUuid(identity.userId),
    role: mapRole(identity.role),
  })
    .setProtectedHeader({ alg: 'HS256' })
    // Minted fresh for this one proxied call and used immediately — a
    // short expiry keeps the exposure window negligible without needing
    // any revocation mechanism.
    .setExpirationTime('60s')
    .setIssuedAt()
    .sign(BACKEND_JWT_SECRET);
}

export class BackendError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Calls one of our own `/internal/*` backend endpoints on behalf of the
 * already-authenticated gateway user. Mints a short-lived JWT carrying the
 * verified tenant/user/role and forwards it as a normal Bearer token — this
 * gateway is, in effect, the "API gateway" role the backend's trust
 * boundary was designed around from the start.
 */
export async function callBackend<T = unknown>(
  path: string,
  identity: BackendIdentity,
  init?: { method?: string; body?: unknown },
): Promise<T> {
  const token = await mintBackendToken(identity);

  try {
    const response = await fetch(`${BACKEND_URL}${path}`, {
      method: init?.method ?? 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init?.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
      cache: 'no-store',
    });

    if (response.status === 204) {
      return undefined as T;
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new BackendError(response.status, (data as { error?: string }).error ?? 'backend request failed');
    }

    return data as T;
  } catch (err: any) {
    if (err instanceof BackendError) {
      throw err;
    }
    console.error('Connection to backend failed:', err.message);
    throw new BackendError(
      503,
      'Backend service is offline (connection refused). Please make sure the backend database and server are started.',
    );
  }
}
