import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { env } from '../env';

export const ROLES = ['viewer', 'operator', 'admin', 'auditor'] as const;
export type Role = (typeof ROLES)[number];

export interface AuthContext {
  tenantId: string;
  userId: string;
  role: Role;
  /** Optional display name for auto-provisioning `tenants.name` on first sight of a tenant_id — see lib/withTenantTx.ts. */
  tenantName?: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

const claimsSchema = z.object({
  tenant_id: z.string().uuid(),
  user_id: z.string().uuid(),
  role: z.enum(ROLES),
  tenant_name: z.string().min(1).max(255).optional(),
});

// Headers the gateway is supposed to have already resolved into the verified
// JWT it forwards — they must never arrive as plain, unsigned trust signals.
// Per the trust boundary: if we ever see one, that's a bug upstream, not a
// shortcut to honor.
const FORBIDDEN_TRUST_HEADERS = ['x-tenant-id', 'x-user-id', 'x-role'];

export function verifyJwt(req: Request, res: Response, next: NextFunction): void {
  for (const header of FORBIDDEN_TRUST_HEADERS) {
    if (req.headers[header] !== undefined) {
      res.status(400).json({ error: 'invalid request' });
      return;
    }
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  const token = authHeader.slice('Bearer '.length).trim();
  if (!token) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  let decoded: unknown;
  try {
    // Pin the algorithm explicitly — never let the token's own `alg` header
    // pick it (that's how "alg: none" / RS256-to-HS256 confusion attacks work).
    decoded = jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  const parsed = claimsSchema.safeParse(decoded);
  if (!parsed.success) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  req.auth = {
    tenantId: parsed.data.tenant_id,
    userId: parsed.data.user_id,
    role: parsed.data.role,
    tenantName: parsed.data.tenant_name,
  };
  next();
}
