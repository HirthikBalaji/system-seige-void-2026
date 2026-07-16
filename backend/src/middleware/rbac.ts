import type { NextFunction, Request, Response } from 'express';
import type { Role } from './auth';

export type Permission = 'read' | 'write' | 'audit';

// Explicit per-role permission matrix rather than a linear rank. 'auditor'
// deliberately doesn't fit a hierarchy: it needs audit access without write
// access, which a simple viewer < operator < admin ladder can't express.
const ROLE_PERMISSIONS: Record<Role, Record<Permission, boolean>> = {
  viewer: { read: true, write: false, audit: false },
  operator: { read: true, write: true, audit: false },
  admin: { read: true, write: true, audit: true },
  auditor: { read: true, write: false, audit: true },
};

/** Requires the authenticated user's role to grant `permission`. */
export function requirePermission(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.auth) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    if (!ROLE_PERMISSIONS[req.auth.role][permission]) {
      res.status(403).json({ error: 'forbidden' });
      return;
    }
    next();
  };
}
