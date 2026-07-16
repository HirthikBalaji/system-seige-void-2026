import prisma from './prisma';
import { CloudflareUserIdentity } from './cloudflare';

// Roles definition
export type UserRole =
  | 'SUPER_ADMIN'
  | 'ORG_ADMIN'
  | 'SECURITY_ADMIN'
  | 'DEVELOPER'
  | 'AUDITOR'
  | 'READ_ONLY'
  | 'SERVICE_ACCOUNT';

// Permissions definition
export const PERMISSIONS = {
  SECRETS_READ: 'secrets:read',
  SECRETS_CREATE: 'secrets:create',
  SECRETS_UPDATE: 'secrets:update',
  SECRETS_DELETE: 'secrets:delete',
  SECRETS_ROTATE: 'secrets:rotate',

  CERTS_READ: 'certs:read',
  CERTS_IMPORT: 'certs:import',
  CERTS_RENEW: 'certs:renew',
  CERTS_DELETE: 'certs:delete',

  USERS_INVITE: 'users:invite',
  USERS_REMOVE: 'users:remove',
  USERS_UPDATE_ROLE: 'users:update-role',

  AUDIT_VIEW: 'audit:view',
  AUDIT_EXPORT: 'audit:export',

  ORG_SETTINGS: 'org:settings',
  ORG_BILLING: 'org:billing',
  ORG_INTEGRATIONS: 'org:integrations',
};

// Role-to-Permissions Mapping
const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  SUPER_ADMIN: Object.values(PERMISSIONS),
  ORG_ADMIN: [
    PERMISSIONS.SECRETS_READ,
    PERMISSIONS.SECRETS_CREATE,
    PERMISSIONS.SECRETS_UPDATE,
    PERMISSIONS.SECRETS_DELETE,
    PERMISSIONS.SECRETS_ROTATE,
    PERMISSIONS.CERTS_READ,
    PERMISSIONS.CERTS_IMPORT,
    PERMISSIONS.CERTS_RENEW,
    PERMISSIONS.CERTS_DELETE,
    PERMISSIONS.USERS_INVITE,
    PERMISSIONS.USERS_REMOVE,
    PERMISSIONS.USERS_UPDATE_ROLE,
    PERMISSIONS.AUDIT_VIEW,
    PERMISSIONS.AUDIT_EXPORT,
    PERMISSIONS.ORG_SETTINGS,
    PERMISSIONS.ORG_BILLING,
    PERMISSIONS.ORG_INTEGRATIONS,
  ],
  SECURITY_ADMIN: [
    PERMISSIONS.SECRETS_READ,
    PERMISSIONS.SECRETS_CREATE,
    PERMISSIONS.SECRETS_UPDATE,
    PERMISSIONS.SECRETS_DELETE,
    PERMISSIONS.SECRETS_ROTATE,
    PERMISSIONS.CERTS_READ,
    PERMISSIONS.CERTS_IMPORT,
    PERMISSIONS.CERTS_RENEW,
    PERMISSIONS.CERTS_DELETE,
    PERMISSIONS.AUDIT_VIEW,
  ],
  DEVELOPER: [
    PERMISSIONS.SECRETS_READ,
    PERMISSIONS.SECRETS_CREATE,
    PERMISSIONS.SECRETS_UPDATE,
    PERMISSIONS.CERTS_READ,
  ],
  AUDITOR: [
    PERMISSIONS.AUDIT_VIEW,
    PERMISSIONS.AUDIT_EXPORT,
  ],
  READ_ONLY: [
    PERMISSIONS.SECRETS_READ,
    PERMISSIONS.CERTS_READ,
  ],
  SERVICE_ACCOUNT: [
    PERMISSIONS.SECRETS_READ,
  ],
};

export function hasPermission(role: string, permission: string): boolean {
  const permissions = ROLE_PERMISSIONS[role as UserRole];
  if (!permissions) return false;
  return permissions.includes(permission);
}

export function getRolePermissions(role: string): string[] {
  return ROLE_PERMISSIONS[role as UserRole] || [];
}

export async function getOrCreateUserAndTenant(identity: CloudflareUserIdentity) {
  // Resolve tenant name from groups or identity provider or email domain
  let tenantName = '';
  const tenantGroup = identity.groups.find((g) => g.startsWith('tenant-'));
  
  if (tenantGroup) {
    tenantName = tenantGroup.replace('tenant-', '');
  } else if (identity.identityProvider) {
    tenantName = identity.identityProvider;
  } else {
    const emailParts = identity.email.split('@');
    if (emailParts.length === 2) {
      tenantName = emailParts[1].split('.')[0];
    }
  }
  
  // Format tenant name (capitalized)
  tenantName = tenantName.charAt(0).toUpperCase() + tenantName.slice(1);
  if (!tenantName) tenantName = 'Default Tenant';

  // Check if tenant exists, otherwise create it
  let tenant = await prisma.tenant.findFirst({
    where: { name: tenantName },
  });

  if (!tenant) {
    tenant = await prisma.tenant.create({
      data: { name: tenantName },
    });
  }

  // Check if user exists
  let user = await prisma.user.findUnique({
    where: { id: identity.id },
    include: { tenant: true },
  });

  if (!user) {
    // Resolve user's role from Cloudflare groups if available (e.g. role-developer, role-org_admin)
    let role: UserRole = 'DEVELOPER'; // default role
    const roleGroup = identity.groups.find((g) => g.startsWith('role-'));
    if (roleGroup) {
      const parsedRole = roleGroup.replace('role-', '').toUpperCase().replace('-', '_');
      if (Object.keys(ROLE_PERMISSIONS).includes(parsedRole)) {
        role = parsedRole as UserRole;
      }
    } else if (identity.email.startsWith('admin@') || identity.email.startsWith('super@')) {
      role = 'ORG_ADMIN';
    }

    // Automatically create the user
    user = await prisma.user.create({
      data: {
        id: identity.id,
        email: identity.email,
        name: identity.name || identity.email.split('@')[0],
        tenantId: tenant.id,
        role,
        status: 'ACTIVE',
        lastLogin: new Date(),
      },
      include: { tenant: true },
    });
  } else {
    // Update user's last login and details if name changed
    user = await prisma.user.update({
      where: { id: identity.id },
      data: {
        lastLogin: new Date(),
        name: identity.name || user.name,
      },
      include: { tenant: true },
    });
  }

  return user;
}

export async function createSession(userId: string) {
  // Session duration: 2 hours
  const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
  
  const session = await prisma.session.create({
    data: {
      userId,
      expiresAt,
    },
  });

  return session.id;
}

export async function verifySession(sessionId: string) {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: {
      user: {
        include: {
          tenant: true,
        },
      },
    },
  });

  if (!session) {
    throw new Error('Session not found');
  }

  if (session.revoked) {
    throw new Error('Session has been revoked');
  }

  if (new Date() > session.expiresAt) {
    throw new Error('Session has expired');
  }

  if (session.user.status !== 'ACTIVE') {
    throw new Error('User account is suspended');
  }

  return session.user;
}

export async function renewSession(sessionId: string) {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
  });

  if (!session || session.revoked || new Date() > session.expiresAt) {
    throw new Error('Cannot renew inactive or expired session');
  }

  // Extend expiration by 2 hours
  const newExpiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
  
  return await prisma.session.update({
    where: { id: sessionId },
    data: { expiresAt: newExpiresAt },
  });
}

export async function revokeSession(sessionId: string) {
  await prisma.session.update({
    where: { id: sessionId },
    data: { revoked: true },
  });
}

export async function revokeAllUserSessions(userId: string) {
  await prisma.session.updateMany({
    where: { userId },
    data: { revoked: true },
  });
}
