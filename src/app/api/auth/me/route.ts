import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError } from '@/lib/api-helper';
import { getRolePermissions } from '@/lib/auth';

export async function GET(req: NextRequest) {
  try {
    const { user } = await verifyApiRequest(req);
    
    return NextResponse.json({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        status: user.status,
        lastLogin: user.lastLogin,
        tenant: {
          id: user.tenant.id,
          name: user.tenant.name
        },
        permissions: getRolePermissions(user.role)
      }
    });
  } catch (error) {
    return handleApiError(error);
  }
}
