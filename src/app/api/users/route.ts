import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import prisma from '@/lib/prisma';
import { logEvent } from '@/lib/audit';
import crypto from 'crypto';

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req);
    
    // View members in tenant (all logged in users can see team members)
    const whereClause = user.role === 'SUPER_ADMIN' ? {} : { tenantId };
    
    const users = await prisma.user.findMany({
      where: whereClause,
      orderBy: { createdAt: 'desc' }
    });

    return NextResponse.json(users);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'users:invite');
    const body = await req.json();
    const { email, name, role } = body;

    if (!email || !role) {
      throw new ApiError(400, 'Email and Role are required');
    }

    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      throw new ApiError(400, 'User with this email already exists');
    }

    const mockId = `usr_${crypto.randomUUID().replace(/-/g, '')}`;

    const newUser = await prisma.user.create({
      data: {
        id: mockId,
        email,
        name: name || email.split('@')[0],
        tenantId,
        role,
        status: 'ACTIVE'
      }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'User Invited',
      result: 'SUCCESS',
      details: { invitedUserId: newUser.id, invitedEmail: email, role }
    });

    return NextResponse.json(newUser);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function PUT(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'users:update-role');
    const body = await req.json();
    const { id, role } = body;

    if (!id || !role) {
      throw new ApiError(400, 'User ID and Role are required');
    }

    const targetUser = await prisma.user.findUnique({
      where: { id }
    });

    if (!targetUser || (user.role !== 'SUPER_ADMIN' && targetUser.tenantId !== tenantId)) {
      throw new ApiError(404, 'User not found in organization');
    }

    const updatedUser = await prisma.user.update({
      where: { id },
      data: { role }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'User Role Updated',
      result: 'SUCCESS',
      details: { targetUserId: id, targetEmail: targetUser.email, newRole: role }
    });

    return NextResponse.json(updatedUser);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'users:remove');
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');

    if (!id) {
      throw new ApiError(400, 'User ID is required');
    }

    if (id === user.id) {
      throw new ApiError(400, 'You cannot remove yourself');
    }

    const targetUser = await prisma.user.findUnique({
      where: { id }
    });

    if (!targetUser || (user.role !== 'SUPER_ADMIN' && targetUser.tenantId !== tenantId)) {
      throw new ApiError(404, 'User not found in organization');
    }

    await prisma.user.delete({
      where: { id }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'User Removed',
      result: 'SUCCESS',
      details: { targetUserId: id, targetEmail: targetUser.email }
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    return handleApiError(error);
  }
}
