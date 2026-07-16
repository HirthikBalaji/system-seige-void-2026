import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import { encrypt, decrypt } from '@/lib/encryption';
import prisma from '@/lib/prisma';
import { logEvent } from '@/lib/audit';
import crypto from 'crypto';

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:read');
    const { searchParams } = new URL(req.url);
    const secretId = searchParams.get('id');
    const reveal = searchParams.get('reveal') === 'true';

    if (secretId) {
      // Fetch single secret
      const secret = await prisma.secret.findUnique({
        where: { id: secretId }
      });

      if (!secret || secret.tenantId !== tenantId) {
        throw new ApiError(404, 'Secret not found');
      }

      if (reveal) {
        // Decrypt the secret value
        const decryptedValue = decrypt(secret.value);
        
        await logEvent({
          userId: user.id,
          email: user.email,
          tenantId,
          ipAddress,
          userAgent,
          action: 'Secret Decrypted',
          result: 'SUCCESS',
          details: { secretId, name: secret.name }
        });

        return NextResponse.json({
          ...secret,
          value: decryptedValue
        });
      }

      return NextResponse.json({
        ...secret,
        value: '********' // masked
      });
    }

    // List all secrets for tenant
    const secrets = await prisma.secret.findMany({
      where: { tenantId },
      orderBy: { updatedAt: 'desc' }
    });

    const maskedSecrets = secrets.map((s: any) => ({
      ...s,
      value: '********'
    }));

    return NextResponse.json(maskedSecrets);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:create');
    const body = await req.json();
    const { name, value } = body;

    if (!name || !value) {
      throw new ApiError(400, 'Name and Value are required');
    }

    // Encrypt the value
    const encryptedValue = encrypt(value);

    const secret = await prisma.secret.create({
      data: {
        name,
        value: encryptedValue,
        tenantId,
        createdBy: user.id
      }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'Secret Created',
      result: 'SUCCESS',
      details: { secretId: secret.id, name }
    });

    return NextResponse.json({
      id: secret.id,
      name: secret.name,
      version: secret.version,
      createdAt: secret.createdAt
    });
  } catch (error) {
    return handleApiError(error);
  }
}

export async function PUT(req: NextRequest) {
  try {
    const body = await req.json();
    const { id, name, value, action } = body;

    if (!id) {
      throw new ApiError(400, 'Secret ID is required');
    }

    // Handle rotation permission check vs normal update check
    const requiredPermission = action === 'rotate' ? 'secrets:rotate' : 'secrets:update';
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, requiredPermission);

    const existingSecret = await prisma.secret.findUnique({
      where: { id }
    });

    if (!existingSecret || existingSecret.tenantId !== tenantId) {
      throw new ApiError(404, 'Secret not found');
    }

    let finalValue = existingSecret.value;
    let actionLogName = 'Secret Updated';

    if (action === 'rotate') {
      // Auto-generate a secure 32-character hex key for rotation
      const rotatedPlaintext = crypto.randomBytes(16).toString('hex');
      finalValue = encrypt(rotatedPlaintext);
      actionLogName = 'Secret Rotated';
    } else if (value) {
      finalValue = encrypt(value);
    }

    const updatedSecret = await prisma.secret.update({
      where: { id },
      data: {
        name: name || existingSecret.name,
        value: finalValue,
        version: existingSecret.version + 1
      }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: actionLogName,
      result: 'SUCCESS',
      details: { secretId: id, name: updatedSecret.name, version: updatedSecret.version }
    });

    return NextResponse.json({
      id: updatedSecret.id,
      name: updatedSecret.name,
      version: updatedSecret.version,
      updatedAt: updatedSecret.updatedAt
    });
  } catch (error) {
    return handleApiError(error);
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:delete');
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');

    if (!id) {
      throw new ApiError(400, 'Secret ID is required');
    }

    const existingSecret = await prisma.secret.findUnique({
      where: { id }
    });

    if (!existingSecret || existingSecret.tenantId !== tenantId) {
      throw new ApiError(404, 'Secret not found');
    }

    await prisma.secret.delete({
      where: { id }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'Secret Deleted',
      result: 'SUCCESS',
      details: { secretId: id, name: existingSecret.name }
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    return handleApiError(error);
  }
}
