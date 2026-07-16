import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import prisma from '@/lib/prisma';
import { logEvent } from '@/lib/audit';

export async function GET(req: NextRequest) {
  try {
    const { tenantId } = await verifyApiRequest(req, 'certs:read');
    
    const certs = await prisma.certificate.findMany({
      where: { tenantId },
      orderBy: { expiresAt: 'asc' }
    });

    return NextResponse.json(certs);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'certs:import');
    const body = await req.json();
    const { name, domain, certificateData, expiresAt } = body;

    if (!name || !domain || !certificateData || !expiresAt) {
      throw new ApiError(400, 'Name, Domain, Certificate Data, and Expiration Date are required');
    }

    const cert = await prisma.certificate.create({
      data: {
        name,
        domain,
        certificateData,
        expiresAt: new Date(expiresAt),
        status: 'ACTIVE',
        tenantId
      }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'Certificate Imported',
      result: 'SUCCESS',
      details: { certId: cert.id, domain }
    });

    return NextResponse.json(cert);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function PUT(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'certs:renew');
    const body = await req.json();
    const { id, certificateData, expiresAt } = body;

    if (!id) {
      throw new ApiError(400, 'Certificate ID is required');
    }

    const existingCert = await prisma.certificate.findUnique({
      where: { id }
    });

    if (!existingCert || existingCert.tenantId !== tenantId) {
      throw new ApiError(404, 'Certificate not found');
    }

    const newExpiresAt = expiresAt ? new Date(expiresAt) : new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    const newCertData = certificateData || existingCert.certificateData;

    const updatedCert = await prisma.certificate.update({
      where: { id },
      data: {
        certificateData: newCertData,
        expiresAt: newExpiresAt,
        status: 'ACTIVE'
      }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'Certificate Renewed',
      result: 'SUCCESS',
      details: { certId: id, domain: existingCert.domain, newExpiration: newExpiresAt }
    });

    return NextResponse.json(updatedCert);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'certs:delete');
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');

    if (!id) {
      throw new ApiError(400, 'Certificate ID is required');
    }

    const existingCert = await prisma.certificate.findUnique({
      where: { id }
    });

    if (!existingCert || existingCert.tenantId !== tenantId) {
      throw new ApiError(404, 'Certificate not found');
    }

    await prisma.certificate.delete({
      where: { id }
    });

    await logEvent({
      userId: user.id,
      email: user.email,
      tenantId,
      ipAddress,
      userAgent,
      action: 'Certificate Deleted',
      result: 'SUCCESS',
      details: { certId: id, domain: existingCert.domain }
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    return handleApiError(error);
  }
}
