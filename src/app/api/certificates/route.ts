import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import { callBackend, BackendError } from '@/lib/backendClient';

// Thin proxy over our Express/Postgres certificate lifecycle service. The
// backend tracks lifecycle metadata only (common name / issued-at /
// expires-at / status) — it never stores raw certificate material, so
// `certificateData` from the import form is accepted here for UI
// compatibility but intentionally never forwarded or persisted anywhere.

interface BackendCert {
  id: string;
  name: string | null;
  commonName: string;
  issuedAt: string;
  expiresAt: string;
  status: string;
  autoRenew: boolean;
  createdAt: string;
}

function serializeCert(c: BackendCert) {
  return {
    id: c.id,
    name: c.name ?? c.commonName,
    domain: c.commonName,
    expiresAt: c.expiresAt,
    issuedAt: c.issuedAt,
    status: c.status,
    autoRenew: c.autoRenew,
    createdAt: c.createdAt,
  };
}

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'certs:read');
    const identity = { tenantId, userId: user.id, role: user.role };

    const { certificates } = await callBackend<{ certificates: BackendCert[] }>('/internal/certs', identity);
    return NextResponse.json(certificates.map(serializeCert));
  } catch (error) {
    return handleApiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'certs:import');
    const body = await req.json();
    const { name, domain, certificateData, expiresAt } = body;

    if (!name || !domain || !certificateData || !expiresAt) {
      throw new ApiError(400, 'Name, Domain, Certificate Data, and Expiration Date are required');
    }

    const identity = { tenantId, userId: user.id, role: user.role };
    const created = await callBackend<BackendCert>('/internal/certs', identity, {
      method: 'POST',
      body: { name, commonName: domain, expiresAt: new Date(expiresAt).toISOString() },
    });

    return NextResponse.json(serializeCert(created));
  } catch (error) {
    return handleApiError(error);
  }
}

export async function PUT(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'certs:renew');
    const body = await req.json();
    const { id } = body;

    if (!id) {
      throw new ApiError(400, 'Certificate ID is required');
    }

    const identity = { tenantId, userId: user.id, role: user.role };
    try {
      const renewed = await callBackend<BackendCert>(`/internal/certs/${id}/renew`, identity, { method: 'PATCH' });
      return NextResponse.json(serializeCert(renewed));
    } catch (err) {
      if (err instanceof BackendError && err.status === 404) {
        throw new ApiError(404, 'Certificate not found');
      }
      throw err;
    }
  } catch (error) {
    return handleApiError(error);
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'certs:delete');
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');

    if (!id) {
      throw new ApiError(400, 'Certificate ID is required');
    }

    const identity = { tenantId, userId: user.id, role: user.role };
    try {
      await callBackend(`/internal/certs/${id}`, identity, { method: 'DELETE' });
    } catch (err) {
      if (err instanceof BackendError && err.status === 404) {
        throw new ApiError(404, 'Certificate not found');
      }
      throw err;
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    return handleApiError(error);
  }
}
