import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import { callBackend, BackendError } from '@/lib/backendClient';
import crypto from 'crypto';

// Thin proxy over our Express/Postgres vault service — see backend/. This
// route no longer does its own encryption or storage; it only resolves the
// gateway session, mints a scoped JWT, and translates between the
// dashboard's existing contract and the backend's actual one.

interface BackendSecretMeta {
  id: string;
  name: string;
  version: number;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

interface BackendSecretValue {
  id: string;
  name: string;
  value: string;
  version: number;
}

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'secrets:read');
    const identity = { tenantId, userId: user.id, role: user.role };
    const { searchParams } = new URL(req.url);
    const secretId = searchParams.get('id');
    const reveal = searchParams.get('reveal') === 'true';

    if (secretId) {
      if (reveal) {
        try {
          const secret = await callBackend<BackendSecretValue>(`/internal/vault/secrets/${secretId}`, identity);
          return NextResponse.json(secret);
        } catch (err) {
          if (err instanceof BackendError && err.status === 404) {
            throw new ApiError(404, 'Secret not found');
          }
          throw err;
        }
      }

      const { secrets } = await callBackend<{ secrets: BackendSecretMeta[] }>('/internal/vault/secrets', identity);
      const found = secrets.find((s) => s.id === secretId);
      if (!found) throw new ApiError(404, 'Secret not found');
      return NextResponse.json({ ...found, value: '********' });
    }

    const { secrets } = await callBackend<{ secrets: BackendSecretMeta[] }>('/internal/vault/secrets', identity);
    return NextResponse.json(secrets.map((s) => ({ ...s, value: '********' })));
  } catch (error) {
    return handleApiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'secrets:create');
    const body = await req.json();
    const { name, value } = body;

    if (!name || !value) {
      throw new ApiError(400, 'Name and Value are required');
    }

    const identity = { tenantId, userId: user.id, role: user.role };
    const created = await callBackend('/internal/vault/secrets', identity, {
      method: 'POST',
      body: { name, value },
    });

    return NextResponse.json(created);
  } catch (error) {
    return handleApiError(error);
  }
}

export async function PUT(req: NextRequest) {
  try {
    const body = await req.json();
    const { id, value, action } = body;

    if (!id) {
      throw new ApiError(400, 'Secret ID is required');
    }

    const requiredPermission = action === 'rotate' ? 'secrets:rotate' : 'secrets:update';
    const { tenantId, user } = await verifyApiRequest(req, requiredPermission);
    const identity = { tenantId, userId: user.id, role: user.role };

    // Auto-generate a secure random value for rotation, same as before.
    const finalValue = action === 'rotate' ? crypto.randomBytes(16).toString('hex') : value;
    if (!finalValue) {
      throw new ApiError(400, 'A new value is required to update a secret');
    }

    try {
      const updated = await callBackend(`/internal/vault/secrets/${id}`, identity, {
        method: 'PATCH',
        body: { value: finalValue },
      });
      return NextResponse.json(updated);
    } catch (err) {
      if (err instanceof BackendError && err.status === 404) {
        throw new ApiError(404, 'Secret not found');
      }
      throw err;
    }
  } catch (error) {
    return handleApiError(error);
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'secrets:delete');
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');

    if (!id) {
      throw new ApiError(400, 'Secret ID is required');
    }

    const identity = { tenantId, userId: user.id, role: user.role };
    try {
      await callBackend(`/internal/vault/secrets/${id}`, identity, { method: 'DELETE' });
    } catch (err) {
      if (err instanceof BackendError && err.status === 404) {
        throw new ApiError(404, 'Secret not found');
      }
      throw err;
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    return handleApiError(error);
  }
}
