import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import { callBackend } from '@/lib/backendClient';
import { logEvent } from '@/lib/audit';

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:read');
    const { searchParams } = new URL(req.url);
    const action = searchParams.get('action');

    const identity = { tenantId, userId: user.id, role: user.role };

    if (action === 'timelock-secrets') {
      const result = await callBackend<any>('/internal/cyber/timelock/secrets', identity);
      return NextResponse.json(result);
    } else if (action === 'workload-identities') {
      const result = await callBackend<any>('/internal/cyber/workload/identities', identity);
      return NextResponse.json(result);
    } else if (action === 'revocations') {
      const result = await callBackend<any>('/internal/cyber/revocations', identity);
      return NextResponse.json(result);
    } else if (action === 'digitaltwin-graph') {
      const result = await callBackend<any>('/internal/cyber/digitaltwin/graph', identity);
      return NextResponse.json(result);
    } else if (action === 'digitaltwin-simulations') {
      const result = await callBackend<any>('/internal/cyber/digitaltwin/simulations', identity);
      return NextResponse.json(result);
    } else if (action === 'federated-rules') {
      const result = await callBackend<any>('/internal/cyber/federated/rules', identity);
      return NextResponse.json(result);
    } else if (action === 'riskcards') {
      const result = await callBackend<any>('/internal/cyber/riskcards', identity);
      return NextResponse.json(result);
    } else {
      throw new ApiError(400, 'Invalid action specified');
    }
  } catch (error) {
    return handleApiError(error);
  }
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user, ipAddress, userAgent } = await verifyApiRequest(req, 'secrets:write');
    const { searchParams } = new URL(req.url);
    const action = searchParams.get('action');
    const body = await req.json().catch(() => ({}));

    const identity = { tenantId, userId: user.id, role: user.role };

    let result;

    if (action === 'timelock-create') {
      result = await callBackend<any>('/internal/cyber/timelock/secrets', identity, {
        method: 'POST',
        body,
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Create Time-Locked Secret',
        result: 'SUCCESS',
        details: { name: body.name, expiresAt: body.expiresAt, provider: body.provider },
      });
    } else if (action === 'timelock-decrypt') {
      result = await callBackend<any>(`/internal/cyber/timelock/decrypt/${body.id}`, identity, {
        method: 'POST',
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Decrypt Time-Locked Secret',
        result: 'SUCCESS',
        details: { secretId: body.id, name: result.name },
      });
    } else if (action === 'workload-register') {
      result = await callBackend<any>('/internal/cyber/workload/register', identity, {
        method: 'POST',
        body,
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Register Workload Identity',
        result: 'SUCCESS',
        details: { name: body.name, type: body.type, attestationType: body.attestationType },
      });
    } else if (action === 'workload-attest') {
      result = await callBackend<any>('/internal/cyber/workload/attest', identity, {
        method: 'POST',
        body,
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Attest Workload Identity',
        result: 'SUCCESS',
        details: { workloadId: body.workloadId },
      });
    } else if (action === 'workload-revoke') {
      result = await callBackend<any>('/internal/cyber/workload/revoke', identity, {
        method: 'POST',
        body,
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Revoke Workload Identity/Certificate',
        result: 'SUCCESS',
        details: { serialNumber: body.serialNumber, workloadId: body.workloadId, reason: body.reason },
      });
    } else if (action === 'revocations-trigger') {
      result = await callBackend<any>('/internal/cyber/revocations/trigger-mock', identity, {
        method: 'POST',
        body,
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Trigger Autonomous Revocation Mock',
        result: 'SUCCESS',
        details: { provider: body.provider, findingId: result.finding?.id },
      });
    } else if (action === 'digitaltwin-simulate') {
      result = await callBackend<any>('/internal/cyber/digitaltwin/simulate', identity, {
        method: 'POST',
        body,
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Simulate Blast Radius',
        result: 'SUCCESS',
        details: { startNodeId: body.startNodeId, riskScore: result.riskScore },
      });
    } else if (action === 'federated-aggregate') {
      result = await callBackend<any>('/internal/cyber/federated/aggregate', identity, {
        method: 'POST',
      });

      await logEvent({
        userId: user.id,
        email: user.email,
        tenantId,
        ipAddress,
        userAgent,
        action: 'Aggregate Federated Model Intelligence',
        result: 'SUCCESS',
        details: { rulesCount: result.rulesCount },
      });
    } else {
      throw new ApiError(400, 'Invalid action specified');
    }

    return NextResponse.json(result);
  } catch (error) {
    return handleApiError(error);
  }
}
