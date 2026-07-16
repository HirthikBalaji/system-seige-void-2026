import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError } from '@/lib/api-helper';
import { callBackend } from '@/lib/backendClient';

// Thin proxy over our Express/Postgres hash-chained audit log — this is the
// platform's real tamper-evident trail (see backend/src/lib/audit.ts). The
// gateway's own SQLite audit.ts / logEvent() keeps logging auth events
// (login, logout, permission-denied) separately and is not surfaced here;
// this tab is specifically about the secrets/certs/scanner audit trail the
// hackathon problem statement asks for.

interface BackendAuditEntry {
  id: string;
  tenantId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  details: unknown;
  createdAt: string;
}

export async function GET(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'audit:view');
    const identity = { tenantId, userId: user.id, role: user.role };
    const { searchParams } = new URL(req.url);
    const verify = searchParams.get('verify') === 'true';

    if (verify) {
      const result = await callBackend<{ valid: boolean; brokenAtId: number | null; totalRecords: number }>(
        '/internal/audit/verify',
        identity,
      );

      return NextResponse.json({
        valid: result.valid,
        totalRecords: result.totalRecords,
        errors: result.valid
          ? []
          : [
              {
                id: String(result.brokenAtId),
                index: result.brokenAtId ?? 0,
                error: 'Hash chain broken at this record — its entry_hash no longer matches the recomputed value.',
              },
            ],
      });
    }

    const { entries } = await callBackend<{ entries: BackendAuditEntry[] }>('/internal/audit/log?limit=200', identity);

    return NextResponse.json(
      entries.map((e) => ({
        id: e.id,
        timestamp: e.createdAt,
        action: e.action,
        resourceType: e.resourceType,
        resourceId: e.resourceId,
        details: JSON.stringify(e.details ?? {}),
      })),
    );
  } catch (error) {
    return handleApiError(error);
  }
}
