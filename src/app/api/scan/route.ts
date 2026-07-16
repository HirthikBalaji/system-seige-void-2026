import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError, ApiError } from '@/lib/api-helper';
import { callBackend } from '@/lib/backendClient';
import { decryptApiKey } from '@/lib/scanKeyExchange';

// Thin proxy over our Express AI scanner — a real two-stage pipeline
// (deterministic regex/entropy pre-filter, then an actual LLM call with
// only a masked snippet ever leaving the process). Replaces the previous
// implementation, which sent whole, unmasked file content straight to a
// third-party API.

const SECRET_TYPE_LABELS: Record<string, string> = {
  aws_key: 'AWS API Key',
  generic_api_key: 'Generic API Key / Secret',
  private_key: 'Private Key',
  generic_high_entropy: 'High-Entropy Token',
};

function toRisk(severity: string): 'HIGH' | 'MEDIUM' | 'LOW' {
  if (severity === 'critical' || severity === 'high') return 'HIGH';
  if (severity === 'medium') return 'MEDIUM';
  return 'LOW';
}

interface BackendFinding {
  id: string;
  secretType: string;
  matchedSnippet: string;
  severity: string;
  remediation: string;
  line: number;
}

export async function POST(req: NextRequest) {
  try {
    const { tenantId, user } = await verifyApiRequest(req, 'secrets:create');
    const body = await req.json();
    const { text, filename, encryptedApiKey } = body;

    if (!text) {
      throw new ApiError(400, 'Content to scan is required');
    }

    // Bring-your-own-key: the browser encrypted this against our public key
    // (see /api/scan/key) so it never crossed the wire in the clear. We
    // decrypt it here and forward the plaintext to the backend over the
    // trusted internal hop — never logged, never stored.
    let apiKey: string | undefined;
    if (encryptedApiKey) {
      try {
        apiKey = await decryptApiKey(encryptedApiKey);
      } catch {
        throw new ApiError(400, 'Could not decrypt the provided API key — please try again');
      }
    }

    const identity = { tenantId, userId: user.id, role: user.role };
    const result = await callBackend<{ findings: BackendFinding[]; modelUsed: string; isMocked: boolean; usedOwnKey: boolean }>(
      '/internal/scanner/scan',
      identity,
      { method: 'POST', body: { source: filename || 'unnamed_source.txt', content: text, apiKey } },
    );

    const findings = result.findings.map((f) => ({
      type: SECRET_TYPE_LABELS[f.secretType] ?? f.secretType,
      risk: toRisk(f.severity),
      evidence: f.matchedSnippet,
      line: f.line,
      remediation: f.remediation,
    }));

    const safe = findings.length === 0;
    const summary = result.isMocked
      ? `Note: Live AI classification was unavailable — findings below used the local regex/entropy pre-filter only. ${
          safe ? 'No candidates matched.' : `Detected ${findings.length} candidate(s).`
        }`
      : safe
        ? 'No exposed secrets or credentials detected in the code.'
        : `Detected ${findings.length} potential security exposure(s) in file: ${filename || 'unnamed'}.`;

    return NextResponse.json({
      safe,
      findings,
      summary,
      isMocked: result.isMocked,
      modelUsed: result.modelUsed,
      usedOwnKey: result.usedOwnKey,
    });
  } catch (error) {
    return handleApiError(error);
  }
}
