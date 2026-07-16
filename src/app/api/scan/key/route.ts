import { NextRequest, NextResponse } from 'next/server';
import { verifyApiRequest, handleApiError } from '@/lib/api-helper';
import { getPublicKeyPem } from '@/lib/scanKeyExchange';

// Hands back the gateway's ephemeral RSA public key so the browser can
// encrypt a personal API key before POSTing it to /api/scan. Requires a
// valid session (same as everything else here) but no specific permission —
// a public key isn't sensitive, this just avoids handing it to anonymous
// requests for no reason.
export async function GET(req: NextRequest) {
  try {
    await verifyApiRequest(req);
    const publicKey = await getPublicKeyPem();
    return NextResponse.json({ publicKey });
  } catch (error) {
    return handleApiError(error);
  }
}
