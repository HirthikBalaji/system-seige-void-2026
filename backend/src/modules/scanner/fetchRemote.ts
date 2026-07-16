import net from 'node:net';

// Allow-list, not deny-list: only well-known raw-content hosts, HTTPS only,
// no redirects followed, response size capped. This is a deliberately
// narrow SSRF mitigation — it does not attempt full DNS-rebinding
// protection, which would need resolving the hostname ourselves and pinning
// the resolved IP for the actual request. Good enough for the demo's "scan
// a repo URL" flow without opening a generic internal-network fetch proxy.
const ALLOWED_HOSTS = new Set(['raw.githubusercontent.com', 'gist.githubusercontent.com']);
const MAX_BYTES = 2 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 10_000;

export class RemoteFetchError extends Error {}

export async function fetchRemoteSource(rawUrl: string): Promise<string> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new RemoteFetchError('invalid url');
  }

  if (url.protocol !== 'https:') {
    throw new RemoteFetchError('only https urls are allowed');
  }
  if (net.isIP(url.hostname)) {
    throw new RemoteFetchError('ip literal hosts are not allowed');
  }
  if (!ALLOWED_HOSTS.has(url.hostname)) {
    throw new RemoteFetchError('host not allowed — only approved raw-content hosts are permitted');
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, { redirect: 'manual', signal: controller.signal });

    if (response.status >= 300 && response.status < 400) {
      throw new RemoteFetchError('redirects are not followed — supply a direct raw-content url');
    }
    if (!response.ok || !response.body) {
      throw new RemoteFetchError('failed to fetch remote source');
    }

    const reader = response.body.getReader();
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BYTES) {
        await reader.cancel();
        throw new RemoteFetchError('remote source exceeds size limit');
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    clearTimeout(timeout);
  }
}
