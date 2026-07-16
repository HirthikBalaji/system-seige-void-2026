import crypto from 'crypto';

// The backend's Postgres columns are strictly typed UUID (tenant_id,
// user_id, created_by, actor_id) — deliberately, so those columns can never
// hold anything but a well-formed UUID. Cloudflare Access subjects (and our
// sandbox's `cf_<email>` mock ids) aren't UUID-shaped, so rather than loosen
// the backend's validation (a real input-trust boundary), we deterministically
// derive a stable UUID from the external id here at the gateway. Same input
// always maps to the same UUID, so a given user/tenant gets a stable
// identity in the backend across requests without ever needing to persist
// a mapping table.
//
// This is a standard RFC 4122 v5 UUID (name-based, SHA-1) using a fixed,
// private namespace UUID — there's no published registration for this
// namespace because it only needs to be consistent within this app.
const NAMESPACE = 'b7c9e2b0-1c3a-4e9a-9d1b-2f7a8e6c4d10';

function toBytes(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ''), 'hex');
}

function toUuidString(bytes: Buffer): string {
  const hex = bytes.toString('hex');
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join('-');
}

/** Deterministically derives a stable UUIDv5 from an arbitrary external id string. */
export function deriveUuid(seed: string): string {
  const hash = crypto.createHash('sha1').update(toBytes(NAMESPACE)).update(seed, 'utf8').digest();
  const bytes = Buffer.from(hash.subarray(0, 16));

  // Set version (5) and variant (RFC 4122) bits per spec.
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  return toUuidString(bytes);
}
