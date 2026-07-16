export type CertStatus = 'active' | 'expiring_soon' | 'expired';

const EXPIRING_SOON_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

export function computeStatus(expiresAt: Date, now: Date = new Date()): CertStatus {
  const msUntilExpiry = expiresAt.getTime() - now.getTime();
  if (msUntilExpiry < 0) return 'expired';
  if (msUntilExpiry <= EXPIRING_SOON_WINDOW_MS) return 'expiring_soon';
  return 'active';
}
