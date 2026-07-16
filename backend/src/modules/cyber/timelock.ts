import crypto from 'node:crypto';
import { HttpError } from '../../middleware/errorHandler';

export interface TimeLockMetadata {
  provider: 'ephemeral' | 'vdf';
  algorithm: string;
  iv: string;
  authTag: string;
  expiresAt: string;
  // Provider-specific details
  vdfIterations?: number;
  vdfChallenge?: string;
}

// In-memory key store for ephemeral time-lock keys (mocking a HSM/key vault)
// In production, these are stored in a secure hardware enclave or vault with automatic deletion policy
const ephemeralKeyStore = new Map<string, Buffer>();

// Periodic cleanup of expired keys from memory
setInterval(() => {
  const now = new Date();
  for (const [key, value] of ephemeralKeyStore.entries()) {
    // We parse the secretId/expiresAt combination from the key
    const parts = key.split(':');
    if (parts.length === 2) {
      const expiresAtStr = parts[1]!;
      const expiresAt = new Date(expiresAtStr);
      if (now > expiresAt) {
        ephemeralKeyStore.delete(key);
        console.log(`[TimeLockManager] Cryptographically deleted expired key for secret ${parts[0]}`);
      }
    }
  }
}, 5000);

export class TimeLockManager {
  /**
   * Encrypts a secret value using a time-locked provider.
   */
  static async encrypt(
    secretId: string,
    plaintext: Buffer,
    expiresAt: Date,
    providerType: 'ephemeral' | 'vdf' = 'ephemeral',
  ): Promise<{ encryptedValue: Buffer; metadata: TimeLockMetadata }> {
    const now = new Date();
    if (expiresAt <= now) {
      throw new HttpError(400, 'Expiration time must be in the future');
    }

    const salt = crypto.randomBytes(16);
    let encryptionKey: Buffer;

    let providerMeta: Partial<TimeLockMetadata> = {};

    if (providerType === 'ephemeral') {
      // Ephemeral key custody: generate random key, save in memory, delete on expiry
      encryptionKey = crypto.randomBytes(32);
      const storeKey = `${secretId}:${expiresAt.toISOString()}`;
      ephemeralKeyStore.set(storeKey, encryptionKey);
    } else {
      // VDF / Time-Lock Puzzle prototype: KDF derived from expiration and secret ID,
      // simulating a puzzle where decryption requires a work proof.
      const iterations = 5000; // Simulated delay parameter
      const challenge = crypto.randomBytes(16).toString('hex');
      
      // Derive key using sequential pbkdf2 to simulate VDF time delay
      encryptionKey = crypto.pbkdf2Sync(
        Buffer.from(challenge),
        salt,
        iterations,
        32,
        'sha256',
      );

      providerMeta = {
        vdfIterations: iterations,
        vdfChallenge: challenge,
      };
    }

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const metadata: TimeLockMetadata = {
      provider: providerType,
      algorithm: 'aes-256-gcm',
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      expiresAt: expiresAt.toISOString(),
      ...providerMeta,
    };

    return {
      encryptedValue: encrypted,
      metadata,
    };
  }

  /**
   * Decrypts a secret value if not expired.
   */
  static async decrypt(
    secretId: string,
    encryptedValue: Buffer,
    metadata: TimeLockMetadata,
  ): Promise<Buffer> {
    const expiresAt = new Date(metadata.expiresAt);
    const now = new Date();

    if (now > expiresAt) {
      // Cryptographic purge: delete key if using ephemeral provider
      if (metadata.provider === 'ephemeral') {
        const storeKey = `${secretId}:${metadata.expiresAt}`;
        ephemeralKeyStore.delete(storeKey);
      }
      throw new HttpError(403, 'Cryptographic Time-Lock Expired. The secret is no longer decryptable.');
    }

    let decryptionKey: Buffer;

    if (metadata.provider === 'ephemeral') {
      const storeKey = `${secretId}:${metadata.expiresAt}`;
      const cachedKey = ephemeralKeyStore.get(storeKey);
      if (!cachedKey) {
        throw new HttpError(403, 'Decryption key has been purged from key custody. Secret is cryptographically lost.');
      }
      decryptionKey = cachedKey;
    } else {
      // Recompute KDF (VDF puzzle verify)
      const iterations = metadata.vdfIterations || 5000;
      const challenge = metadata.vdfChallenge || '';
      const salt = Buffer.from(metadata.iv, 'hex'); // use IV as salt for PBKDF2 derivation

      // Simulate VDF solving time
      decryptionKey = crypto.pbkdf2Sync(
        Buffer.from(challenge),
        salt,
        iterations,
        32,
        'sha256',
      );
    }

    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        decryptionKey,
        Buffer.from(metadata.iv, 'hex'),
      );
      decipher.setAuthTag(Buffer.from(metadata.authTag, 'hex'));
      return Buffer.concat([decipher.update(encryptedValue), decipher.final()]);
    } catch (err) {
      throw new HttpError(400, 'Time-lock decryption failed. Key might have been modified or corrupted.');
    }
  }

  /**
   * Helper to register a key for a secret (useful on seed/startup or after rotation)
   */
  static provisionEphemeralKey(secretId: string, expiresAt: Date, key: Buffer) {
    const storeKey = `${secretId}:${expiresAt.toISOString()}`;
    ephemeralKeyStore.set(storeKey, key);
  }
}
