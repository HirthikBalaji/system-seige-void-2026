import crypto from 'node:crypto';
import { env } from '../env';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // NIST-recommended nonce size for GCM
const AUTH_TAG_LENGTH = 16;

const masterKek = Buffer.from(env.MASTER_KEK, 'hex');

interface Encrypted {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

function encrypt(key: Buffer, plaintext: Buffer): Encrypted {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv, authTag };
}

function decrypt(key: Buffer, ciphertext: Buffer, iv: Buffer, authTag: Buffer): Buffer {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Generates a fresh random 32-byte Data Encryption Key for one secret. */
export function generateDek(): Buffer {
  return crypto.randomBytes(32);
}

/** Encrypts a secret's plaintext value with its per-secret DEK. */
export function encryptValue(dek: Buffer, plaintext: Buffer): Encrypted {
  return encrypt(dek, plaintext);
}

/** Decrypts a secret's value given its DEK, IV, and auth tag. */
export function decryptValue(dek: Buffer, ciphertext: Buffer, iv: Buffer, authTag: Buffer): Buffer {
  return decrypt(dek, ciphertext, iv, authTag);
}

/**
 * Wraps (encrypts) a DEK with the master KEK for storage. Packs
 * [iv][authTag][ciphertext] into one buffer since `secrets.wrapped_dek` is a
 * single column.
 */
export function wrapDek(dek: Buffer): Buffer {
  const { ciphertext, iv, authTag } = encrypt(masterKek, dek);
  return Buffer.concat([iv, authTag, ciphertext]);
}

/** Unwraps a DEK previously wrapped with `wrapDek`. */
export function unwrapDek(wrapped: Buffer): Buffer {
  const iv = wrapped.subarray(0, IV_LENGTH);
  const authTag = wrapped.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = wrapped.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  return decrypt(masterKek, ciphertext, iv, authTag);
}

/** Best-effort zeroing of key material once it's no longer needed. */
export function wipe(buf: Buffer): void {
  buf.fill(0);
}
