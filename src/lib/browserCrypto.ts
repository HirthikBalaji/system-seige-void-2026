// Client-side half of the bring-your-own-key exchange (see
// src/lib/scanKeyExchange.ts for the server side and why this exists).
// Encrypts a plaintext string with the gateway's RSA-OAEP public key using
// the browser's native Web Crypto API — the key never leaves the browser
// unencrypted, so a proxy sitting on the wire (Burp Suite, etc.) only ever
// sees ciphertext.

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export async function encryptWithPublicKeyPem(pem: string, plaintext: string): Promise<string> {
  const key = await window.crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(pem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    key,
    new TextEncoder().encode(plaintext),
  );
  return arrayBufferToBase64(encrypted);
}
