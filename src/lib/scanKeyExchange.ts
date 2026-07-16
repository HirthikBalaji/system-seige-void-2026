import crypto from 'crypto';

/**
 * Lets a visitor test the AI scanner against their own Anthropic key instead
 * of the shared one in backend/.env (useful when other teams are poking at
 * a live demo and you don't want their usage on your bill). The key has to
 * cross the browser → gateway hop in the open otherwise, which is exactly
 * what a proxy like Burp Suite is built to inspect — so it's RSA-OAEP
 * encrypted client-side against a public key before it ever leaves the
 * browser, and only decrypted here, server-side, for the single request
 * that needs it.
 *
 * The keypair is generated fresh in memory when this process starts and is
 * never written to disk or logged. It's process-lifetime, not per-request —
 * regenerating per-request would be needless overhead for what this
 * actually defends against (a passive network observer on the wire), and
 * restarting the dev server rotates it anyway. This is a real cryptographic
 * boundary against wire-level inspection; it is not a substitute for
 * serving the app over HTTPS in production, which you should still do.
 *
 * Stored on `globalThis` rather than a plain module-level variable — same
 * reason src/lib/prisma.ts does this. Next.js dev (Turbopack in particular)
 * doesn't guarantee that two different route files importing this module
 * share one module instance; `globalThis` is the one thing guaranteed to
 * survive across route bundles within the same Node process, which matters
 * a lot here since the public key hand-out and the private-key decrypt
 * happen in two separate route files and MUST use the same keypair.
 */
declare global {
  // eslint-disable-next-line no-var
  var scanKeyPairPromise: Promise<{ publicKey: string; privateKey: string }> | undefined;
}

function generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
  return new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'rsa',
      {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, publicKey, privateKey) => {
        if (err) reject(err);
        else resolve({ publicKey, privateKey });
      },
    );
  });
}

function getKeyPair() {
  if (!globalThis.scanKeyPairPromise) {
    globalThis.scanKeyPairPromise = generateKeyPair();
  }
  return globalThis.scanKeyPairPromise;
}

export async function getPublicKeyPem(): Promise<string> {
  const { publicKey } = await getKeyPair();
  return publicKey;
}

/** Decrypts a base64 RSA-OAEP(SHA-256) ciphertext produced by the browser. */
export async function decryptApiKey(encryptedBase64: string): Promise<string> {
  const { privateKey } = await getKeyPair();
  const plaintext = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encryptedBase64, 'base64'),
  );
  return plaintext.toString('utf8');
}
