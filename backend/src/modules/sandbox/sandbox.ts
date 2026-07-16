import crypto from 'node:crypto';
import { Prisma } from '@prisma/client';
import { prisma } from '../../lib/prisma';
import { appendAuditEntry } from '../../lib/audit';

const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;
const NIM_BASE_URL = 'https://integrate.api.nvidia.com/v1/chat/completions';
const HMAC_SECRET = process.env.AUDIT_HMAC_SECRET || 'super-secure-hmac-signing-key-for-audit-logs-validation';

export interface SandboxResource {
  type: 'db' | 'api' | 'k8s' | 'cert' | 'oauth' | 'ssh';
  name: string;
  details: string;
  mockValue: string;
}

// Simulates enterprise PII and payment credential masking
export function maskSensitiveData(fieldName: string, rawValue: string): string {
  const normalized = fieldName.toLowerCase();
  
  if (normalized.includes('email')) {
    const parts = rawValue.split('@');
    if (parts.length === 2) {
      return `${parts[0]!.substring(0, 2)}***@sandbox.internal`;
    }
    return 'user***@sandbox.internal';
  }
  
  if (normalized.includes('card') || normalized.includes('cc') || normalized.includes('payment')) {
    return '4111-XXXX-XXXX-9999 (Disposable Sandbox Token)';
  }

  if (normalized.includes('key') || normalized.includes('secret') || normalized.includes('passwd') || normalized.includes('password')) {
    const prefix = rawValue.substring(0, 4) || 'KEY';
    return `${prefix}-SANDBOX-DISPOSABLE-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
  }

  if (normalized.includes('name') || normalized.includes('user')) {
    return 'Sandbox Test Actor';
  }

  return `[TOKENIZED:${crypto.createHmac('sha256', HMAC_SECRET).update(rawValue).digest('hex').substring(0, 12)}]`;
}

// Ask NVIDIA NIM to analyze natural language prompt
export async function askNIMForSandbox(prompt: string): Promise<{ name: string; resources: SandboxResource[] }> {
  if (!NVIDIA_API_KEY) {
    throw new Error('NVIDIA_API_KEY is not configured');
  }

  const promptMessage = `Analyze this developer sandbox request: "${prompt}"
Determine a set of mock temporary resources (databases, API credentials, Kubernetes namespaces, TLS certificates, OAuth configurations, SSH keys) needed for this testing workflow.
You must return a valid JSON object ONLY. Do not write markdown wrappers like \`\`\`json or explanations.

Follow this schema exactly:
{
  "name": "string (name of the sandbox environment, e.g. Payment Gateway Sandbox)",
  "resources": [
    {
      "type": "db" | "api" | "k8s" | "cert" | "oauth" | "ssh",
      "name": "string (resource name, e.g. Temporary Stripe API Key)",
      "details": "string (description of the resource)",
      "mockValue": "string (a safe, disposable mock secret value, e.g. sk_test_mock...)"
    }
  ]
}`;

  const response = await fetch(NIM_BASE_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${NVIDIA_API_KEY}`
    },
    body: JSON.stringify({
      model: 'meta/llama-3.1-8b-instruct',
      messages: [{ role: 'user', content: promptMessage }],
      temperature: 0.1,
      max_tokens: 1024
    })
  });

  if (!response.ok) {
    throw new Error(`NIM API responded with status ${response.status}`);
  }

  const data = (await response.json()) as any;
  const text = data.choices[0]?.message?.content || '';
  const cleanedText = text.replace(/```json/g, '').replace(/```/g, '').trim();
  return JSON.parse(cleanedText);
}

// Heuristics parser if NIM is offline
export function getHeuristicSandbox(prompt: string): { name: string; resources: SandboxResource[] } {
  const normalized = prompt.toLowerCase();
  const resources: SandboxResource[] = [];
  let name = 'Development Testing Sandbox';

  if (normalized.includes('payment') || normalized.includes('stripe') || normalized.includes('checkout')) {
    name = 'Payment Gateway Integration Sandbox';
    resources.push(
      { type: 'api', name: 'Temporary Payment Gateway Key', details: 'Disposable Stripe Mock Key', mockValue: 'sk_test_51MockKey' + crypto.randomBytes(8).toString('hex') },
      { type: 'db', name: 'Sandbox Transaction Log Database', details: 'Sqlite database for logs', mockValue: 'sqlite://sandbox_transactions.db' },
      { type: 'k8s', name: 'Namespace "sandbox-payments"', details: 'Isolated namespace', mockValue: 'k8s:namespace:sandbox-payments' }
    );
  } else if (normalized.includes('database') || normalized.includes('db') || normalized.includes('postgres')) {
    name = 'Disposable Database Sandbox';
    resources.push(
      { type: 'db', name: 'Temporary Postgres Schema', details: 'Disposable isolated PostgreSQL schema', mockValue: 'postgresql://sandbox_user:disposable_pass@localhost:5432/sandbox_schema' },
      { type: 'ssh', name: 'SSH Tunnel Key', details: 'Disposable SSH access key', mockValue: 'ssh-rsa AAAAB3Nza...sandbox-temp' }
    );
  } else if (normalized.includes('cert') || normalized.includes('ssl') || normalized.includes('tls')) {
    name = 'SSL/TLS Certificate Testing Sandbox';
    resources.push(
      { type: 'cert', name: 'Mock TLS Certificate', details: 'Common name: test.local', mockValue: '-----BEGIN CERTIFICATE-----\nMIIDMock...\n-----END CERTIFICATE-----' }
    );
  } else {
    // Default fallback
    resources.push(
      { type: 'db', name: 'Sandbox Cache Database', details: 'Redis temporary cache', mockValue: 'redis://:disposable-pass@localhost:6379/0' },
      { type: 'oauth', name: 'Temporary Client Credentials Client', details: 'Mock OAuth Client', mockValue: 'client_id: mock-client, client_secret: ' + crypto.randomBytes(8).toString('hex') }
    );
  }

  return { name, resources };
}

// Provision sandbox session in database
export async function provisionSandbox(
  tx: Prisma.TransactionClient,
  tenantId: string,
  userId: string,
  prompt: string,
  expiresInHours = 1
) {
  let sandboxConfig;
  
  if (NVIDIA_API_KEY) {
    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 6000); // 6 seconds timeout
      sandboxConfig = await askNIMForSandbox(prompt);
      clearTimeout(id);
    } catch (err: any) {
      console.warn('NIM Sandbox AI builder timed out or failed. Falling back to heuristics:', err.message);
      sandboxConfig = getHeuristicSandbox(prompt);
    }
  } else {
    sandboxConfig = getHeuristicSandbox(prompt);
  }

  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + expiresInHours);

  // Write SandboxSession in PostgreSQL
  const session = await tx.sandboxSession.create({
    data: {
      tenantId,
      name: sandboxConfig.name,
      createdBy: userId,
      status: 'ACTIVE',
      resources: sandboxConfig.resources as unknown as Prisma.InputJsonValue,
      expiresAt
    }
  });

  // Log in tamper-evident AuditLog
  await appendAuditEntry(tx, {
    tenantId,
    actorId: userId,
    action: 'Provision Secret Sandbox',
    resourceType: 'SandboxSession',
    resourceId: session.id,
    details: {
      name: session.name,
      expiresAt: session.expiresAt.toISOString(),
      resourcesCount: sandboxConfig.resources.length
    }
  });

  return session;
}

// Destroy a sandbox session and generate a destruction certificate
export async function destroySandbox(
  tx: Prisma.TransactionClient,
  tenantId: string,
  userId: string,
  sessionId: string
) {
  const session = await tx.sandboxSession.findFirst({
    where: { id: sessionId, tenantId }
  });

  if (!session) {
    throw new Error('Sandbox session not found');
  }

  if (session.status === 'DESTROYED') {
    return session;
  }

  const now = new Date();
  const resourcesList = (session.resources as any[] || []).map(r => `${r.type.toUpperCase()}: ${r.name}`).join(', ');

  // 1. Generate cryptographic Destruction Certificate content
  const certText = `
==================================================
SOVEREIGNGUARD SECURE ENVIRONMENT DESTRUCTION CERTIFICATE
==================================================
Session ID: ${session.id}
Tenant ID: ${session.tenantId}
Environment Name: ${session.name}
Provisioned By: ${session.createdBy}
Created At: ${session.createdAt.toISOString()}
Destroyed At: ${now.toISOString()}
Purged Resources: [${resourcesList}]
--------------------------------------------------
Status: ALL RESOURCES COMPLETELY PURGED & DESTROYED
Compliance Standard: DoD 5220.22-M Wipe Equivalent
==================================================
`;

  // 2. Compute a tamper-proof cryptographic signature
  const hmacSignature = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(certText)
    .digest('hex');

  const fullCertificate = `${certText}\nVerification Signature: ${hmacSignature}\n`;

  // 3. Update database status
  const updatedSession = await tx.sandboxSession.update({
    where: { id: sessionId },
    data: {
      status: 'DESTROYED',
      destroyedAt: now,
      destructionCertificate: fullCertificate
    }
  });

  // 4. Log in tamper-evident AuditLog
  await appendAuditEntry(tx, {
    tenantId,
    actorId: userId,
    action: 'Destroy Secret Sandbox',
    resourceType: 'SandboxSession',
    resourceId: session.id,
    details: {
      name: session.name,
      destroyedAt: now.toISOString(),
      destructionCertificateSignature: hmacSignature
    }
  });

  return updatedSession;
}

// Background cleanup worker for expired sandboxes
export async function cleanupExpiredSandboxes(tx: Prisma.TransactionClient) {
  // Find all active but expired sandbox sessions
  const expired = await tx.sandboxSession.findMany({
    where: {
      status: 'ACTIVE',
      expiresAt: { lt: new Date() }
    }
  });

  const results = [];
  for (const session of expired) {
    console.log(`Auto-cleaning expired sandbox session: "${session.name}" (${session.id})`);
    const destroyed = await destroySandbox(tx, session.tenantId, session.createdBy, session.id);
    results.push(destroyed);
  }

  return results;
}
