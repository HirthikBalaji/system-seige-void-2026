import { z } from 'zod';

// Fail fast at startup rather than at first request — a misconfigured
// secret here is a total compromise waiting to happen, not a 500 to retry.
const envSchema = z.object({
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  MASTER_KEK: z
    .string()
    .regex(/^[0-9a-f]{64}$/i, 'MASTER_KEK must be 64 hex chars (32 bytes) — generate with `openssl rand -hex 32`'),
  LLM_API_KEY: z.string().min(1, 'LLM_API_KEY is required'),
  PORT: z.coerce.number().int().positive().default(4000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

function loadEnv() {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    console.error('Invalid environment configuration:');
    for (const issue of parsed.error.issues) {
      console.error(`  - ${issue.path.join('.')}: ${issue.message}`);
    }
    process.exit(1);
  }
  return parsed.data;
}

export const env = loadEnv();
