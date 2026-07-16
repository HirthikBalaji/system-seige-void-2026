#!/usr/bin/env node
// DEV/TEST ONLY. Mints a JWT signed with our own JWT_SECRET so this service
// can be exercised locally without the auth team's real issuance flow. This
// is not part of the running server and must never be deployed or exposed —
// token *issuance* is explicitly the auth team's responsibility, not ours.
//
// Usage: node --env-file=.env scripts/mint-dev-token.mjs [role] [tenantId] [userId]
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

const role = process.argv[2] ?? 'admin';
const tenantId = process.argv[3] ?? crypto.randomUUID();
const userId = process.argv[4] ?? crypto.randomUUID();

if (!process.env.JWT_SECRET) {
  console.error('JWT_SECRET not set — run with: node --env-file=.env scripts/mint-dev-token.mjs');
  process.exit(1);
}

const token = jwt.sign(
  { tenant_id: tenantId, user_id: userId, role },
  process.env.JWT_SECRET,
  { algorithm: 'HS256', expiresIn: '1h' },
);

console.log(JSON.stringify({ token, tenantId, userId, role }, null, 2));
