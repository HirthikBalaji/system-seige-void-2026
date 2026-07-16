# SovereignGuard 🛡️

SovereignGuard is a highly secure, enterprise-grade multi-tenant secrets and TLS/SSL certificate lifecycle control plane. It integrates directly with **Cloudflare Access (Cloudflare Zero Trust)** for identity verification and implements strict application-level RBAC, tenant isolation, dual-protected audit logs, and AI-powered credentials exposure scanning.

## Architecture

Two services:

- **This Next.js app (repo root)** — the gateway: Cloudflare Access / sandbox authentication, sessions, tenant/user management, and the dashboard UI. Backed by its own SQLite database (`prisma/schema.prisma`).
- **[`backend/`](backend/README.md)** — a separate Express + PostgreSQL service that owns the actual secrets vault, certificate lifecycle, hash-chained audit trail, and AI scanner. This is where envelope encryption, Row-Level Security, and tamper-evidence actually live.

The four resource-facing API routes (`/api/secrets`, `/api/certificates`, `/api/audit-logs`, `/api/scan`) are thin proxies: they resolve the caller's session the same way they always did, then mint a short-lived, internally-signed JWT (`src/lib/backendClient.ts`) carrying the verified `tenant_id` / `user_id` / `role` and forward the request to the backend — mirroring the trust-boundary model the backend was designed around (gateway authenticates, backend independently re-verifies). `/api/auth/*` and `/api/users` are untouched and still talk directly to this app's own SQLite database, since those areas (identity, session, org membership) were never in the backend's scope.

---

## 🚀 AI / LLM Integration Disclosure (BYOK)

As required by the System Siege problem guidelines, the AI-powered scanner (now implemented in `backend/`) utilizes:
- **LLM Provider**: Anthropic
- **Model Version**: `claude-haiku-4-5-20251001` (see `backend/src/modules/scanner/llm.ts`, overridable via `LLM_MODEL`)
- **Purpose**: A deterministic regex/entropy pre-filter finds candidates first (no LLM call yet); only then does a real LLM call classify each candidate as a confirmed leak vs. false positive, assign severity, and suggest remediation. Only a **masked** snippet plus a few lines of context ever leaves the process — the full candidate value is never sent to the LLM or stored.
- **Key Configuration**: Provide your key via `backend/.env`'s `LLM_API_KEY`. If the LLM call fails, the response is honest about it (`isMocked: true`) rather than silently passing off pre-filter output as an LLM verdict.

---

## 🔒 Security Architecture

1. **Zero Trust Authentication** (this app):
   - Single Source of Truth: Cloudflare Access.
   - Strictly validates `CF-Access-Jwt-Assertion` signatures against Cloudflare's JWKS certificates.
   - Verifies issuer (`iss`), audience (`aud`), expiration (`exp`), and nbf claims.
   - Extracts identity claims (Email, Subject, Groups, Identity Provider).

2. **Session Management** (this app):
   - Validates Cloudflare assertion to create a secure, server-side database-backed Session.
   - Uses strict browser cookies: `HttpOnly`, `Secure` (production), `SameSite=Strict`, `2h MaxAge`.
   - Allows administrators to revoke sessions in real-time.

3. **Strict Multi-Tenant Isolation**:
   - Users are dynamically resolved to a Tenant (organization) on first login via Cloudflare groups (`tenant-<org>`), Identity Provider name, or email domain.
   - The backend enforces tenant isolation twice, independently: every query is explicitly scoped by the verified `tenant_id`, *and* PostgreSQL Row-Level Security blocks cross-tenant rows even if an app-layer scope check were ever missed. See `backend/README.md`.

4. **Role-Based Access Control (RBAC)**:
   - Defined roles: `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ADMIN`, `DEVELOPER`, `AUDITOR`, `READ_ONLY`, `SERVICE_ACCOUNT`.
   - Mapped onto the backend's 4-tier permission model (`read` / `write` / `audit`) in `src/lib/backendClient.ts` — a genuine permission mapping, not a role rounded up to a broader one than it actually has (e.g. `AUDITOR` gets audit access without secrets/cert write access, which a simple linear hierarchy couldn't express).

5. **Hash-Chained, Append-Only Audit Trail** (backend):
   - A single SHA-256 hash chain spans every tenant on the platform — a break anywhere is detectable from anywhere, by design.
   - Enforced append-only at the database level (a trigger rejects `UPDATE`/`DELETE` outright, even for the table owner), not just by application convention.
   - `GET /api/audit-logs?verify=true` walks the entire chain and recomputes every hash from genesis, returning whether it's still intact and — if not — the exact broken record.
   - This gateway also keeps its own, separate SQLite trail (`AuditLog` in `prisma/schema.prisma`) for auth events (login, logout, permission-denied) — that one isn't hash-chained and isn't shown in the dashboard's Audit tab, which is specifically the backend's tamper-evident trail.

6. **Secrets Encryption** (backend):
   - Envelope encryption: a fresh random Data Encryption Key per secret (AES-256-GCM), itself wrapped by a single master Key Encryption Key. Real cryptography, not a single static key reused across every secret.

---

## 🛠️ Getting Started

Requires Node.js 20+, npm, and Docker Desktop (for the backend's Postgres).

### 1. Start the backend first

```bash
cd backend
cp .env.example .env
# Fill in real values in backend/.env: MASTER_KEK and JWT_SECRET via
# `openssl rand -hex 32` each, POSTGRES_OWNER_PASSWORD / APP_DB_PASSWORD to
# any strings, and LLM_API_KEY with a real Anthropic API key.
docker compose up -d postgres
npm install
npm run migrate:dev     # creates tables (owner role)
npm run harden:db        # applies RLS policies, append-only trigger, role grants
npm run dev              # backend listening on :4000
```

Full detail on why there are two Postgres roles, the RLS design, and the hash chain is in [`backend/README.md`](backend/README.md).

### 2. Then this app, in a second terminal

```bash
# from the repo root
cp .env.example .env   # if it doesn't already exist
npm install
npx prisma generate
npx prisma migrate dev   # only needed the first time / after a schema change
npm run dev               # gateway + dashboard on :3000
```

Set `BACKEND_JWT_SECRET` in the root `.env` to the **exact same value** as `backend/.env`'s `JWT_SECRET` — this is the shared secret that lets the backend trust JWTs this gateway mints. If they don't match, every proxied request fails with 401. `BACKEND_URL` defaults to `http://localhost:4000`.

### 3. Open it

Open [http://localhost:3000](http://localhost:3000).
- In **Sandbox Mode** (`NEXT_PUBLIC_MOCK_CF_ACCESS=true`, the default), you'll see the **Developer Sandbox Login Portal**. Select any pre-defined persona (e.g. Org Admin, Developer, Auditor, or a different organization) to test RBAC and tenant isolation instantly — no real Cloudflare Access setup needed.
- In **Production Mode**, you'll be redirected to authenticate through Cloudflare Access.

Try: create a secret as **Developer**, reveal/rotate it, switch to the **Auditor** persona and confirm you can see the audit trail and hit "Verify Chain Integrity" but can't create secrets, then switch to **Beta Corp • Developer** and confirm Acme Corp's secrets are invisible.
