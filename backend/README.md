# Secrets & Certificate Lifecycle Platform — Backend

Backend services for PS-006 ("System Siege"): vault, certificate lifecycle, audit log, and
AI-powered credential scanner. This is the `/internal/*` layer that sits behind the API
gateway/auth team's service — see [API contract](#api-contract-for-the-gateway-team) below.

## AI/LLM disclosure (BYOK, required by hackathon rules)

The scanner's Stage 2 classification calls the **Anthropic Messages API** directly over HTTPS
using a real API key (`LLM_API_KEY`, BYOK, never committed). Model used:

- **Provider:** Anthropic
- **Model:** `claude-haiku-4-5-20251001` (overridable via `LLM_MODEL`)
- **What it does:** classifies each Stage-1 candidate as `confirmed_leak` vs
  `likely_false_positive`, assigns a severity, and writes one remediation sentence. This is real
  classification work on every candidate — Stage 1 (regex + Shannon entropy) is deterministic
  pre-filtering only and never itself produces a verdict.

See [src/modules/scanner/llm.ts](src/modules/scanner/llm.ts).

## Trust boundary

This service independently verifies the `Authorization: Bearer <JWT>` header on every request —
it does **not** trust any pre-decoded `X-Tenant-Id` / `X-User-Id` / `X-Role` header. If one of
those headers ever arrives, the request is rejected outright (see
[src/middleware/auth.ts](src/middleware/auth.ts)) rather than silently ignored, because its
presence means something upstream of us is broken.

`tenant_id`, `user_id`, and `role` are extracted only from verified JWT claims (HS256 pinned
explicitly — the token's own `alg` header is never trusted) and every DB query is scoped by that
verified `tenant_id`, with Postgres Row-Level Security as an independent second layer.

## Why there are two Postgres roles

Prisma migrations run as `platform_owner`; the running server connects as `app_user`. This is
not incidental — **Postgres table owners bypass Row-Level Security by default**, even when RLS
is enabled on the table. If the app ever connected as the owner, every RLS policy in
[prisma/hardening.sql](prisma/hardening.sql) would be silently inert while looking like it
worked. `app_user` has no DDL rights, no ownership, and is the only role permitted to serve
traffic — see `docker/init/00-create-app-role.sh` and the top of `prisma/hardening.sql` for the
full rationale.

## Setup

Requires Docker Desktop and Node 20+.

```bash
cp .env.example .env       # then fill in real values — MASTER_KEK, JWT_SECRET (coordinate
                            # the exact value with the auth team), LLM_API_KEY
npm install
docker compose up -d postgres
npm run migrate:dev        # creates tables as platform_owner (owner role)
npm run harden:db          # applies RLS policies, append-only trigger, app_user grants
npm run dev                # starts the server on $PORT (default 4000)
```

`.env` is gitignored from the first commit — never commit it. `MASTER_KEK` is generated with
`openssl rand -hex 32`; rotating it means re-wrapping every stored DEK, so treat it as a
long-lived secret (a real secrets manager in production, not a `.env` file).

## Data model & security layers

- **Envelope encryption** (vault): per-secret DEK (fresh random 32 bytes), AES-256-GCM. The DEK
  itself is wrapped with a single master KEK (also AES-256-GCM) and stored as `wrapped_dek`. Only
  `node:crypto` — no third-party crypto libraries.
- **Row-Level Security** on all four tables, keyed on `current_setting('app.current_tenant')`,
  set via a parameterized `set_config(...)` call inside the same transaction as every request
  (see [src/lib/withTenantTx.ts](src/lib/withTenantTx.ts)) — not string-interpolated `SET LOCAL`,
  which would be the one place in this codebase that couldn't be parameterized. Tables are also
  `FORCE ROW LEVEL SECURITY`, so even the owner role would be bound by policy if it ever queried
  them directly.
  - If `app.current_tenant` is ever left unset, `current_setting(..., true)` returns `NULL`,
    and `tenant_id = NULL` is never true — the failure mode is **zero rows**, not "every tenant's
    rows."
- **Audit log:** append-only at the DB level (trigger rejects UPDATE/DELETE outright; `app_user`
  also has no UPDATE/DELETE grant on the table at all — two independent layers, not one). Every
  mutating vault/cert/scanner action writes its audit row in the same transaction as the
  underlying change.
- **Global hash chain:** a single SHA-256 chain spans every tenant (by design — see
  `BACKEND_BRIEF.md` and `prisma/hardening.sql`). Appends are serialized with a Postgres advisory
  lock (`pg_advisory_xact_lock`) so concurrent writes from different tenants can't both read the
  same "last row" and fork the chain. Reading the true last row for `prev_hash` requires
  bypassing RLS by design (the chain is deliberately cross-tenant); this is done through a
  narrow `SECURITY DEFINER` function that returns only `(id, hash)` — never any tenant's actual
  audit data — so it can't leak anything through that bypass.

### A known trade-off: `GET /internal/audit/verify` is platform-wide

Because the chain is global, verifying it requires walking every tenant's rows in id order —
there's no way to prove the chain intact using only one tenant's slice of it. This endpoint is
gated to the `admin` role and its response is intentionally minimal
(`{ valid: boolean, brokenAtId: number | null }` — a bare boolean and an opaque integer, never
`tenant_id`/`action`/`resource_id`/`details`), so a tenant's admin learns whether *the platform's*
chain is intact, not what any other tenant did. This is still a departure from "complete tenant
isolation" in the strict sense, driven directly by the brief's "single global chain" requirement.
**Recommend revisiting before judging** whether this should instead be restricted to a
platform-operator role that's distinct from any tenant's own admin, rather than exposed through
the multi-tenant gateway to every tenant.

### AI scanner — repo URL SSRF mitigation

`POST /internal/scanner/scan` accepts either raw `content` or a `repoUrl`. Fetching an
arbitrary user-supplied URL from the server is an SSRF vector, so `repoUrl` is restricted to an
explicit host allow-list (`raw.githubusercontent.com`, `gist.githubusercontent.com`), HTTPS only,
IP-literal hostnames rejected, redirects not followed, response capped at 2 MB with a 10s
timeout. See [src/modules/scanner/fetchRemote.ts](src/modules/scanner/fetchRemote.ts). This is a
narrow mitigation (no DNS-rebinding protection) sized for the demo's scope, not a general-purpose
fetch proxy.

Only the **masked** snippet (e.g. `AKIA****************WXYZ`) is ever sent to the LLM or stored
in `scan_findings` — the raw candidate value never leaves the pre-filter step.

## Role matrix

| Role | Secrets/Certs | Audit log & chain verify |
|---|---|---|
| `viewer` | read-only | no access |
| `operator` | read/write | no access |
| `admin` | read/write | full access |

Coordinate the final matrix with the auth team — this is the working assumption used throughout.

## API contract for the gateway team

All routes below are mounted under `/internal/*` and expect the original, still-signed
`Authorization: Bearer <JWT>` header forwarded as-is (not pre-decoded).

```
POST   /internal/vault/secrets          create                        (operator+)
GET    /internal/vault/secrets          list (metadata only)          (viewer+)
GET    /internal/vault/secrets/:id      get, decrypted                (viewer+)
PATCH  /internal/vault/secrets/:id      update (bumps version)        (operator+)
DELETE /internal/vault/secrets/:id      delete                        (operator+)

POST   /internal/certs                  register                      (operator+)
GET    /internal/certs                  list, computed status         (viewer+)
GET    /internal/certs/:id              get                           (viewer+)
PATCH  /internal/certs/:id/renew        renew                         (operator+)

GET    /internal/audit/log              paginated, tenant-scoped      (admin)
GET    /internal/audit/verify           platform-wide chain verify    (admin)

POST   /internal/scanner/scan           scan content or repoUrl        (operator+)
GET    /internal/scanner/findings       list, tenant-scoped           (viewer+)

GET    /internal/health                 unauthenticated liveness probe
```

Every error response is `{"error": "<generic message>"}` — never a stack trace, SQL error, or
internal path. 401 = missing/invalid JWT, 403 = valid JWT but insufficient role, 400 = failed
zod validation (including a rejected `X-Tenant-Id`-style header), 404 = not found or not in your
tenant (these are intentionally indistinguishable from the outside).

## Testing the tamper-evidence claim

```bash
# after generating a few audit rows through normal use:
docker compose exec postgres psql -U platform_owner -d secrets_platform \
  -c "UPDATE audit_log SET action = 'tampered' WHERE id = (SELECT MIN(id) FROM audit_log)"
```

This should fail outright — the append-only trigger rejects the UPDATE before it commits. To
actually exercise `GET /internal/audit/verify` catching a break, corrupt `entry_hash` directly
(bypassing the trigger isn't possible from `app_user`, so this has to be done as `platform_owner`
against a row's hash column, e.g. by disabling the trigger temporarily in a throwaway local DB)
and confirm the endpoint returns `valid: false` with the correct `brokenAtId`.
