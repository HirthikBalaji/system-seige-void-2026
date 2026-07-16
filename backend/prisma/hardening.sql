-- Security hardening pass, run AFTER `prisma migrate` has created the tables.
-- Must be run as the table-owning role (platform_owner). Idempotent: safe to
-- re-run after every schema change.
--
-- Why this is a separate file instead of a Prisma migration: Prisma migrate
-- runs as whatever role DATABASE_URL points to at the time, and that role
-- becomes the table OWNER. Table owners bypass Row-Level Security by
-- default (even with RLS enabled), so if the app ever connected as the
-- owner, every RLS policy below would be silently inert. We deliberately
-- keep migrations and app runtime on two different roles: platform_owner
-- (owns tables, runs DDL, never touches request traffic) and app_user
-- (no DDL rights, subject to RLS, this is what the running server uses).

-- ── Row-Level Security ─────────────────────────────────────────────────────
-- current_setting(..., true) returns NULL instead of raising when
-- app.current_tenant hasn't been set for the session — NULL = tenant_id is
-- never true in SQL, so a request that forgets to set the tenant context
-- fails CLOSED (sees zero rows) instead of erroring open.

ALTER TABLE secrets       ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates  ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log     ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_findings ENABLE ROW LEVEL SECURITY;

-- FORCE means even the table owner (platform_owner) is bound by these
-- policies. Belt-and-suspenders: the owner never serves traffic anyway, but
-- this closes off "just connect as owner" as a bypass path entirely.
ALTER TABLE secrets       FORCE ROW LEVEL SECURITY;
ALTER TABLE certificates  FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log     FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_findings FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON secrets;
CREATE POLICY tenant_isolation ON secrets
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON certificates;
CREATE POLICY tenant_isolation ON certificates
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON scan_findings;
CREATE POLICY tenant_isolation ON scan_findings
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- audit_log: readable per-tenant, but writes are INSERT-only (see trigger and
-- the revoked UPDATE/DELETE grants below) — there is deliberately no
-- UPDATE/DELETE policy because no role should ever be allowed either command.
DROP POLICY IF EXISTS tenant_read ON audit_log;
CREATE POLICY tenant_read ON audit_log
  FOR SELECT
  USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_write ON audit_log;
CREATE POLICY tenant_write ON audit_log
  FOR INSERT
  WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ── Append-only audit_log at the DB level ──────────────────────────────────
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

-- ── Global hash-chain read, bypassing RLS on purpose ───────────────────────
-- The audit chain is a single chain across ALL tenants (see prisma/hardening
-- rationale in BACKEND_BRIEF.md) — a break anywhere must be detectable
-- globally. But the tenant_read policy above means a session scoped to
-- tenant A cannot see tenant B's rows, so it cannot discover the true last
-- row of the global chain to compute the next prev_hash. This function
-- returns ONLY (id, hash) — never tenant_id, actor_id, action, or details —
-- so exposing it cross-tenant leaks nothing about any tenant's data, while
-- letting the chain stay globally contiguous. `SET row_security = off` is
-- only honored for the owning role even under FORCE ROW LEVEL SECURITY,
-- which is exactly the privilege this SECURITY DEFINER function borrows.
CREATE OR REPLACE FUNCTION get_last_audit_entry()
RETURNS TABLE(last_id BIGINT, last_hash CHAR(64))
LANGUAGE sql
SECURITY DEFINER
SET row_security = off
SET search_path = public
AS $$
  SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1;
$$;

REVOKE ALL ON FUNCTION get_last_audit_entry() FROM PUBLIC;

-- ── Full chain read for GET /internal/audit/verify ─────────────────────────
-- Verifying a *global* hash chain requires walking every row in id order,
-- which is unavoidably cross-tenant by design (see rationale above). This is
-- gated at the app layer to the `admin` role, and the HTTP response only
-- ever returns {valid, brokenAtId} — a bare boolean and an opaque integer,
-- never tenant_id/action/resource_id/details — so a tenant admin calling
-- this learns whether *the platform's* chain is intact, not what any other
-- tenant did. Documented as a deliberate, minimal-disclosure trade-off
-- against the "complete tenant isolation" requirement in exchange for the
-- platform-wide tamper-evidence the brief calls for.
CREATE OR REPLACE FUNCTION get_full_audit_chain()
RETURNS SETOF audit_log
LANGUAGE sql
SECURITY DEFINER
SET row_security = off
SET search_path = public
AS $$
  SELECT * FROM audit_log ORDER BY id ASC;
$$;

REVOKE ALL ON FUNCTION get_full_audit_chain() FROM PUBLIC;

-- ── Tenant id enumeration for the cert-lifecycle background job ───────────
-- The periodic job (src/modules/certs/job.ts) needs the list of tenant ids
-- so it can process each tenant's certificates inside its own RLS-scoped
-- transaction — it never queries certificates across tenants in one go, so
-- it needs no RLS bypass there. It does need tenant ids up front, though,
-- and app_user has no direct grant on `tenants` (see note at the bottom of
-- this file), so this function hands back ids only — never tenant names or
-- any other column.
CREATE OR REPLACE FUNCTION get_all_tenant_ids()
RETURNS SETOF UUID
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id FROM tenants;
$$;

REVOKE ALL ON FUNCTION get_all_tenant_ids() FROM PUBLIC;

-- ── Tenant auto-provisioning from verified JWT claims ──────────────────────
-- In this deployment, the gateway (Next.js, backed by its own auth/session
-- store) is the source of truth for which tenants exist — it verifies
-- identity and issues our JWT, but doesn't have its own Postgres connection
-- into this database. Rather than grant it raw INSERT on `tenants` (or add
-- a second, unauthenticated provisioning endpoint), every authenticated
-- request idempotently provisions its own tenant_id through this one
-- narrow RPC (see src/lib/withTenantTx.ts) — app_user still has zero direct
-- grants on the table itself.
CREATE OR REPLACE FUNCTION provision_tenant(p_id UUID, p_name TEXT)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  INSERT INTO tenants (id, name) VALUES (p_id, p_name)
  ON CONFLICT (id) DO NOTHING;
$$;

REVOKE ALL ON FUNCTION provision_tenant(UUID, TEXT) FROM PUBLIC;

-- ── Least-privilege grants for the runtime role ────────────────────────────
GRANT USAGE ON SCHEMA public TO app_user;

GRANT SELECT, INSERT, UPDATE, DELETE ON secrets       TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON certificates  TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_findings TO app_user;

-- audit_log: no UPDATE/DELETE grant at all — the trigger is a second,
-- independent layer on top of this, not a substitute for it.
GRANT SELECT, INSERT ON audit_log TO app_user;

GRANT EXECUTE ON FUNCTION get_last_audit_entry() TO app_user;
GRANT EXECUTE ON FUNCTION get_full_audit_chain() TO app_user;
GRANT EXECUTE ON FUNCTION get_all_tenant_ids() TO app_user;
GRANT EXECUTE ON FUNCTION provision_tenant(UUID, TEXT) TO app_user;

-- Sequence backing audit_log.id (BIGSERIAL) needs USAGE for INSERT to work.
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO app_user;

-- No privileges granted to app_user on `tenants` — FK/referential-integrity
-- checks run with the referenced table owner's privileges internally, so the
-- referencing role never needs direct access to the table it points at.
