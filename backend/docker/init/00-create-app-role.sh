#!/bin/sh
# Creates the low-privilege runtime role the Node app connects as.
# platform_owner (the Postgres init user, a superuser locally) stays reserved
# for migrations and DB hardening — it must never be the app's runtime role,
# because Postgres table owners bypass Row-Level Security by default, which
# would silently defeat the RLS policies applied later.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
      CREATE ROLE app_user LOGIN PASSWORD '$APP_DB_PASSWORD' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
  END
  \$\$;
EOSQL
