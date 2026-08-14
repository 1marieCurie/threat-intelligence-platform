\set ON_ERROR_STOP on

-- ============================================================
-- Runtime PostgreSQL role for the Asset Inventory API
-- ============================================================
--
-- IMPORTANT:
-- Run this script AFTER:
--
--     alembic upgrade head
--
-- Usage:
--
-- psql ^
--   -h localhost ^
--   -p 5432 ^
--   -U postgres ^
--   -d threat_intelligence ^
--   -v asset_api_password='LOCAL_PASSWORD' ^
--   -f database/bootstrap/006_asset_api_role.sql
--
-- No real password is stored in this file.
-- ============================================================


-- ============================================================
-- Validate psql variables
-- ============================================================

\if :{?asset_api_password}
\else
    \echo 'ERROR: asset_api_password must be supplied with -v.'
    \quit 1
\endif


-- ============================================================
-- Permission role
-- ============================================================

SELECT
    'CREATE ROLE threat_intel_asset_api_role
        WITH
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS
            NOINHERIT'
WHERE NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'threat_intel_asset_api_role'
)
\gexec


ALTER ROLE threat_intel_asset_api_role
WITH
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    NOINHERIT;


-- ============================================================
-- Login role
-- ============================================================

SELECT format(
    'CREATE ROLE threat_intel_asset_api
        WITH
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS
            INHERIT
            CONNECTION LIMIT 10
            PASSWORD %L',
    :'asset_api_password'
)
WHERE NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'threat_intel_asset_api'
)
\gexec


ALTER ROLE threat_intel_asset_api
WITH
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    INHERIT
    CONNECTION LIMIT 10;


SELECT format(
    'ALTER ROLE threat_intel_asset_api PASSWORD %L',
    :'asset_api_password'
)
\gexec


-- ============================================================
-- Membership
-- ============================================================

GRANT threat_intel_asset_api_role
TO threat_intel_asset_api
WITH INHERIT TRUE, SET FALSE;


-- ============================================================
-- Runtime safety
-- ============================================================

ALTER ROLE threat_intel_asset_api
SET statement_timeout = '30s';

ALTER ROLE threat_intel_asset_api
SET lock_timeout = '5s';

ALTER ROLE threat_intel_asset_api
SET idle_in_transaction_session_timeout = '30s';

ALTER ROLE threat_intel_asset_api
SET search_path = pg_catalog;


-- ============================================================
-- Database / schema
-- ============================================================

GRANT CONNECT
ON DATABASE threat_intelligence
TO threat_intel_asset_api;


GRANT USAGE
ON SCHEMA threat_intel
TO threat_intel_asset_api_role;


-- ============================================================
-- Least-privilege inventory access
-- ============================================================

-- Organization is only resolved/validated.
GRANT SELECT
ON TABLE threat_intel.organization
TO threat_intel_asset_api_role;


-- Machine observation.
GRANT SELECT, INSERT, UPDATE
ON TABLE threat_intel.machine
TO threat_intel_asset_api_role;


-- One current inventory state per machine.
GRANT SELECT, INSERT, UPDATE
ON TABLE threat_intel.machine_inventory_state
TO threat_intel_asset_api_role;


-- Current software inventory reconciliation.
GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE threat_intel.software_component
TO threat_intel_asset_api_role;