\set ON_ERROR_STOP on

-- ============================================================
-- Rôle PostgreSQL de documentation en lecture seule
-- ============================================================
--
-- Exécution :
--
-- psql ^
--   -h localhost ^
--   -p 5432 ^
--   -U postgres ^
--   -d threat_intelligence ^
--   -v reader_password='MOT_DE_PASSE_LOCAL' ^
--   -f database/bootstrap/005_reader_role.sql
--
-- Le mot de passe n'est volontairement pas stocké dans ce fichier.
-- ============================================================


-- ============================================================
-- Validation des paramètres psql
-- ============================================================

\if :{?reader_password}
\else
    \echo 'ERREUR : reader_password doit être fourni avec -v.'
    \quit 1
\endif


-- ============================================================
-- Création idempotente du rôle
-- ============================================================

SELECT format(
    'CREATE ROLE threat_intel_reader
        WITH
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS
            NOINHERIT
            CONNECTION LIMIT 5
            PASSWORD %L',
            '1111'
)
WHERE NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = 'threat_intel_reader'
)
\gexec


-- ============================================================
-- Remise en conformité si le rôle existait déjà
-- ============================================================

ALTER ROLE threat_intel_reader
WITH
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    NOINHERIT
    CONNECTION LIMIT 5;

SELECT format(
    'ALTER ROLE threat_intel_reader PASSWORD %L',
    :'reader_password'
)
\gexec


-- ============================================================
-- Sécurité par défaut
-- ============================================================

ALTER ROLE threat_intel_reader
SET default_transaction_read_only = on;

ALTER ROLE threat_intel_reader
SET statement_timeout = '60s';

ALTER ROLE threat_intel_reader
SET lock_timeout = '5s';

ALTER ROLE threat_intel_reader
SET idle_in_transaction_session_timeout = '60s';

ALTER ROLE threat_intel_reader
SET search_path = pg_catalog;


-- ============================================================
-- Connexion à la base
-- ============================================================

GRANT CONNECT
ON DATABASE threat_intelligence
TO threat_intel_reader;


-- ============================================================
-- Accès aux schémas du projet
-- ============================================================

GRANT USAGE
ON SCHEMA
    threat_intel,
    ops,
    raw,
    normalized,
    canonical
TO threat_intel_reader;


-- ============================================================
-- Lecture des tables existantes
-- ============================================================
--
-- Le générateur de documentation exécute COUNT(*) sur les
-- tables afin de fournir des nombres exacts.
--
-- Il a donc besoin de SELECT sur les tables documentées.
-- Le script Python ne lit toutefois aucune valeur métier et
-- n'exporte aucun payload.
-- ============================================================

GRANT SELECT
ON ALL TABLES IN SCHEMA
    threat_intel,
    ops,
    raw,
    normalized,
    canonical
TO threat_intel_reader;


-- ============================================================
-- Lecture des séquences existantes
-- ============================================================
--
-- Ce droit facilite l'inspection documentaire des séquences.
-- Il ne permet pas de modifier leur valeur.
-- ============================================================

GRANT SELECT
ON ALL SEQUENCES IN SCHEMA
    threat_intel,
    ops,
    raw,
    normalized,
    canonical
TO threat_intel_reader;


-- ============================================================
-- Privilèges par défaut pour les futures tables
-- ============================================================
--
-- Les objets du projet sont normalement créés par
-- threat_intel_owner.
-- ============================================================

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA threat_intel
GRANT SELECT ON TABLES
TO threat_intel_reader;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA ops
GRANT SELECT ON TABLES
TO threat_intel_reader;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA raw
GRANT SELECT ON TABLES
TO threat_intel_reader;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA normalized
GRANT SELECT ON TABLES
TO threat_intel_reader;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA canonical
GRANT SELECT ON TABLES
TO threat_intel_reader;


-- ============================================================
-- Privilèges par défaut pour les futures séquences
-- ============================================================

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA threat_intel
GRANT SELECT ON SEQUENCES
TO threat_intel_reader;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA ops
GRANT SELECT ON SEQUENCES
TO threat_intel_reader;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA raw
GRANT SELECT ON SEQUENCES
TO threat_intel_reader;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA normalized
GRANT SELECT ON SEQUENCES
TO threat_intel_reader;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA canonical
GRANT SELECT ON SEQUENCES
TO threat_intel_reader;


-- ============================================================
-- Interdictions explicites
-- ============================================================

REVOKE CREATE
ON SCHEMA
    threat_intel,
    ops,
    raw,
    normalized,
    canonical
FROM threat_intel_reader;

REVOKE TEMPORARY
ON DATABASE threat_intelligence
FROM threat_intel_reader;


-- ============================================================
-- Vérification finale
-- ============================================================

SELECT
    role.rolname,
    role.rolcanlogin,
    role.rolsuper,
    role.rolcreatedb,
    role.rolcreaterole,
    role.rolreplication,
    role.rolbypassrls,
    role.rolconnlimit,
    role.rolconfig
FROM pg_catalog.pg_roles AS role
WHERE role.rolname = 'threat_intel_reader';

SELECT
    schema_row.nspname AS schema_name,
    has_schema_privilege(
        'threat_intel_reader',
        schema_row.oid,
        'USAGE'
    ) AS has_usage,
    has_schema_privilege(
        'threat_intel_reader',
        schema_row.oid,
        'CREATE'
    ) AS has_create
FROM pg_catalog.pg_namespace AS schema_row
WHERE schema_row.nspname IN (
    'threat_intel',
    'ops',
    'raw',
    'normalized',
    'canonical'
)
ORDER BY schema_row.nspname;