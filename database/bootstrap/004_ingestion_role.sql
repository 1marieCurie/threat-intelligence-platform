-- Rôle de permissions, sans connexion directe.
CREATE ROLE threat_intel_ingestion_role
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT;

-- Compte utilisé par l’application d’ingestion.
CREATE ROLE threat_intel_ingestion
    LOGIN
    PASSWORD 'change_me'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    INHERIT;

GRANT threat_intel_ingestion_role
TO threat_intel_ingestion
WITH INHERIT TRUE, SET FALSE;

GRANT CONNECT
ON DATABASE threat_intelligence
TO threat_intel_ingestion;

GRANT USAGE
ON SCHEMA ops, raw
TO threat_intel_ingestion_role;

GRANT SELECT
ON TABLE ops.source
TO threat_intel_ingestion_role;

GRANT SELECT, INSERT, UPDATE
ON TABLE ops.ingestion_run
TO threat_intel_ingestion_role;

GRANT SELECT, INSERT, UPDATE
ON TABLE ops.sync_state
TO threat_intel_ingestion_role;

GRANT SELECT, INSERT, UPDATE
ON TABLE raw.source_payload
TO threat_intel_ingestion_role;

-- Future migrations
ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA ops
GRANT SELECT, INSERT, UPDATE
ON TABLES
TO threat_intel_ingestion_role;

ALTER DEFAULT PRIVILEGES
FOR ROLE threat_intel_owner
IN SCHEMA raw
GRANT SELECT, INSERT, UPDATE
ON TABLES
TO threat_intel_ingestion_role;