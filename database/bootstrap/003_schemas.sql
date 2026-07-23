REVOKE CREATE
ON SCHEMA public
FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS threat_intel
    AUTHORIZATION threat_intel_owner;

GRANT USAGE, CREATE
ON SCHEMA threat_intel
TO threat_intel_owner;

GRANT USAGE
ON SCHEMA threat_intel
TO threat_intel_migrator;