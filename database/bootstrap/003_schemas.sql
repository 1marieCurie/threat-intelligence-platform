REVOKE CREATE
ON SCHEMA public
FROM PUBLIC;

CREATE SCHEMA IF NOT EXISTS threat_intel
    AUTHORIZATION threat_intel_owner;

CREATE SCHEMA IF NOT EXISTS ops
    AUTHORIZATION threat_intel_owner;

CREATE SCHEMA IF NOT EXISTS raw
    AUTHORIZATION threat_intel_owner;

GRANT USAGE, CREATE
ON SCHEMA threat_intel, ops, raw
TO threat_intel_owner;

GRANT USAGE
ON SCHEMA threat_intel, ops, raw
TO threat_intel_migrator;