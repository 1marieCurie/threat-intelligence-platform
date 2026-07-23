CREATE DATABASE threat_intelligence
    OWNER threat_intel_owner
    ENCODING 'UTF8'
    TEMPLATE template0;

REVOKE ALL
ON DATABASE threat_intelligence
FROM PUBLIC;

GRANT CONNECT
ON DATABASE threat_intelligence
TO threat_intel_migrator;