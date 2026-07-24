-- Propriétaire des objets, sans connexion directe.
CREATE ROLE threat_intel_owner
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT;

-- Compte utilisé exclusivement par Alembic.
CREATE ROLE threat_intel_migrator
    LOGIN
    PASSWORD 'change_me'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT;

-- Autorise le migrator à prendre temporairement le rôle owner.
GRANT threat_intel_owner TO threat_intel_migrator;