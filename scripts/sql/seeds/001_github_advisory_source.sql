BEGIN;

SET LOCAL ROLE threat_intel_owner;

INSERT INTO ops.source (
    id,
    code,
    name,
    base_url,
    enabled
)
SELECT
    gen_random_uuid(),
    'GITHUB_ADVISORY',
    'GitHub Security Advisories',
    'https://api.github.com/advisories',
    TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM ops.source
    WHERE code = 'GITHUB_ADVISORY'
);

SELECT
    id,
    code,
    name,
    base_url,
    enabled
FROM ops.source
WHERE code = 'GITHUB_ADVISORY';

COMMIT;
