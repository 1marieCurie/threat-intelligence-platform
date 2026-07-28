BEGIN;

SET LOCAL ROLE threat_intel_owner;

INSERT INTO ops.source (
    id,
    code,
    name,
    base_url,
    enabled
)
VALUES
    (
        gen_random_uuid(),
        'CISA_KEV',
        'CISA Known Exploited Vulnerabilities',
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        TRUE
    ),
    (
        gen_random_uuid(),
        'MITRE_CWE',
        'MITRE Common Weakness Enumeration',
        'https://cwe-api.mitre.org/api/v1',
        TRUE
    ),
    (
        gen_random_uuid(),
        'FIRST_EPSS',
        'FIRST Exploit Prediction Scoring System',
        'https://api.first.org/data/v1/epss',
        TRUE
    ),
    (
        gen_random_uuid(),
        'PHISHTANK',
        'PhishTank',
        'https://data.phishtank.com/data/online-valid.json.bz2',
        TRUE
    ),
    (
        gen_random_uuid(),
        'URLHAUS',
        'URLhaus',
        'https://urlhaus-api.abuse.ch/v1',
        TRUE
    )
ON CONFLICT (code)
DO UPDATE SET
    name = EXCLUDED.name,
    base_url = EXCLUDED.base_url;

SELECT
    id,
    code,
    name,
    base_url,
    enabled
FROM ops.source
WHERE code IN (
    'CISA_KEV',
    'MITRE_CWE',
    'FIRST_EPSS',
    'PHISHTANK',
    'URLHAUS'
)
ORDER BY code;

COMMIT;