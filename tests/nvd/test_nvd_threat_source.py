from copy import deepcopy

from application.services.nvd_threat_source import NVDThreatSource
from infrastructure.adapters.outbound.nvd_connector import NVDConnector


connector = NVDConnector()
source = NVDThreatSource()


def get_sample_cve():

    connector = NVDConnector()

    raw = connector.fetch(
        start_date="2026-06-29T00:00:00.000Z",
        end_date="2026-07-06T00:00:00.000Z",
        results_per_page=1,
        start_index=0,
    )

    return raw["vulnerabilities"][0]["cve"]

def test_missing_fields():

    source = NVDThreatSource()

    original_cve = get_sample_cve()

    print("\n========== TEST 1 : NO METRICS ==========")

    cve = deepcopy(original_cve)
    cve.pop("metrics", None)

    threat = source._parse_cve(cve)

    print("Severity :", threat.severity)
    print("CVSS     :", threat.cvss_score)

    print("\n========== TEST 2 : NO REFERENCES ==========")

    cve = deepcopy(original_cve)
    cve.pop("references", None)

    threat = source._parse_cve(cve)

    print(threat.references)

    print("\n========== TEST 3 : NO WEAKNESSES ==========")

    cve = deepcopy(original_cve)
    cve.pop("weaknesses", None)

    threat = source._parse_cve(cve)

    print(threat.weaknesses)

    print("\n========== TEST 4 : NO AFFECTED ==========")

    cve = deepcopy(original_cve)
    cve.pop("affected", None)

    threat = source._parse_cve(cve)

    print(threat.affected_products)

def test_period(start_date, end_date, title):

    print(f"\n========== {title} ==========")

    connector = NVDConnector()
    parser = NVDThreatSource()

    raw = connector.fetch(
        start_date=start_date,
        end_date=end_date,
        results_per_page=5,
        start_index=0
    )

    threats = parser.parse(raw)

    print(f"Threats parsed : {len(threats)}")

    for threat in threats:
        print("--------------------------------")
        print(f"ID          : {threat.id}")
        print(f"Severity    : {threat.severity}")
        print(f"CVSS Score  : {threat.cvss_score}")
        
def main():

    test_missing_fields()

    test_period(
        "2026-06-29T00:00:00.000Z",
        "2026-07-06T00:00:00.000Z",
        "Recent CVEs v3.1 and v4.0"
    )

    test_period(
        "2018-01-01T00:00:00.000Z",
        "2018-01-31T23:59:59.000Z",
        "CVSS v3.0"
    )

    test_period(
        "2009-01-01T00:00:00.000Z",
        "2009-01-31T23:59:59.000Z",
        "CVSS v2.0"
    )


if __name__ == "__main__":
    main()