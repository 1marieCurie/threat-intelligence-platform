import pytest

from application.services.cisa_threat_source import CISAThreatSource
from infrastructure.adapters.inbound.cisa_ingestion_job import CISAIngestionJob

@pytest.mark.integration
def test_collection():

    source = CISAThreatSource()
    job = CISAIngestionJob(source)

    result = job.run()

    print("\n========== CISA COLLECTION METADATA ==========\n")

    for key, value in result.metadata.items():
        print(f"{key:<25}: {value}")

    print("\n========== CISA SUMMARY ==========\n")

    print(f"Collected threats : {len(result.threats)}")

    if not result.threats:
        return

    first = result.threats[0]

    print("\n========== FIRST CISA THREAT ==========\n")

    print(f"ID                 : {first.id}")
    print(f"Title              : {first.title or 'N/A'}")
    print(f"Description        : {first.description}")
    print(f"Affected products  : {first.affected_products}")
    print(f"Weaknesses         : {first.weaknesses}")
    print(f"References         : {len(first.references)}")

    print("\n========== CISA INTELLIGENCE ==========\n")

    print(f"Known exploited    : {first.known_exploited_date}")
    print(f"Ransomware use     : {first.ransomware_campaign_use}")
    print(f"Remediation        : {first.remediation}")

    print("\n========== RAW CISA DATA ==========\n")

    print(f"Date Added         : {first.raw.get('dateAdded')}")
    print(f"Vendor             : {first.raw.get('vendorProject')}")
    print(f"Product            : {first.raw.get('product')}")
    print(f"Vulnerability Name : {first.raw.get('vulnerabilityName')}")
    print(f"Due Date           : {first.raw.get('dueDate')}")
    print(f"CWEs               : {first.raw.get('cwes')}")
    print(f"Notes              : {first.raw.get('notes')}")


if __name__ == "__main__":
    test_collection()