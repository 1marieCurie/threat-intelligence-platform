from application.services.nvd_threat_source import NVDThreatSource
from infrastructure.adapters.inbound.nvd_ingestion_job import NVDIngestionJob


def main():

    source = NVDThreatSource()
    job = NVDIngestionJob(source)

    threats = job.run()

    print("\n========== SUMMARY ==========")
    print(f"Collected threats: {len(threats)}")

    if threats:
        first = threats[0]

        print("\n========== FIRST THREAT ==========")
        print(f"ID               : {first.id}")
        print(f"Description      : {first.description}")
        print(f"Severity         : {first.severity}")
        print(f"CVSS Score       : {first.cvss_score}")
        print(f"Published        : {first.published_date}")
        print(f"Last Modified    : {first.last_modified_date}")
        print(f"Weaknesses       : {first.weaknesses}")
        print(f"References       : {len(first.references)}")
        print(f"Affected         : {len(first.affected_products)}")


if __name__ == "__main__":
    main()