from application.services.nvd_threat_source import NVDThreatSource
from infrastructure.adapters.inbound.nvd_ingestion_job import NVDIngestionJob

from application.services.cisa_threat_source import CISAThreatSource
from infrastructure.adapters.inbound.cisa_ingestion_job import CISAIngestionJob


def test_nvd():

    source = NVDThreatSource()
    job = NVDIngestionJob(source)

    result = job.run()

    print("\n========== NVD COLLECTION METADATA ==========")

    for key, value in result.metadata.items():
        print(f"{key:<20}: {value}")


    print("\n========== NVD SUMMARY ==========")

    print(f"Collected threats: {len(result.threats)}")


    if result.threats:

        first = result.threats[0]

        print("\n========== FIRST NVD THREAT ==========")

        print(f"ID               : {first.id}")
        print(f"Description      : {first.description}")
        print(f"Severity         : {first.severity}")
        print(f"CVSS Score       : {first.cvss_score}")
        print(f"Published        : {first.published_date}")
        print(f"Last Modified    : {first.last_modified_date}")
        print(f"Weaknesses       : {first.weaknesses}")
        print(f"References       : {len(first.references)}")
        print(f"Affected         : {len(first.affected_products)}")



def test_cisa():

    source = CISAThreatSource()
    job = CISAIngestionJob(source)

    result = job.run()


    print("\n========== CISA COLLECTION METADATA ==========")

    for key, value in result.metadata.items():
        print(f"{key:<25}: {value}")


    print("\n========== CISA SUMMARY ==========")

    print(f"Collected threats: {len(result.threats)}")


    if result.threats:

        first = result.threats[0]


        print("\n========== FIRST CISA THREAT ==========")

        print(f"ID               : {first.id}")
        print(f"Description      : {first.description}")
        print(f"Affected         : {first.affected_products}")
        print(f"Weaknesses       : {first.weaknesses}")
        print(f"References count : {len(first.references)}")


        print("\n========== RAW CISA SPECIFIC DATA ==========")

        print(f"Date Added       : {first.raw.get('dateAdded')}")
        print(f"Vendor           : {first.raw.get('vendorProject')}")
        print(f"Product          : {first.raw.get('product')}")
        print(f"Ransomware Use   : {first.raw.get('knownRansomwareCampaignUse')}")
        print(f"Due Date         : {first.raw.get('dueDate')}")


def main():

    print("\n\n############ TESTING NVD SOURCE ############")
    test_nvd()


    print("\n\n############ TESTING CISA SOURCE ############")
    test_cisa()



if __name__ == "__main__":
    main()