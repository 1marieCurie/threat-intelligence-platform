from application.services.nvd_threat_source import NVDThreatSource
from infrastructure.adapters.inbound.nvd_ingestion_job import NVDIngestionJob

from application.services.cisa_threat_source import CISAThreatSource
from infrastructure.adapters.inbound.cisa_ingestion_job import CISAIngestionJob


def main():

    print("========== Threat Intelligence Engine ==========\n")

    # Future orchestration of all intelligence sources

    sources = [
        NVDThreatSource(),
        CISAThreatSource(),
    ]

    for source in sources:

        print(f"[INFO] Collecting threats from {source.name()}...")

        if source.name() == "NVD":
            job = NVDIngestionJob(source)
        else:
            job = CISAIngestionJob(source)

        result = job.run()

        print(
            f"[OK] {len(result.threats)} threats collected from {source.name()}."
        )

    print("\n[INFO] Collection completed.")


if __name__ == "__main__":
    main()