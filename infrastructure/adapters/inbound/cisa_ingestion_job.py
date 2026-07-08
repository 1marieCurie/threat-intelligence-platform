from application.services.cisa_threat_source import CISAThreatSource
from domain.collection_result import CollectionResult


class CISAIngestionJob:
    """
    Inbound Adapter

    Triggers the ingestion of vulnerabilities from the CISA KEV Catalog.
    """

    def __init__(self, threat_source: CISAThreatSource):
        self.threat_source = threat_source

    def run(self) -> CollectionResult:

        result = self.threat_source.collect()

        print(
            f"\nCollected {len(result.threats)} threats "
            f"from {self.threat_source.name()}.\n"
        )

        return result