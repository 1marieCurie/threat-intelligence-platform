from application.services.mitre_threat_source import MITREThreatSource
from domain.collection_result import CollectionResult


class MITREIngestionJob:
    """
    Inbound adapter responsible for triggering
    MITRE threat collection.
    """

    def __init__(self):
        self.source = MITREThreatSource()

    def run(self) -> CollectionResult:
        """
        Executes the MITRE ingestion pipeline.
        """
        return self.source.collect()