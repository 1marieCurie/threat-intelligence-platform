from application.services.nvd_threat_source import NVDThreatSource


class NVDIngestionJob:
    """
    Inbound Adapter

    Entry point for the NVD ingestion process.

    This adapter can be triggered by:
    - scheduler (cron)
    - API endpoint
    - CLI command
    """

    def __init__(self, threat_source : NVDThreatSource): #dependency injection
        self.threat_source  = threat_source 

    def run(self):
        """
        Execute the NVD ingestion workflow.
        """
        print("[INFO] Starting NVD ingestion job...")

        
        result = self.threat_source.collect()

        print(
            f"[INFO] Collected {len(result.threats)} threats "
            f"from {self.threat_source.name()}."
        )

        return result