from typing import List, Any

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from infrastructure.adapters.outbound.cisa_connector import CISAConnector

from domain.threat import Threat


class CISAThreatSource(ThreatSource):
    """
    Application Service

    Orchestrates the CISA KEV ingestion logic:
    - fetch raw data via connector
    - parse into Threat objects
    """

    def __init__(self):
        self.connector = CISAConnector()

    def name(self) -> str:
        return "CISA"

    def collect(self)-> CollectionResult:

        raw = self.fetch_raw()

        threats = self.parse(raw)

        metadata = {
            "source": "CISA",
            "title": raw.get("title"),
            "catalog_version": raw.get("catalogVersion"),
            "date_released": raw.get("dateReleased"),
            "count": raw.get("count")
        }

        return CollectionResult(
            threats=threats,
            metadata=metadata
        )

    def fetch_raw(self) -> Any:
        """
        Fetch the complete CISA Known Exploited Vulnerabilities (KEV) catalog.
        """
        return self.connector.fetch()

    def parse(self, raw_data: dict) -> List[Threat]:

        threats = []

        for vulnerability in raw_data.get("vulnerabilities", []):
            threats.append(self._parse_vulnerability(vulnerability))

        return threats

    def _parse_vulnerability(self, vulnerability: dict) -> Threat:
        """
        Convert a single CISA KEV entry into a Threat domain object.
        """

        cve_id = vulnerability.get("cveID")

        if cve_id is None:
            raise ValueError("Missing CVE identifier.")

        return Threat(
        id=cve_id,

        title=vulnerability.get("vulnerabilityName"),

        description=vulnerability.get(
            "shortDescription",
            ""
        ),

        affected_products=[
            {
                "vendor": vulnerability.get("vendorProject"),
                "product": vulnerability.get("product")
            }
        ],

        weaknesses=vulnerability.get("cwes", []),

        references=self._extract_references(vulnerability),


        # CISA specific enrichment
        known_exploited_date=vulnerability.get(
            "dateAdded"
        ),

        remediation=vulnerability.get(
            "requiredAction"
        ),

        ransomware_campaign_use=vulnerability.get(
            "knownRansomwareCampaignUse"
        ),

        raw=vulnerability
    )
        # -------------------------
    # Helper parsing methods
    # -------------------------

    def _extract_references(self, vulnerability: dict) -> List[str]:
        """
        Extract reference URLs from the CISA 'notes' field.

        The notes field contains multiple URLs separated by ';'.
        """

        notes = vulnerability.get("notes", "")

        if not notes:
            return []

        return [
            note.strip()
            for note in notes.split(";")
            if note.strip()
        ]