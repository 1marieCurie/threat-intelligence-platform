from typing import List, Any

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from infrastructure.adapters.outbound.cisa_connector import CISAConnector

from domain.threat import Threat
from domain.weakness_reference import WeaknessReference


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

    def _parse_vulnerability(
        self,
        vulnerability: dict,
    ) -> Threat:
        """
        Convert a single CISA KEV entry into a Threat domain object.
        """

        cve_id = vulnerability.get("cveID")

        if cve_id is None:
            raise ValueError(
                "Missing CVE identifier."
            )

        return Threat(
            id=cve_id,

            source=self.name(),

            title=vulnerability.get(
                "vulnerabilityName"
            ),

            description=vulnerability.get(
                "shortDescription",
                "",
            ),

            affected_products=[
                {
                    "vendor": vulnerability.get(
                        "vendorProject"
                    ),
                    "product": vulnerability.get(
                        "product"
                    ),
                }
            ],

            weakness_references=(
                self._extract_weakness_references(
                    vulnerability
                )
            ),

            references=self._extract_references(
                vulnerability
            ),

            known_exploited_date=vulnerability.get(
                "dateAdded"
            ),

            remediation=vulnerability.get(
                "requiredAction"
            ),

            ransomware_campaign_use=vulnerability.get(
                "knownRansomwareCampaignUse"
            ),

            raw=vulnerability,
        )
    def _extract_weakness_references(
        self,
        vulnerability: dict,
    ) -> List[WeaknessReference]:
        """
        Convert CISA KEV CWE values into source-specific
        WeaknessReference objects.

        CISA usually provides a list such as:
            ["CWE-306", "CWE-918"]

        Invalid or empty elements are ignored.
        Duplicate identifiers are removed while preserving order.
        """

        raw_cwes = vulnerability.get(
            "cwes",
            [],
        )

        if not isinstance(raw_cwes, list):
            return []

        references: List[WeaknessReference] = []
        seen_ids: set[str] = set()

        for raw_value in raw_cwes:
            cwe_id = self._normalize_cwe_id(
                raw_value
            )

            if cwe_id is None:
                continue

            if cwe_id in seen_ids:
                continue

            references.append(
                WeaknessReference(
                    source=self.name(),
                    cwe_id=cwe_id,
                    origin="cisa_kev",
                    resolution_status="resolved",
                    resolution_method="explicit_id",
                    raw={
                        "value": raw_value,
                    },
                )
            )

            seen_ids.add(cwe_id)

        return references   
    
    @staticmethod
    def _normalize_cwe_id(
        value: Any,
    ) -> str | None:
        """
        Normalize a CISA CWE value to CWE-N.

        Accepted examples:
            "CWE-306"
            "cwe-306"
            "306"
            306

        Placeholders and malformed values are rejected.
        """

        if isinstance(value, int):
            if value <= 0:
                return None

            return f"CWE-{value}"

        if not isinstance(value, str):
            return None

        normalized = value.strip().upper()

        if not normalized:
            return None

        placeholders = {
            "NVD-CWE-NOINFO",
            "NVD-CWE-OTHER",
            "CWE-NOINFO",
            "CWE-OTHER",
        }

        if normalized in placeholders:
            return None

        if normalized.isdigit():
            number = int(normalized)

            if number <= 0:
                return None

            return f"CWE-{number}"

        if normalized.startswith("CWE-"):
            number = normalized.removeprefix(
                "CWE-"
            )

            if number.isdigit() and int(number) > 0:
                return f"CWE-{int(number)}"

        return None
            
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