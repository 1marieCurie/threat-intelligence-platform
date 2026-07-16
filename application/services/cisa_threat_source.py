from typing import Any, List

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from domain.threat import Threat
from domain.threat_category import ThreatCategory
from domain.weakness_reference import WeaknessReference
from infrastructure.adapters.outbound.cisa_connector import (
    CISAConnector,
)


class CISAThreatSource(ThreatSource):
    """
    Application service responsible for CISA KEV ingestion.

    Responsibilities:
    - fetch the CISA Known Exploited Vulnerabilities catalog;
    - parse source-specific vulnerability records;
    - classify records as vulnerability Threat objects;
    - normalize affected products;
    - normalize CWE references;
    - extract references and remediation information;
    - return normalized domain Threat objects.
    """

    SOURCE_NAME = "CISA"

    THREAT_CATEGORY = (
        ThreatCategory.VULNERABILITY
    )

    CWE_PLACEHOLDERS = {
        "NVD-CWE-NOINFO",
        "NVD-CWE-OTHER",
        "CWE-NOINFO",
        "CWE-OTHER",
    }

    def __init__(self) -> None:
        self.connector = CISAConnector()

    def name(self) -> str:
        """
        Return the normalized source name.
        """

        return self.SOURCE_NAME

    def collect(self) -> CollectionResult:
        """
        Fetch and parse the CISA KEV catalog into a
        CollectionResult.
        """

        raw = self.fetch_raw()
        threats = self.parse(raw)

        metadata = {
            "source": self.name(),
            "category": (
                self.THREAT_CATEGORY.value
            ),
            "title": raw.get("title"),
            "catalog_version": raw.get(
                "catalogVersion"
            ),
            "date_released": raw.get(
                "dateReleased"
            ),
            "count": raw.get("count"),
        }

        return CollectionResult(
            threats=threats,
            metadata=metadata,
        )

    def fetch_raw(self) -> Any:
        """
        Fetch the complete CISA Known Exploited
        Vulnerabilities catalog.
        """

        return self.connector.fetch()

    def parse(
        self,
        raw_data: Any,
    ) -> List[Threat]:
        """
        Parse the CISA KEV response into Threat objects.

        Invalid top-level values and malformed vulnerability
        elements are ignored safely.
        """

        if not isinstance(raw_data, dict):
            return []

        raw_vulnerabilities = raw_data.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(
            raw_vulnerabilities,
            list,
        ):
            return []

        threats: List[Threat] = []

        for vulnerability in raw_vulnerabilities:
            if not isinstance(
                vulnerability,
                dict,
            ):
                continue

            threats.append(
                self._parse_vulnerability(
                    vulnerability
                )
            )

        return threats

    def _parse_vulnerability(
        self,
        vulnerability: dict[str, Any],
    ) -> Threat:
        """
        Convert one CISA KEV entry into a vulnerability Threat.
        """

        cve_id = vulnerability.get(
            "cveID"
        )

        if not isinstance(cve_id, str):
            raise ValueError(
                "Missing CVE identifier."
            )

        cve_id = cve_id.strip()

        if not cve_id:
            raise ValueError(
                "Missing CVE identifier."
            )

        return Threat(
            id=cve_id,
            category=self.THREAT_CATEGORY,
            source=self.SOURCE_NAME,
            title=self._clean_optional_string(
                vulnerability.get(
                    "vulnerabilityName"
                )
            ),
            description=(
                self._clean_optional_string(
                    vulnerability.get(
                        "shortDescription"
                    )
                )
                or ""
            ),
            affected_products=(
                self._extract_affected_products(
                    vulnerability
                )
            ),
            weakness_references=(
                self._extract_weakness_references(
                    vulnerability
                )
            ),
            references=(
                self._extract_references(
                    vulnerability
                )
            ),
            known_exploited_date=(
                self._clean_optional_string(
                    vulnerability.get(
                        "dateAdded"
                    )
                )
            ),
            remediation=(
                self._clean_optional_string(
                    vulnerability.get(
                        "requiredAction"
                    )
                )
            ),
            ransomware_campaign_use=(
                self._clean_optional_string(
                    vulnerability.get(
                        "knownRansomwareCampaignUse"
                    )
                )
            ),
            source_dates=(
                self._extract_source_dates(
                    vulnerability
                )
            ),
            raw=vulnerability,
        )

    # =========================================================
    # Affected products
    # =========================================================

    def _extract_affected_products(
        self,
        vulnerability: dict[str, Any],
    ) -> List[dict[str, Any]]:
        """
        Extract the vendor and product reported by CISA.

        An empty affected-products list is returned when neither
        value is available.
        """

        vendor = self._clean_optional_string(
            vulnerability.get(
                "vendorProject"
            )
        )

        product = self._clean_optional_string(
            vulnerability.get(
                "product"
            )
        )

        if vendor is None and product is None:
            return []

        return [
            {
                "vendor": vendor,
                "product": product,
            }
        ]

    # =========================================================
    # Weakness references
    # =========================================================

    def _extract_weakness_references(
        self,
        vulnerability: dict[str, Any],
    ) -> List[WeaknessReference]:
        """
        Convert CISA KEV CWE values into source-specific
        WeaknessReference objects.

        CISA usually provides a list such as:

            ["CWE-306", "CWE-918"]

        Invalid, placeholder or empty elements are ignored.
        Duplicate identifiers are removed while preserving order.
        """

        raw_cwes = vulnerability.get(
            "cwes",
            [],
        )

        if not isinstance(raw_cwes, list):
            return []

        references: List[
            WeaknessReference
        ] = []

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
                    source=self.SOURCE_NAME,
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

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: Any,
    ) -> str | None:
        """
        Normalize a CISA CWE value to CWE-N.

        Accepted examples:
            "CWE-306"
            "cwe-306"
            "306"
            306

        Placeholders, booleans and malformed values are rejected.
        """

        if isinstance(value, bool):
            return None

        if isinstance(value, int):
            if value <= 0:
                return None

            return f"CWE-{value}"

        if not isinstance(value, str):
            return None

        normalized = (
            value
            .strip()
            .upper()
        )

        if not normalized:
            return None

        if normalized in cls.CWE_PLACEHOLDERS:
            return None

        if normalized.isdigit():
            number = int(normalized)

            if number <= 0:
                return None

            return f"CWE-{number}"

        if normalized.startswith(
            "CWE-"
        ):
            number = normalized.removeprefix(
                "CWE-"
            )

            if number.isdigit():
                number_value = int(number)

                if number_value > 0:
                    return (
                        f"CWE-{number_value}"
                    )

        return None

    # =========================================================
    # References
    # =========================================================

    def _extract_references(
        self,
        vulnerability: dict[str, Any],
    ) -> List[str]:
        """
        Extract reference URLs from the CISA ``notes`` field.

        CISA may provide multiple entries separated by semicolons.
        Duplicate values are removed while preserving order.
        """

        notes = vulnerability.get(
            "notes",
            "",
        )

        if not isinstance(notes, str):
            return []

        references: List[str] = []
        seen: set[str] = set()

        for raw_reference in notes.split(";"):
            reference = (
                raw_reference.strip()
            )

            if (
                not reference
                or reference in seen
            ):
                continue

            references.append(reference)
            seen.add(reference)

        return references

    # =========================================================
    # Source dates
    # =========================================================

    def _extract_source_dates(
        self,
        vulnerability: dict[str, Any],
    ) -> dict[str, str]:
        """
        Preserve dates whose semantics are specific to CISA KEV.
        """

        source_dates: dict[str, str] = {}

        date_added = self._clean_optional_string(
            vulnerability.get(
                "dateAdded"
            )
        )

        due_date = self._clean_optional_string(
            vulnerability.get(
                "dueDate"
            )
        )

        if date_added is not None:
            source_dates[
                "date_added_to_kev"
            ] = date_added

        if due_date is not None:
            source_dates[
                "remediation_due_date"
            ] = due_date

        return source_dates

    # =========================================================
    # Common normalization
    # =========================================================

    @staticmethod
    def _clean_optional_string(
        value: Any,
    ) -> str | None:
        """
        Normalize an optional source string.

        Empty strings and non-string values become None.
        """

        if not isinstance(value, str):
            return None

        normalized = (
            value
            .replace("\u00a0", " ")
            .strip()
        )

        return normalized or None