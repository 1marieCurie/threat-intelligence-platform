from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from domain.threat import Threat
from infrastructure.adapters.outbound.epss_connector import EPSSConnector
from application.services.threat_correlation_service import ThreatCorrelationResult


@dataclass
class EPSSEnrichmentResult:
    """
    Represents the result of enriching existing Threat objects with EPSS data.

    EPSS is not a primary threat source.
    It does not collect new vulnerabilities.
    It enriches already known CVE-based threats with exploitation probability.
    """

    threats: List[Threat] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class EPSSEnrichmentService:
    """
    Application Service

    Enriches existing Threat objects with EPSS scores.

    Important architectural note:
    EPSS depends on CVE identifiers, not on a specific correlation strategy.

    This service can therefore work with:
    - a simple list of Threat objects;
    - a ThreatCorrelationResult;
    - a direct list of CVE IDs.

    This keeps the service extensible for future sources such as:
    - GitHub Advisory Database, which may provide GHSA IDs and sometimes CVE IDs;
    - MITRE ATT&CK, which provides attack techniques, not CVE scores;
    - MISP / OTX, which provide indicators such as IPs, domains, hashes, and URLs.
    """

    def __init__(
        self,
        connector: Optional[EPSSConnector] = None
    ):
        self.connector = connector or EPSSConnector()

    def fetch_epss_by_cve_ids(
        self,
        cve_ids: Sequence[Optional[str]],
        date: Optional[str] = None
    ) -> Dict[str, Dict]:
        """
        Fetches EPSS records for a list of CVE IDs.

        This method does not require Threat objects.
        It is useful for future sources that may expose CVE IDs
        without being modeled exactly like NVD, CISA or MITRE.

        Args:
            cve_ids:
                List of CVE identifiers.

            date:
                Optional historical EPSS date in YYYY-MM-DD format.

        Returns:
            Dictionary mapping CVE IDs to EPSS records.

            Example:
            {
                "CVE-2021-44228": {
                    "cve": "CVE-2021-44228",
                    "epss": "0.999990000",
                    "percentile": "1.000000000",
                    "date": "2026-07-09"
                }
            }
        """

        cleaned_cve_ids = self._extract_unique_cve_ids_from_strings(
            cve_ids
        )

        if not cleaned_cve_ids:
            return {}

        raw_responses = self.connector.fetch_by_batches(
            cve_ids=cleaned_cve_ids,
            date=date
        )

        return self._build_epss_lookup(
            raw_responses
        )

    def enrich_threats(
        self,
        threats: List[Threat],
        date: Optional[str] = None
    ) -> EPSSEnrichmentResult:
        """
        Enriches a list of Threat objects with EPSS data.

        Only threats with valid CVE identifiers are enriched.
        Non-CVE threats, such as future GHSA-only advisories or IOC-based
        records, are ignored by EPSS.

        Args:
            threats:
                Existing Threat objects collected from NVD, CISA, MITRE,
                GitHub Advisory Database, or other future sources.

            date:
                Optional historical EPSS date in YYYY-MM-DD format.

        Returns:
            EPSSEnrichmentResult containing the enriched threats and metadata.
        """

        cve_ids = self._extract_unique_cve_ids_from_threats(
            threats
        )

        if not cve_ids:
            return EPSSEnrichmentResult(
                threats=threats,
                metadata={
                    "source": "EPSS",
                    "requested_cves": 0,
                    "epss_records_found": 0,
                    "enriched_threats": 0,
                    "missing_cves": [],
                    "non_cve_threats": len(threats),
                    "date_requested": date
                }
            )

        epss_lookup = self.fetch_epss_by_cve_ids(
            cve_ids=cve_ids,
            date=date
        )

        enriched_count = self._apply_epss_to_threats(
            threats=threats,
            epss_lookup=epss_lookup
        )

        missing_cves = [
            cve_id
            for cve_id in cve_ids
            if cve_id not in epss_lookup
        ]

        non_cve_threats = self._count_non_cve_threats(
            threats
        )

        metadata = {
            "source": "EPSS",
            "requested_cves": len(cve_ids),
            "epss_records_found": len(epss_lookup),
            "enriched_threats": enriched_count,
            "missing_cves": missing_cves,
            "non_cve_threats": non_cve_threats,
            "date_requested": date
        }

        return EPSSEnrichmentResult(
            threats=threats,
            metadata=metadata
        )

    def enrich_correlation_result(
        self,
        correlation_result: ThreatCorrelationResult,
        date: Optional[str] = None
    ) -> EPSSEnrichmentResult:
        """
        Enriches all Threat objects inside a ThreatCorrelationResult.

        This method is only a convenience method.
        EPSS does not depend on the correlator.
        The real dependency of EPSS is the availability of CVE IDs.
        """

        threats = []

        for group in correlation_result.all_groups():
            threats.extend(
                group.threats
            )

        return self.enrich_threats(
            threats=threats,
            date=date
        )

    def _extract_unique_cve_ids_from_threats(
        self,
        threats: List[Threat]
    ) -> List[str]:
        """
        Extracts unique CVE identifiers from Threat objects.

        Current model:
            threat.id is usually a CVE ID.

        Future compatibility:
            if later the Threat model supports cve_ids: List[str],
            this method can be extended without changing the EPSS API logic.
        """

        cve_ids = []

        for threat in threats:

            # Current project model:
            # NVD, CISA and MITRE use threat.id as CVE ID.
            if threat.id:
                cve_ids.append(
                    threat.id
                )

            # Future-proof extension:
            # If later you add threat.cve_ids for GitHub Advisory Database,
            # this block will automatically support it without breaking
            # the current model.
            extra_cve_ids = getattr(
                threat,
                "cve_ids",
                []
            )

            if isinstance(extra_cve_ids, list):
                cve_ids.extend(
                    extra_cve_ids
                )

        return self._extract_unique_cve_ids_from_strings(
            cve_ids
        )

    def _extract_unique_cve_ids_from_strings(
        self,
        cve_ids: Sequence[Optional[str]]
    ) -> List[str]:
        """
        Cleans, validates and deduplicates CVE IDs while preserving order.
        """

        cleaned = []
        seen = set()

        for cve_id in cve_ids:

            if not cve_id:
                continue

            if not isinstance(cve_id, str):
                continue

            normalized = cve_id.strip().upper()

            if not normalized.startswith("CVE-"):
                continue

            if normalized in seen:
                continue

            cleaned.append(
                normalized
            )

            seen.add(
                normalized
            )

        return cleaned

    def _build_epss_lookup(
        self,
        raw_responses: List[Dict]
    ) -> Dict[str, Dict]:
        """
        Builds a dictionary mapping CVE IDs to EPSS records.
        """

        lookup = {}

        for response in raw_responses:

            for item in response.get("data", []):

                cve_id = item.get("cve")

                if not cve_id:
                    continue

                lookup[cve_id.strip().upper()] = item

        return lookup

    def _apply_epss_to_threats(
        self,
        threats: List[Threat],
        epss_lookup: Dict[str, Dict]
    ) -> int:
        """
        Applies EPSS data to Threat objects.

        Returns:
            Number of Threat objects enriched.
        """

        enriched_count = 0

        for threat in threats:

            candidate_cve_ids = self._get_candidate_cve_ids_for_threat(
                threat
            )

            epss_record = None

            for cve_id in candidate_cve_ids:

                epss_record = epss_lookup.get(
                    cve_id
                )

                if epss_record is not None:
                    break

            if epss_record is None:
                continue

            threat.epss_score = self._safe_float(
                epss_record.get("epss")
            )

            threat.epss_percentile = self._safe_float(
                epss_record.get("percentile")
            )

            threat.epss_date = epss_record.get(
                "date"
            )

            enriched_count += 1

        return enriched_count

    def _get_candidate_cve_ids_for_threat(
        self,
        threat: Threat
    ) -> List[str]:
        """
        Returns all CVE IDs that can be associated with a Threat.

        Current behavior:
            Uses threat.id if it is a CVE.

        Future behavior:
            Also supports threat.cve_ids if added later for sources
            such as GitHub Advisory Database.
        """

        candidates = []

        if threat.id:
            candidates.append(
                threat.id
            )

        extra_cve_ids = getattr(
            threat,
            "cve_ids",
            []
        )

        if isinstance(extra_cve_ids, list):
            candidates.extend(
                extra_cve_ids
            )

        return self._extract_unique_cve_ids_from_strings(
            candidates
        )

    def _count_non_cve_threats(
        self,
        threats: List[Threat]
    ) -> int:
        """
        Counts Threat objects that do not expose any usable CVE ID.

        This will become useful later when adding non-CVE sources such as:
        - GHSA-only GitHub advisories;
        - ATT&CK techniques;
        - MISP or OTX indicators.
        """

        count = 0

        for threat in threats:

            candidate_cve_ids = self._get_candidate_cve_ids_for_threat(
                threat
            )

            if not candidate_cve_ids:
                count += 1

        return count

    def _safe_float(
        self,
        value
    ) -> Optional[float]:
        """
        Safely converts a value to float.

        The EPSS API returns epss and percentile values as strings.
        """

        if value is None:
            return None

        try:
            return float(
                value
            )

        except (TypeError, ValueError):
            return None