from typing import Any, Dict, List, Optional

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from domain.threat import Threat

from infrastructure.adapters.outbound.mitre_connector import MITREConnector
from infrastructure.persistence.mitre_sync_state import MITRESyncState


class MITREThreatSource(ThreatSource):
    """
    Application Service

    Orchestrates MITRE CVE List ingestion:
    - retrieves newly published or modified CVE Records
    - transforms them into normalized Threat entities
    - stores the synchronization state
    """

    def __init__(
        self,
        connector: Optional[MITREConnector] = None,
        sync_state: Optional[MITRESyncState] = None
    ):

        self.connector = connector or MITREConnector()
        self.sync_state = sync_state or MITRESyncState()

    def name(self) -> str:
        return "MITRE"

    def collect(self) -> CollectionResult:
        """
        Main entry point for MITRE ingestion.
        """

        raw = self.fetch_raw()

        threats = self.parse(raw["records"])

        metadata = {
            "source": "MITRE",
            "previous_commit": raw["previous_commit"],
            "current_commit": raw["current_commit"],
            "records_collected": len(threats)
        }

        return CollectionResult(
            threats=threats,
            metadata=metadata
        )

    def fetch_raw(self) -> Dict[str, Any]:
        """
        Retrieves all newly published or modified
        MITRE CVE records since the last synchronization.
        """

        previous_commit = self.sync_state.get_last_commit()

        current_commit, records = (
            self.connector.fetch_new_records(
                previous_commit
            )
        )

        self.sync_state.save_last_commit(
            current_commit
        )

        return {
            "previous_commit": previous_commit,
            "current_commit": current_commit,
            "records": records
        }

    def parse(
        self,
        raw_data: List[Dict]
    ) -> List[Threat]:
        """
        Converts raw MITRE CVE Records
        into normalized Threat entities.
        """

        threats = []

        for record in raw_data:

            threats.append(
                self._parse_record(
                    record
                )
            )

        return threats

    def _parse_record(
        self,
        record: Dict
    ) -> Threat:
        """
        Converts a single MITRE CVE Record
        into a normalized Threat domain entity.

        The CNA container provides the primary vulnerability information,
        while optional ADP containers are used to enrich the Threat.
        """

        metadata = record.get(
            "cveMetadata",
            {}
        )

        cna = (
            record.get("containers", {})
                .get("cna", {})
        )

        cve_id = metadata.get("cveId")

        if cve_id is None:
            raise ValueError(
                "Missing CVE identifier."
            )

        threat = Threat(

            id=cve_id,

            title=cna.get(
                "title"
            ),

            description=self._extract_description(
                cna
            ),

            severity=self._extract_severity(
                cna
            ),

            cvss_score=self._extract_cvss(
                cna
            ),

            affected_products=self._extract_affected_products(
                cna
            ),

            weaknesses=self._extract_weaknesses(
                cna
            ),

            labels=self._extract_labels(
                cna
            ),

            references=self._extract_references(
                cna
            ),

            remediation=self._extract_remediation(
                cna
            ),

            published_date=metadata.get(
                "datePublished"
            ),

            last_modified_date=metadata.get(
                "dateUpdated"
            ),

            raw=record
        )

        # Enrich the Threat using optional ADP containers.
        self._merge_adp_enrichments(
            threat,
            record
        )

        return threat

    def _extract_description(
        self,
        cna: Dict
    ) -> str:

        descriptions = cna.get(
            "descriptions",
            []
        )

        for description in descriptions:

            if description.get("lang") == "en":
                return (
                    description.get("value", "")
                    .replace("\u00a0", " ")
                    .strip()
                )

        if descriptions:
            return (
                descriptions[0]
                .get("value", "")
                .replace("\u00a0", " ")
                .strip()
            )

        return ""
    
    def _extract_cvss(
        self,
        cna: Dict
    ):

        metrics = cna.get(
            "metrics",
            []
        )

        for metric in metrics:

            for value in metric.values():

                if (
                    isinstance(value, dict)
                    and "baseScore" in value
                ):
                    return value["baseScore"]

        return None

    def _extract_severity(
        self,
        cna: Dict
    ):

        metrics = cna.get(
            "metrics",
            []
        )

        for metric in metrics:

            for value in metric.values():

                if (
                    isinstance(value, dict)
                    and "baseSeverity" in value
                ):
                    return value["baseSeverity"]

        return None

    def _extract_weaknesses(
        self,
        cna: Dict
    ) -> List[str]:

        weaknesses = []

        for problem in cna.get(
            "problemTypes",
            []
        ):

            for description in problem.get(
                "descriptions",
                []
            ):

                value = description.get("description")

                if value:
                    weaknesses.append(value)

        return weaknesses
    
    def _extract_references(
        self,
        cna: Dict
    ) -> List[str]:

        return [

            reference.get("url")

            for reference in cna.get(
                "references",
                []
            )

            if reference.get("url")
        ]

    def _extract_labels(
        self,
        cna: Dict
    ) -> List[str]:

        labels = []

        labels.extend(
            cna.get(
                "tags",
                []
            )
        )

        return labels

    def _extract_affected_products(
        self,
        cna: Dict
    ) -> List[Dict]:

        products = []

        for affected in cna.get(
            "affected",
            []
        ):

            products.append(
                {

                    "vendor":
                        affected.get("vendor"),

                    "product":
                        affected.get("product"),

                    "versions":
                        affected.get(
                            "versions",
                            []
                        ),

                    "platforms":
                        affected.get(
                            "platforms",
                            []
                        ),

                    "cpes":
                        affected.get(
                            "cpes",
                            []
                        )
                }
            )

        return products

    def _extract_remediation(
        self,
        cna: Dict
    ):

        solutions = cna.get(
            "solutions",
            []
        )

        if solutions:

            return "\n".join(

                solution.get(
                    "value",
                    ""
                )

                for solution in solutions

                if solution.get("value")
            )

        workarounds = cna.get(
            "workarounds",
            []
        )

        if workarounds:

            return "\n".join(

                workaround.get(
                    "value",
                    ""
                )

                for workaround in workarounds

                if workaround.get("value")
            )

        return None
    
############ Enrichement of the Threat by ADP (optional) ###################
    def _merge_adp_enrichments(
        self,
        threat: Threat,
        record: Dict
    ) -> None:
        """
        Enriches a Threat with information
        provided by ADP containers.
        """

        adps = (
            record.get("containers", {})
                .get("adp", [])
        )

        for adp in adps:

            self._merge_references(
                threat,
                adp
            )

            self._merge_labels(
                threat,
                adp
            )

            self._merge_weaknesses(
                threat,
                adp
            )

            self._merge_cvss(
                threat,
                adp
            )

            self._merge_remediation(
                threat,
                adp
            )

#fuse references
    def _merge_references(
        self,
        threat: Threat,
        adp: Dict
    ):

        refs = self._extract_references(adp)

        for ref in refs:

            if ref not in threat.references:
                threat.references.append(ref)
                
# Fuse labels
    def _merge_labels(
        self,
        threat: Threat,
        adp: Dict
    ):

        labels = self._extract_labels(adp)

        for label in labels:

            if label not in threat.labels:
                threat.labels.append(label)

#Fuse CWE (weaknesses)
    def _merge_weaknesses(
        self,
        threat: Threat,
        adp: Dict
    ):

        weaknesses = self._extract_weaknesses(adp)

        for weakness in weaknesses:

            if weakness not in threat.weaknesses:
                threat.weaknesses.append(weakness)

# Fuse CVSS : adp if necessery, otherwise keep the original cvss
    def _merge_cvss(
        self,
        threat: Threat,
        adp: Dict
    ):

        if threat.cvss_score is None:

            threat.cvss_score = (
                self._extract_cvss(adp)
            )

        if threat.severity is None:

            threat.severity = (
                self._extract_severity(adp)
            )

#Fuse solutions
    def _merge_remediation(
        self,
        threat: Threat,
        adp: Dict
    ):

        if threat.remediation is None:

            threat.remediation = (
                self._extract_remediation(adp)
            )