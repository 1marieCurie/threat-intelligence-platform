from typing import List, Any
from datetime import datetime, timedelta

from application.ports.inbound.threat_source import ThreatSource
from infrastructure.adapters.outbound.nvd_connector import NVDConnector
from domain.threat import Threat


class NVDThreatSource(ThreatSource):
    """
    Application Service

    Orchestrates the NVD ingestion logic:
    - fetch raw data via connector
    - parse into Threat objects
    """
    
    CVSS_PRIORITY = (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    )

    def __init__(self):
        self.connector = NVDConnector()

    def name(self) -> str:
        return "NVD"

    def collect(self) -> List[Threat]:
        raw = self.fetch_raw()
        return self.parse(raw)

    def fetch_raw(self) -> Any:
        """
        Fetch raw CVE data from the NVD API for the last 7 days.
        """

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)

        return self.connector.fetch(
            start_date=start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            end_date=end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            results_per_page=100,
            start_index=0,
        )

    def parse(self, raw_data: dict) -> List[Threat]:

        threats = []

        for item in raw_data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            threats.append(self._parse_cve(cve))

        return threats

    def _parse_cve(self, cve: dict) -> Threat:
        """
        Convert a single NVD CVE into a Threat domain object.
        """
        cve_id = cve.get("id")

        if cve_id is None:
            raise ValueError("Missing CVE identifier.")
        
        return Threat(
            id = cve_id,
            description=self._extract_description(cve),
            severity=self._extract_severity(cve),
            cvss_score=self._extract_cvss(cve),
            affected_products=cve.get("affected", []),
            weaknesses=self._extract_weaknesses(cve),
            references=self._extract_references(cve),
            source="NVD",
            published_date=cve.get("published"),
            last_modified_date=cve.get("lastModified"),
            raw=cve
            # we have volunteerly removed labels since the Threat structure isn't stable yet
        )
    # -------------------------
    # Helper parsing methods
    # -------------------------

    def _extract_description(self, cve: dict) -> str:
        """
        Return the English description if available.
        """

        descriptions = cve.get("descriptions", [])

        for description in descriptions:
            if description.get("lang") == "en":
                return description.get("value", "")

        if descriptions:
            return descriptions[0].get("value", "")

        return ""

    #supporting all versions of cvss score
    def _extract_severity(self, cve: dict):

        metric = self._extract_cvss_metric(cve)

        cvss_data = metric.get("cvssData", {})

        # CVSS v3.x and v4.0
        severity = cvss_data.get("baseSeverity")

        if severity is not None:
            return severity

        # CVSS v2
        return metric.get("baseSeverity")
    
    def _extract_cvss(self, cve: dict):

        metric = self._extract_cvss_metric(cve)
        cvss_data = metric.get("cvssData", {})

        return cvss_data.get("baseScore")
        

    def _extract_cvss_metric(self, cve: dict) -> dict:
        """
        Return the highest-priority CVSS metric available.

        The returned object has the following structure:

        {
            "source": "...",
            "type": "...",
            "cvssData": {...},
            "baseSeverity": "...",   # only for CVSS v2
            ...
        }
        """

        metrics = cve.get("metrics", {})

        for version in self.CVSS_PRIORITY:
            if version in metrics and metrics[version]:
                return metrics[version][0]

        return {}
    
    def _extract_weaknesses(self, cve: dict) -> List[str]:
        weaknesses = cve.get("weaknesses", [])
        return [
            w.get("description", [{}])[0].get("value", "")
            for w in weaknesses
        ]

    def _extract_references(self, cve: dict) -> List[str]:
        refs = cve.get("references", [])
        
        return [r.get("url", "") for r in refs]