from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from domain.indicator import Indicator
from domain.weakness_reference import WeaknessReference


@dataclass
class Threat:
    """
    Normalized cybersecurity threat or vulnerability.

    A Threat may progressively combine intelligence collected
    from NVD, MITRE, CISA, GitHub Advisory and other sources.
    """

    # ============================================================
    # Identity
    # ============================================================

    # Canonical identifier.
    # Prefer CVE when available, otherwise use GHSA or another
    # source-specific identifier.
    id: str

    # All identifiers associated with the threat.
    #
    # Example:
    # {
    #     "CVE": ["CVE-2021-44228"],
    #     "GHSA": ["GHSA-jfh8-c2jp-5v3q"]
    # }
    external_ids: Dict[str, List[str]] = field(
        default_factory=dict
    )

    # ============================================================
    # Core information
    # ============================================================

    title: Optional[str] = None
    description: str = ""

    # reviewed, unreviewed, malware, etc.
    advisory_type: Optional[str] = None
    
    # Normalized category of the threat.
    #
    # Examples:
    # vulnerability, phishing, malware_distribution,
    # malicious_domain, malicious_ip
    threat_type: Optional[str] = None

    # Source that produced this normalized record.
    #
    # Examples:
    # NVD, CISA, MITRE, GITHUB_ADVISORY, PHISHTANK
    source: Optional[str] = None
    
    # ============================================================
    # Indicators of compromise and observables
    # ============================================================

    indicators: List[Indicator] = field(
        default_factory=list
    )

    # ============================================================
    # Severity and CVSS
    # ============================================================

    severity: Optional[str] = None

    # Main normalized score selected by the application.
    cvss_score: Optional[float] = None

    # All CVSS versions provided by the sources.
    #
    # Example:
    # {
    #     "3.1": {
    #         "score": 9.8,
    #         "vector": "CVSS:3.1/..."
    #     },
    #     "4.0": {
    #         "score": 9.3,
    #         "vector": "CVSS:4.0/..."
    #     }
    # }
    cvss_metrics: Dict[str, Dict[str, Any]] = field(
        default_factory=dict
    )

    # ============================================================
    # EPSS
    # ============================================================

    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[str] = None

    # ============================================================
    # Affected systems and packages
    # ============================================================

    affected_products: List[Dict[str, Any]] = field(
        default_factory=list
    )

    # ============================================================
    # Weaknesses
    # ============================================================

    weakness_references: list[WeaknessReference] = field(
        default_factory=list
    )
    labels: List[str] = field(default_factory=list)

    # ============================================================
    # References and source locations
    # ============================================================

    references: List[str] = field(default_factory=list)

    source_urls: Dict[str, str] = field(
        default_factory=dict
    )

    source_code_locations: List[str] = field(
        default_factory=list
    )

    # ============================================================
    # Exploitation and remediation
    # ============================================================

    known_exploited_date: Optional[str] = None
    remediation: Optional[str] = None
    ransomware_campaign_use: Optional[str] = None

    # ============================================================
    # Dates
    # ============================================================

    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    reviewed_date: Optional[str] = None
    withdrawn_date: Optional[str] = None

    # Dates with source-specific semantics.
    source_dates: Dict[str, str] = field(
        default_factory=dict
    )

    # ============================================================
    # Raw data
    # ============================================================

    raw: Dict[str, Any] = field(default_factory=dict)

    # ============================================================
    # AI and enrichment
    # ============================================================

    risk_score: Optional[float] = None
    embedding: Optional[List[float]] = None

    # ============================================================
    # Derived weakness information
    # ============================================================
    
    @property
    def weakness_ids(self) -> List[str]:
        """
        Return unique resolved canonical CWE identifiers.
        """

        return list(
            dict.fromkeys(
                reference.cwe_id
                for reference in self.weakness_references
                if (
                    reference.cwe_id is not None
                    and reference.resolution_status
                    == "resolved"
                )
            )
        )