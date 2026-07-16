from __future__ import annotations

from enum import Enum


class ThreatCategory(str, Enum):
    """
    High-level business category of a cybersecurity threat.

    The category describes the nature of the main intelligence
    entity represented by a Threat.

    It must not be confused with Indicator.type:

    - ThreatCategory describes the threat or cyber activity;
    - Indicator.type describes an observable such as a URL,
      domain, IP address or file hash.
    """

    VULNERABILITY = "vulnerability"
    PHISHING = "phishing"
    MALWARE_DISTRIBUTION = "malware_distribution"
    MALWARE = "malware"
    CAMPAIGN = "campaign"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"