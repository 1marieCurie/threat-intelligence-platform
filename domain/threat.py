from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class Threat:
    """
    Domain Entity

    Represents a normalized cybersecurity vulnerability (CVE, advisory, etc.)
    independent of its source (NVD, MITRE, GitHub, CISA...).
    """

    # Provenance is handled at attribute level, not at Threat level.
    # A Threat can be composed from multiple intelligence sources.

    # --- Identity ---
    id: str  # e.g. CVE-2026-XXXX
    
    #a vulnerability name if provided
    title: Optional[str] = None

    # --- Core information ---
    description: str = "" # different sources providing descriptions

    # --- Classification ---
    severity: Optional[str] = None  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: Optional[float] = None
    
    # --- EPSS exploitation probability ---
    # EPSS estimates the probability that a CVE will be exploited in the wild.
    # Values are provided by FIRST EPSS API.
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[str] = None

    # --- Impacted systems ---
    affected_products: List[Dict] = field(default_factory=list)

    # --- Weakness mapping (CWE) ---
    weaknesses: List[str] = field(default_factory=list)
    
    # generic appelation for the tags fields (cve_tags, etc..)
    labels: List[str] = field(default_factory=list)

    # --- External knowledge ---
    references: List[str] = field(default_factory=list)

    # Date when CISA added the vulnerability to the KEV catalog,
    # indicating confirmed exploitation in the wild.
    known_exploited_date: Optional[str] = None
    
    #Actions to be done by the SOC or cybersecurity team
    remediation: Optional[str] = None
    
    # Indicates whether this vulnerability is known to be used in ransomware campaigns.
    # Values: Known, Unknown, No
    ransomware_campaign_use: Optional[str] = None    
   
 
     # Dates
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None

    # --- Raw data (VERY IMPORTANT for future AI + debugging) ---
    raw: Dict = field(default_factory=dict)

    # --- AI / future enrichment fields ---
    risk_score: Optional[float] = None
    embedding: Optional[List[float]] = None
    
    