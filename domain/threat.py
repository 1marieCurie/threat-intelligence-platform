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

    # --- Identity ---
    id: str  # e.g. CVE-2026-XXXX

    # --- Core information ---
    description: str

    # --- Classification ---
    severity: Optional[str] = None  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: Optional[float] = None

    # --- Impacted systems ---
    affected_products: List[Dict] = field(default_factory=list)

    # --- Weakness mapping (CWE) ---
    weaknesses: List[str] = field(default_factory=list)
    
    # generic appelation for the tags fields (cve_tags, etc..)
    labels: List[str] = field(default_factory=list)

    # --- External knowledge ---
    references: List[str] = field(default_factory=list)

    # --- Source tracking ---
    source: str = ""  # NVD, MITRE, etc.

    # --- Metadata ---
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None

    # --- Raw data (VERY IMPORTANT for future AI + debugging) ---
    raw: Dict = field(default_factory=dict)

    # --- AI / future enrichment fields ---
    risk_score: Optional[float] = None
    embedding: Optional[List[float]] = None
    
    