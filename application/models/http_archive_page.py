from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(
    frozen=True,
    slots=True,
)
class PreparedHTTPArchivePage:
    """
    Page HTTP Archive normalisée et prête à persister.

    canonical_value est volontairement conservée avant
    projection ML afin de permettre l'EDA et l'extraction
    reproductible des features lexicales.
    """

    canonical_value: str
    value_hash: str
    hostname: str
    registered_domain: str

    canonicalization_version: int

    source_rank: int
    source_snapshot: str
    observed_at: datetime


@dataclass(
    frozen=True,
    slots=True,
)
class HTTPArchivePersistenceResult:
    candidates_read: int
    normalized: int

    normalization_rejected: int
    source_rejected: int

    submitted: int
    inserted: int
    already_existing: int