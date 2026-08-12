from __future__ import annotations

from dataclasses import (
    dataclass,
    field,
)
from datetime import datetime
from typing import Literal
from uuid import UUID


ThreatURLLabel = Literal[
    "phishing",
    "malware",
]

ThreatURLSource = Literal[
    "phishtank",
    "urlhaus",
]


@dataclass(
    frozen=True,
    slots=True,
)
class CanonicalThreatURLCursor:
    canonicalization_version: int
    value_hash: str
    indicator_id: UUID


@dataclass(
    frozen=True,
    slots=True,
)
class CanonicalThreatURLCandidate:
    """
    URL de menace canonique prête à entrer
    dans le pipeline ML.

    Les valeurs IOC sensibles sont masquées du repr
    afin de réduire le risque de fuite accidentelle
    dans les logs ou les erreurs de debug.
    """

    canonical_web_indicator_id: UUID

    canonical_value: str = field(
        repr=False
    )

    value_hash: str = field(
        repr=False
    )

    hostname: str = field(
        repr=False
    )

    canonicalization_version: int

    source: ThreatURLSource
    label_code: ThreatURLLabel

    observed_at: datetime

    @property
    def cursor(
        self,
    ) -> CanonicalThreatURLCursor:
        return CanonicalThreatURLCursor(
            canonicalization_version=(
                self.canonicalization_version
            ),
            value_hash=self.value_hash,
            indicator_id=(
                self.canonical_web_indicator_id
            ),
        )