from __future__ import annotations

from typing import Protocol

from application.models.canonical_threat_url_candidate import (
    CanonicalThreatURLCandidate,
    CanonicalThreatURLCursor,
    ThreatURLLabel,
)


class CanonicalThreatURLSource(
    Protocol
):
    def read_batch(
        self,
        *,
        label_code: ThreatURLLabel,
        after_cursor: (
            CanonicalThreatURLCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> tuple[
        CanonicalThreatURLCandidate,
        ...,
    ]:
        ...