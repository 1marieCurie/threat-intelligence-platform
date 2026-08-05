from __future__ import annotations

from abc import (
    ABC,
    abstractmethod,
)

from application.models.phishtank_canonical_source_record import (
    PhishTankCanonicalCursor,
    PhishTankCanonicalSourceRecord,
)


class PhishTankCanonicalSource(
    ABC
):
    """
    Port paginé de lecture des observations PhishTank
    normalisées destinées à la couche canonique.
    """

    @abstractmethod
    def read_batch(
        self,
        *,
        after_cursor: (
            PhishTankCanonicalCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> tuple[
        PhishTankCanonicalSourceRecord,
        ...,
    ]:
        """
        Retourne un lot ordonné par :

            phish_id ASC,
            normalized_record_id ASC

        Le curseur est exclusif.
        """