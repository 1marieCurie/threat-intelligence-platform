from __future__ import annotations

from abc import ABC, abstractmethod

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
    CisaKevCanonicalSourceRecord,
)


class CisaKevCanonicalSource(ABC):
    """
    Port paginé de lecture des vulnérabilités
    CISA KEV normalisées.

    La pagination keyset évite OFFSET et conserve
    un coût stable lorsque le volume augmente.
    """

    @abstractmethod
    def read_batch(
        self,
        *,
        after_cursor: (
            CisaKevCanonicalCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> tuple[
        CisaKevCanonicalSourceRecord,
        ...,
    ]:
        """
        Retourne un lot ordonné par :

            cve_id ASC,
            normalized_record_id ASC

        after_cursor est exclusif.
        """