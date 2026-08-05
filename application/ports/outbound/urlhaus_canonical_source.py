from __future__ import annotations

from abc import (
    ABC,
    abstractmethod,
)

from application.models.urlhaus_canonical_source_record import (
    URLhausCanonicalCursor,
    URLhausCanonicalSourceRecord,
)


class URLhausCanonicalSource(
    ABC
):
    """
    Port paginé de lecture des observations URLhaus
    normalisées destinées à la couche canonique.
    """

    @abstractmethod
    def read_batch(
        self,
        *,
        after_cursor: (
            URLhausCanonicalCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> tuple[
        URLhausCanonicalSourceRecord,
        ...,
    ]:
        """
        Retourne un lot ordonné par :

            urlhaus_id ASC,
            normalized_record_id ASC

        Le curseur est exclusif.
        """