from __future__ import annotations

from abc import ABC, abstractmethod

from application.models.epss_canonical_source_record import (
    EPSSCanonicalSourceRecord,
)


class EPSSCanonicalSource(ABC):
    """
    Port de lecture paginée des scores EPSS normalisés.

    La pagination utilise un curseur CVE et non OFFSET,
    afin de garder un coût stable sur les gros volumes.
    """

    @abstractmethod
    def read_batch(
        self,
        *,
        after_cve_id: str | None = None,
        limit: int = 500,
    ) -> tuple[
        EPSSCanonicalSourceRecord,
        ...,
    ]:
        """
        Retourne un lot ordonné par CVE.

        after_cve_id est exclusif. Un tuple vide signifie
        qu'aucune ligne supplémentaire n'est disponible.
        """